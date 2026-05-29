from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json, os, re
from collections import defaultdict
from datetime import datetime

app = FastAPI(title="APDS API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts_db.json")

def load_db():
    with open(DB_PATH, encoding="utf-8") as f:
        return json.load(f)

def save_db(data):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ── Root ────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "system": "APDS", "version": "2.0.0"}

# ── Alerts ───────────────────────────────────────────────────────────────
@app.get("/alerts")
def get_alerts(
    verdict: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(200),
    offset: int = Query(0),
):
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    if verdict and verdict != "all":
        alerts = [a for a in alerts if a.get("verdict", "").lower() == verdict.lower()]

    if search:
        q = search.lower()
        alerts = [
            a for a in alerts
            if q in a.get("subject", "").lower()
            or q in a.get("sender", "").lower()
            or q in a.get("recipient", "").lower()
        ]

    total = len(alerts)
    alerts = alerts[offset: offset + limit]
    return {"total": total, "alerts": alerts}

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])
    for a in alerts:
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")

class AnalystUpdate(BaseModel):
    action: str          # confirmed_phishing | false_positive | escalated | pending
    notes: Optional[str] = ""

@app.patch("/alerts/{alert_id}/action")
def update_alert_action(alert_id: str, body: AnalystUpdate):
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])
    for a in alerts:
        if a["id"] == alert_id:
            a["analyst_action"] = body.action
            a["analyst_notes"] = body.notes or ""
            save_db(alerts if isinstance(db, list) else {**db, "alerts": alerts})
            return {"ok": True, "alert": a}
    raise HTTPException(status_code=404, detail="Alert not found")

# ── Stats ────────────────────────────────────────────────────────────────
@app.get("/stats")
def stats():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    total = len(alerts)
    phishing = sum(1 for a in alerts if a.get("verdict") == "phishing")
    benign   = sum(1 for a in alerts if a.get("verdict") == "benign")
    pending  = sum(1 for a in alerts if a.get("analyst_action") == "pending")

    # Category breakdown
    cats = defaultdict(int)
    for a in alerts:
        cats[a.get("threat_category", "unknown")] += 1

    # Recipient group breakdown
    groups = defaultdict(int)
    for a in alerts:
        groups[a.get("recipient_group", "Unknown")] += 1

    # Daily volume (last 7 days)
    daily: dict = defaultdict(lambda: {"phishing": 0, "benign": 0})
    for a in alerts:
        ts = a.get("timestamp", "")
        try:
            day = ts[:10]
            v = a.get("verdict", "benign")
            daily[day][v] = daily[day].get(v, 0) + 1
        except Exception:
            pass
    daily_sorted = sorted(daily.items())[-7:]
    daily_list = [{"date": d, **v} for d, v in daily_sorted]

    return {
        "total": total,
        "phishing": phishing,
        "benign": benign,
        "pending_review": pending,
        "detection_rate": round(phishing / total * 100, 1) if total else 0,
        "categories": dict(cats),
        "recipient_groups": dict(groups),
        "daily_volume": daily_list,
    }

# ── Campaigns ────────────────────────────────────────────────────────────
@app.get("/campaigns")
def campaigns():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    camp_map: dict = defaultdict(lambda: {"count": 0, "max_score": 0.0, "category": "unknown"})
    for a in alerts:
        cid = a.get("campaign_id")
        if cid:
            camp_map[cid]["count"] += 1
            sc = a.get("confidence_score", 0)
            if sc > camp_map[cid]["max_score"]:
                camp_map[cid]["max_score"] = sc
            camp_map[cid]["category"] = a.get("threat_category", "unknown")

    result = []
    for cid, info in camp_map.items():
        result.append({
            "id": cid,
            "name": cid.replace("_", " ").title(),
            "occurrences": info["count"],
            "max_score": info["max_score"],
            "category": info["category"],
        })
    result.sort(key=lambda x: x["occurrences"], reverse=True)
    return result

# ── Policy / thresholds ───────────────────────────────────────────────────
@app.get("/policy/thresholds")
def thresholds():
    return {"Executive": 0.6, "Finance": 0.65, "General Employee": 0.75, "Default": 0.7}

# ── Email scorer endpoint (live analysis placeholder) ────────────────────
@app.post("/score")
def score_email(email: dict):
    """Live scoring — returns a deterministic mock based on content signals."""
    raw = email.get("raw", "")
    subject = email.get("subject", raw)
    body = email.get("body", "")

    urgent_kw = ["urgent", "immediately", "action required", "verify", "password", "click here", "suspended"]
    hit = sum(1 for k in urgent_kw if k in (subject + body).lower())
    confidence = min(0.4 + hit * 0.12, 1.0)
    verdict = "phishing" if confidence >= 0.7 else ("suspicious" if confidence >= 0.4 else "benign")

    explanations = []
    if "softfail" in raw.lower(): explanations.append("SPF record returned softfail")
    if "dkim=none" in raw.lower(): explanations.append("DKIM signature missing")
    if "dmarc=fail" in raw.lower(): explanations.append("DMARC policy check failed")
    if hit: explanations.append(f"Body contains {hit} high-risk linguistic signal(s)")
    if not explanations: explanations.append("No significant threat signals detected")

    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "category": "credential_harvesting" if verdict == "phishing" else "benign",
        "explanations": explanations,
    }
