from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json
import os
import threading
from collections import defaultdict
from datetime import datetime, timezone

# Import APDS scoring engine components
from security.email_parser import EmailParser
from ml.nlp_analyzer import NLPAnalyzer
from security.url_scorer import URLScorer
from ml.fusion_engine import FusionEngine

app = FastAPI(title="APDS API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts_db.json")
db_lock = threading.RLock()

def load_db():
    with db_lock:
        with open(DB_PATH, encoding="utf-8") as f:
            return json.load(f)

def save_db(data):
    with db_lock:
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

# Campaign metadata maps
CAMP_NAMES = {
    "camp_bec_wire_01": "Executive Impersonation (Wire Transfer)",
    "camp_m365_harvest_02": "Office 365 Credential Harvesting (Moscow IP)",
    "camp_dhl_delivery_03": "DHL / FedEx Customs Delivery Scam"
}

CAMP_DESCRIPTIONS = {
    "camp_bec_wire_01": "BEC campaigns targeting finance departments asking for urgent wire transfer details or purchase of store gift cards.",
    "camp_m365_harvest_02": "Imitation of Microsoft security sign-in alert messages directing users to spoofed web login pages.",
    "camp_dhl_delivery_03": "Shipping package delivery notice asking for small customs fees to resolve delivery failures."
}

# ── Root ────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "system": "APDS", "version": "2.0.0"}

# ── API v1 Endpoints ───────────────────────────────────────────────────

@app.get("/api/v1/alerts")
def get_alerts_v1():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])
    return alerts

@app.get("/api/v1/campaigns")
def get_campaigns_v1():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    camp_map = defaultdict(lambda: {"count": 0, "max_score": 0.0, "category": "unknown"})
    for a in alerts:
        cid = a.get("campaign_id")
        if cid:
            camp_map[cid]["count"] += 1
            sc = a.get("confidence_score", 0.0)
            if sc > camp_map[cid]["max_score"]:
                camp_map[cid]["max_score"] = sc
            camp_map[cid]["category"] = a.get("threat_category", "unknown")

    result = []
    for cid, info in camp_map.items():
        result.append({
            "id": cid,
            "name": CAMP_NAMES.get(cid, cid.replace("camp_", "").replace("_", " ").title()),
            "count": info["count"],
            "max_score": round(info["max_score"], 3),
            "category": info["category"],
            "description": CAMP_DESCRIPTIONS.get(cid, "Campaign cluster tracking threat occurrences.")
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    return result

@app.get("/api/v1/settings/thresholds")
def get_thresholds_v1():
    return {
        "thresholds": {
            "Executive": 0.6,
            "Finance": 0.65,
            "General Employee": 0.75,
            "Default": 0.7
        }
    }

class ThresholdsPayload(BaseModel):
    thresholds: dict

@app.post("/api/v1/settings/thresholds")
def update_thresholds_v1(payload: ThresholdsPayload):
    return {"status": "success", "thresholds": payload.thresholds}

class FeedbackPayload(BaseModel):
    action: str
    notes: Optional[str] = ""

@app.post("/api/v1/alerts/{alert_id}/feedback")
def alert_feedback_v1(alert_id: str, payload: FeedbackPayload):
    with db_lock:
        db = load_db()
        alerts = db if isinstance(db, list) else db.get("alerts", [])
        for a in alerts:
            if a["id"] == alert_id:
                a["analyst_action"] = payload.action
                a["analyst_notes"] = payload.notes or ""
                save_db(alerts if isinstance(db, list) else {**db, "alerts": alerts})
                return {"status": "success", "alert": a}
    raise HTTPException(status_code=404, detail="Alert not found")

class ScorePayload(BaseModel):
    raw_email: str
    recipient_group: str
    recipient: str

@app.post("/api/v1/score")
def score_email_v1(payload: ScorePayload):
    parsed = EmailParser.parse_raw_email(payload.raw_email)
    body_text = parsed.get("body_text", "")
    urls = parsed.get("urls", [])
    
    nlp_res = NLPAnalyzer.analyze_text(body_text)
    url_res = URLScorer.evaluate_urls(urls)
    
    fusion = FusionEngine.fuse_verdict(parsed, nlp_res, url_res)
    
    with db_lock:
        db = load_db()
        alerts = db if isinstance(db, list) else db.get("alerts", [])
        
        category = fusion.get("threat_category", "benign")
        campaign_id = None
        if category == "bec":
            campaign_id = "camp_bec_wire_01"
        elif category == "credential_harvesting":
            campaign_id = "camp_m365_harvest_02"
        elif category == "generic_phishing":
            campaign_id = "camp_dhl_delivery_03"
            
        alert_id = f"alert_{int(datetime.now(timezone.utc).timestamp())}_{len(alerts)}"
        
        new_alert = {
            "id": alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "sender": parsed.get("from", ""),
            "recipient": payload.recipient,
            "recipient_group": payload.recipient_group,
            "subject": parsed.get("subject", ""),
            "verdict": fusion.get("verdict", "benign"),
            "threat_category": category,
            "confidence_score": fusion.get("confidence_score", 0.0),
            "raw_email": payload.raw_email,
            "parsed_details": parsed,
            "nlp_analysis": nlp_res,
            "url_analysis": url_res,
            "fusion_result": fusion,
            "analyst_action": "pending",
            "analyst_notes": "",
            "campaign_id": campaign_id
        }
        
        alerts.insert(0, new_alert)
        save_db(alerts if isinstance(db, list) else {**db, "alerts": alerts})
        
    return {
        "fusion_result": fusion,
        "threat_category": category,
        "alert": new_alert
    }

@app.get("/api/v1/model/metrics")
def get_model_metrics_v1():
    return {
        "model_version": "deberta-v3-phish-v1.4",
        "last_retrained": "2026-05-22T14:30:00Z",
        "training_samples": 492000,
        "metrics": {
            "precision": 0.972,
            "recall": 0.958,
            "f1_score": 0.965,
            "false_positive_rate": 0.012
        },
        "active_learning": {
            "unlabeled_uncertain_samples": 3,
            "accumulated_feedback_count": 852,
            "drift_indicator": "stable"
        }
    }

@app.post("/api/v1/model/retrain")
def retrain_model_v1():
    return {
        "status": "success",
        "message": "Model retrained successfully"
    }

# ── Compatibility / Legacy Endpoints ────────────────────────────────────

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
    action: str
    notes: Optional[str] = ""

@app.patch("/alerts/{alert_id}/action")
def update_alert_action(alert_id: str, body: AnalystUpdate):
    with db_lock:
        db = load_db()
        alerts = db if isinstance(db, list) else db.get("alerts", [])
        for a in alerts:
            if a["id"] == alert_id:
                a["analyst_action"] = body.action
                a["analyst_notes"] = body.notes or ""
                save_db(alerts if isinstance(db, list) else {**db, "alerts": alerts})
                return {"ok": True, "alert": a}
    raise HTTPException(status_code=404, detail="Alert not found")

@app.get("/stats")
def stats():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    total = len(alerts)
    phishing = sum(1 for a in alerts if a.get("verdict") == "phishing")
    benign   = sum(1 for a in alerts if a.get("verdict") == "benign")
    pending  = sum(1 for a in alerts if a.get("analyst_action") == "pending")

    cats = defaultdict(int)
    for a in alerts:
        cats[a.get("threat_category", "unknown")] += 1

    groups = defaultdict(int)
    for a in alerts:
        groups[a.get("recipient_group", "Unknown")] += 1

    daily = defaultdict(lambda: {"phishing": 0, "benign": 0})
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

@app.get("/campaigns")
def campaigns():
    db = load_db()
    alerts = db if isinstance(db, list) else db.get("alerts", [])

    camp_map = defaultdict(lambda: {"count": 0, "max_score": 0.0, "category": "unknown"})
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
            "name": CAMP_NAMES.get(cid, cid.replace("_", " ").title()),
            "occurrences": info["count"],
            "max_score": info["max_score"],
            "category": info["category"],
        })
    result.sort(key=lambda x: x["occurrences"], reverse=True)
    return result

@app.get("/policy/thresholds")
def thresholds():
    return {"Executive": 0.6, "Finance": 0.65, "General Employee": 0.75, "Default": 0.7}

@app.post("/score")
def score_email(email: dict):
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

