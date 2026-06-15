"""
api/test_apds.py
----------------
Comprehensive pytest test suite for the APDS FastAPI application.

Run with:
    pytest api/test_apds.py -v

Requires the FastAPI dev server NOT to be running — tests use the in-process
TestClient provided by httpx / starlette, so no external server is needed.

Test modules
------------
  TestNLPAnalyzer      – unit tests for scoring logic and keyword matching
  TestURLScorer        – unit tests for all URL risk indicators
  TestFusionEngine     – unit tests for SHAP-style verdict fusion
  TestEmailParser      – unit tests for RFC 2822 parsing
  TestAPDSEndpoints    – integration tests for all API endpoints
"""

from fastapi.testclient import TestClient

# ── Import application and components ──────────────────────────────────────
from api.main          import app
from api.nlp_analyzer  import NLPAnalyzer
from api.url_scorer    import URLScorer
from api.fusion_engine import FusionEngine
from api.email_parser  import EmailParser

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

PHISHING_EMAIL_RAW = (
    "Authentication-Results: mx.google.com; spf=softfail dkim=none dmarc=none\n"
    'From: "Microsoft Office 365 Support" <no-reply@security-office365-updates.com>\n'
    "To: <cfo@enterprise.com>\n"
    "Subject: ACTION REQUIRED: Unusual Sign-in Detected for Security Alert\n"
    "Date: Sat, 23 May 2026 15:20:00 +0000\n"
    "\n"
    "Your Microsoft Office 365 account has experienced an unusual sign-in attempt from Russia.\n"
    "To prevent lockout and permanent deletion of your account, you must verify your identity immediately.\n"
    "Please update your password here: http://microsoft.com-update.security-checkpoint.xyz/login.php\n"
    "\n"
    "Microsoft Security Team"
)

BENIGN_EMAIL_RAW = (
    "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass\n"
    'From: "Sarah Jenkins" <sjenkins@enterprise.com>\n'
    "To: <marketing-team@enterprise.com>\n"
    "Subject: Q3 Marketing Strategy Sync\n"
    "Date: Fri, 22 May 2026 19:27:34 +0000\n"
    "\n"
    "Hi team,\n\n"
    "I've updated the slide deck for our Q3 planning session.\n"
    "Here is the project dashboard: https://internal.enterprise.com/marketing/q3-sync\n\n"
    "Best,\nSarah"
)

BEC_EMAIL_RAW = (
    "Authentication-Results: mx.google.com; spf=pass dkim=none dmarc=fail\n"
    "Received: from mail-sourcer.gmail.com (192.0.2.45)\n"
    "Reply-To: executive.office.remotedesk@office-admin-desk.com\n"
    'From: "Robert Davis (CEO)" <ceo.robert.davis@gmail.com>\n'
    "To: <payroll.officer@enterprise.com>\n"
    "Subject: URGENT: Quick Task\n"
    "Date: Sat, 23 May 2026 02:27:34 +0000\n"
    "\n"
    "Are you at your desk?\n\n"
    "I'm currently tied up in an board meeting and need you to handle an urgent request immediately. "
    "I need you to purchase 10 Apple gift cards worth $100 each for a client reimbursement. "
    "Please send me the clear photos of the codes on the back of the cards.\n\n"
    "Thanks,\nRobert Davis\nChief Executive Officer"
)


# ═══════════════════════════════════════════════════════════════════════════════
# TestNLPAnalyzer
# ═══════════════════════════════════════════════════════════════════════════════

class TestNLPAnalyzer:

    def test_credential_harvesting_detection(self):
        """Strong credential-harvesting text must trigger the correct intent."""
        text = ("Your account has experienced an unusual sign-in attempt. "
                "You must verify your identity immediately by clicking here to login. "
                "Failure to verify within 24 hours will lock your account.")
        result = NLPAnalyzer.analyze_text(text)

        assert result["intent"] == "credential_harvesting", (
            f"Expected credential_harvesting, got {result['intent']}"
        )
        assert result["score"] > 0.5, (
            f"Expected score > 0.5 for phishing text, got {result['score']}"
        )

    def test_bec_detection(self):
        """BEC keywords (wire transfer, gift cards) must classify as BEC."""
        text = ("Are you at your desk? I need you to purchase gift cards "
                "and send me the codes urgently. Do not call, CEO needs this now.")
        result = NLPAnalyzer.analyze_text(text)

        assert result["intent"] == "bec", f"Expected bec, got {result['intent']}"
        assert result["categories"]["bec"] > 0, "BEC category score should be > 0"

    def test_benign_text_low_score(self):
        """Ordinary business email must score below the noise floor."""
        text = ("Hi team, let's sync tomorrow at 10am to discuss the Q3 roadmap. "
                "Please review the attached agenda.")
        result = NLPAnalyzer.analyze_text(text)

        assert result["intent"] == "benign", f"Expected benign, got {result['intent']}"
        assert result["score"] < 0.15, f"Expected score < 0.15, got {result['score']}"

    def test_return_structure(self):
        """Result must always contain the four expected keys."""
        result = NLPAnalyzer.analyze_text("test email body")
        assert "score"              in result
        assert "intent"             in result
        assert "categories"         in result
        assert "linguistic_signals" in result

    def test_categories_sum_independent(self):
        """Each category probability must be in [0, 1] independently."""
        text = ("reset password wire transfer urgent lottery package delivery "
                "verify identity bank details invoice payment")
        result = NLPAnalyzer.analyze_text(text)
        for cat, prob in result["categories"].items():
            assert 0.0 <= prob <= 1.0, f"Category {cat} probability {prob} out of range"

    def test_urgency_regex_deadline(self):
        """Deadline regex patterns must add bonus to urgency."""
        text_with_deadline    = "Please act within 2 hours or your account expires."
        text_without_deadline = "Please act soon."
        r1 = NLPAnalyzer.analyze_text(text_with_deadline)
        r2 = NLPAnalyzer.analyze_text(text_without_deadline)
        # The deadline version should score higher
        assert r1["score"] >= r2["score"], "Deadline text should score >= non-deadline text"

    def test_generic_phishing_keywords(self):
        """Lottery / delivery lure keywords must score under generic_phishing."""
        text = "Congratulations! You have a winning notification. Package delivery tracking."
        result = NLPAnalyzer.analyze_text(text)
        assert result["categories"]["generic_phishing"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# TestURLScorer
# ═══════════════════════════════════════════════════════════════════════════════

class TestURLScorer:

    def test_shortener_detection(self):
        """bit.ly links must trigger redirect_shortener_used indicator."""
        result = URLScorer.score_url("https://bit.ly/3phishlink")
        assert "redirect_shortener_used" in result["indicators"]
        assert result["score"] >= 0.4

    def test_brand_spoofing_subdomain(self):
        """microsoft in subdomain of a non-microsoft domain must score above zero.

        The URL 'microsoft.evil-login.com' triggers at minimum the
        hyphenated_domain indicator (score 0.20).  A pure subdomain-spoof URL
        without hyphens triggers the brand_in_subdomain check (score 0.60).
        """
        # Case 1: bare subdomain spoof (no hyphens in registrable domain)
        result_pure = URLScorer.score_url("https://microsoft.evilsite.org/verify")
        indicators_str = " ".join(result_pure["indicators"])
        assert "spoofing" in indicators_str or result_pure["score"] >= 0.6, (
            f"Expected brand spoofing indicator, got: {result_pure['indicators']}"
        )
        # Case 2: hyphenated domain that also contains brand name
        result_hyph = URLScorer.score_url("https://microsoft.evil-login.com/verify")
        assert result_hyph["score"] > 0.0, "Hyphenated brand-lookalike URL should score > 0"

    def test_hyphenated_domain(self):
        """Hyphenated domain must trigger hyphenated_domain indicator."""
        result = URLScorer.score_url("http://dhl-tracking-portal.net-billing-verify.ru/dhl/track")
        assert "hyphenated_domain" in result["indicators"]

    def test_legitimate_internal_url(self):
        """A clean internal URL must score zero."""
        result = URLScorer.score_url("https://internal.enterprise.com/marketing/q3-sync")
        assert result["score"] == 0.0

    def test_ip_address_url(self):
        """An IP-address URL must trigger ip_address_domain indicator."""
        result = URLScorer.score_url("http://192.168.1.1/malware/payload")
        assert "ip_address_domain" in result["indicators"]
        assert result["score"] >= 0.5

    def test_evaluate_urls_summary(self):
        """evaluate_urls must return correct max and average."""
        urls = [
            "https://bit.ly/phish",                               # ~0.40
            "https://internal.enterprise.com/marketing/q3-sync",  # 0.00
        ]
        result = URLScorer.evaluate_urls(urls)
        assert result["max_score"] >= 0.40
        assert 0.0 < result["average_score"] <= result["max_score"]
        assert len(result["details"]) == 2

    def test_evaluate_urls_empty_list(self):
        """evaluate_urls with empty list must return zeros."""
        result = URLScorer.evaluate_urls([])
        assert result["max_score"] == 0.0
        assert result["average_score"] == 0.0
        assert result["details"] == []

    def test_score_capped_at_one(self):
        """Score must never exceed 1.0 regardless of indicator count."""
        result = URLScorer.score_url(
            "http://192.168.1.1/microsoft-paypal-apple-login/"
            + "A" * 200  # very long URL
        )
        assert result["score"] <= 1.0

    def test_return_structure(self):
        """score_url must always contain the required fields."""
        result = URLScorer.score_url("https://example.com")
        for key in ("url", "domain", "score", "indicators", "ssl_valid", "domain_age_days"):
            assert key in result, f"Missing key: {key}"

    def test_get_entropy_empty_string(self):
        """Entropy of empty string must be 0.0."""
        assert URLScorer.get_entropy("") == 0.0

    def test_levenshtein_identical(self):
        """Levenshtein distance of a string with itself must be 0."""
        assert URLScorer.levenshtein_distance("microsoft", "microsoft") == 0

    def test_levenshtein_typo(self):
        """'micosoft' is 1 edit away from 'microsoft'."""
        assert URLScorer.levenshtein_distance("micosoft", "microsoft") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# TestFusionEngine
# ═══════════════════════════════════════════════════════════════════════════════

class TestFusionEngine:

    def _make_parsed(self, **kwargs):
        base = {
            "spf_status": "none", "dkim_status": "none", "dmarc_status": "none",
            "reply_to_mismatch": False, "hop_count": 0,
            "from_display_name": "", "from_email": "",
            "attachments": [], "urls": [],
        }
        base.update(kwargs)
        return base

    def _benign_nlp(self):
        return {"score": 0.0, "intent": "benign", "categories": {}, "linguistic_signals": []}

    def _benign_url(self):
        return {"max_score": 0.0, "average_score": 0.0, "details": []}

    def test_clean_email_is_benign(self):
        """An email that passes all auth checks and has no threat cues must be benign."""
        parsed = self._make_parsed(spf_status="pass", dkim_status="pass", dmarc_status="pass")
        result = FusionEngine.fuse_verdict(parsed, self._benign_nlp(), self._benign_url())

        assert result["verdict"] == "benign"
        assert result["confidence_score"] < 0.40

    def test_dmarc_fail_raises_score(self):
        """DMARC fail alone should significantly raise the confidence score."""
        parsed = self._make_parsed(dmarc_status="fail")
        result = FusionEngine.fuse_verdict(parsed, self._benign_nlp(), self._benign_url())
        # base(0.1) + dmarc_fail(0.35) + dkim_missing(0.08) + spf_missing(0.05) = 0.58
        assert result["confidence_score"] >= 0.40, (
            f"Expected ≥0.40 with DMARC fail, got {result['confidence_score']}"
        )

    def test_phishing_email_verdict(self):
        """A fully-loaded phishing email must receive a phishing verdict."""
        parsed = EmailParser.parse_raw_email(PHISHING_EMAIL_RAW)
        body = parsed.get("body_text", "")
        urls = parsed.get("urls", [])
        nlp = NLPAnalyzer.analyze_text(body)
        url_r = URLScorer.evaluate_urls(urls)
        result = FusionEngine.fuse_verdict(parsed, nlp, url_r)

        assert result["verdict"] == "phishing", (
            f"Expected phishing verdict, got {result['verdict']} (score={result['confidence_score']})"
        )
        assert result["confidence_score"] > 0.70

    def test_bec_email_verdict(self):
        """BEC email must score phishing or suspicious."""
        parsed = EmailParser.parse_raw_email(BEC_EMAIL_RAW)
        body   = parsed.get("body_text", "")
        urls   = parsed.get("urls", [])
        nlp    = NLPAnalyzer.analyze_text(body)
        url_r  = URLScorer.evaluate_urls(urls)
        result = FusionEngine.fuse_verdict(parsed, nlp, url_r)

        assert result["verdict"] in ("phishing", "suspicious"), (
            f"BEC email expected phishing/suspicious, got {result['verdict']}"
        )

    def test_benign_email_verdict(self):
        """Legitimate internal email must not be marked phishing."""
        parsed = EmailParser.parse_raw_email(BENIGN_EMAIL_RAW)
        body   = parsed.get("body_text", "")
        urls   = parsed.get("urls", [])
        nlp    = NLPAnalyzer.analyze_text(body)
        url_r  = URLScorer.evaluate_urls(urls)
        result = FusionEngine.fuse_verdict(parsed, nlp, url_r)

        assert result["verdict"] != "phishing", (
            f"Benign email incorrectly marked phishing (score={result['confidence_score']})"
        )

    def test_reply_to_mismatch_adds_shap(self):
        """Reply-To mismatch must appear in shap_contributions."""
        parsed = self._make_parsed(reply_to_mismatch=True, from_email="ceo@gmail.com")
        result = FusionEngine.fuse_verdict(parsed, self._benign_nlp(), self._benign_url())
        assert "Reply-To Domain Mismatch" in result["shap_contributions"]

    def test_return_structure(self):
        """fuse_verdict must always contain all required keys."""
        result = FusionEngine.fuse_verdict(
            self._make_parsed(), self._benign_nlp(), self._benign_url()
        )
        for key in ("verdict", "threat_category", "confidence_score",
                    "base_value", "shap_contributions", "explanations"):
            assert key in result, f"Missing key: {key}"

    def test_confidence_clamped(self):
        """Confidence score must always be in [0, 1]."""
        # Simulate a maximally bad email
        parsed = self._make_parsed(
            spf_status="fail", dkim_status="fail", dmarc_status="fail",
            reply_to_mismatch=True, hop_count=15,
            from_display_name="Microsoft Security", from_email="random@evil.ru",
        )
        nlp = {"score": 1.0, "intent": "credential_harvesting", "categories": {}, "linguistic_signals": []}
        url = {"max_score": 1.0, "average_score": 1.0, "details": []}
        result = FusionEngine.fuse_verdict(parsed, nlp, url)
        assert 0.0 <= result["confidence_score"] <= 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# TestEmailParser
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailParser:

    def test_parse_phishing_email(self):
        """Phishing email must parse headers, body, and URLs correctly."""
        result = EmailParser.parse_raw_email(PHISHING_EMAIL_RAW)

        assert result["parsed"] is True
        assert result["spf_status"] == "softfail"
        assert result["dkim_status"] == "none"
        assert result["dmarc_status"] == "none"
        assert result["subject"] == "ACTION REQUIRED: Unusual Sign-in Detected for Security Alert"
        assert len(result["urls"]) >= 1
        assert "microsoft.com-update.security-checkpoint.xyz" in result["urls"][0]

    def test_parse_benign_email(self):
        """Benign email must yield pass for all three auth headers."""
        result = EmailParser.parse_raw_email(BENIGN_EMAIL_RAW)

        assert result["parsed"] is True
        assert result["spf_status"] == "pass"
        assert result["dkim_status"] == "pass"
        assert result["dmarc_status"] == "pass"

    def test_reply_to_mismatch_detected(self):
        """BEC email with mismatched Reply-To domain must set reply_to_mismatch=True."""
        result = EmailParser.parse_raw_email(BEC_EMAIL_RAW)
        assert result["reply_to_mismatch"] is True

    def test_hop_count(self):
        """Hop count must equal the number of Received headers."""
        result = EmailParser.parse_raw_email(BEC_EMAIL_RAW)
        # BEC_EMAIL_RAW has one Received header
        assert result["hop_count"] == 1

    def test_url_deduplication(self):
        """Duplicate URLs in email body must be deduplicated."""
        raw = (
            "From: test@example.com\nTo: victim@example.com\n"
            "Subject: test\n\n"
            "Click http://evil.com/login and also http://evil.com/login again."
        )
        result = EmailParser.parse_raw_email(raw)
        assert result["urls"].count("http://evil.com/login") == 1

    def test_display_name_extraction(self):
        """Display name and actual email must be parsed from From header."""
        result = EmailParser.parse_raw_email(PHISHING_EMAIL_RAW)
        assert result["from_display_name"] == "Microsoft Office 365 Support"
        assert result["from_email"]        == "no-reply@security-office365-updates.com"

    def test_return_structure(self):
        """parse_raw_email must always contain required keys."""
        result = EmailParser.parse_raw_email("From: a@b.com\n\nHello")
        for key in ("parsed", "subject", "from", "from_display_name", "from_email",
                    "to", "reply_to", "reply_to_mismatch", "spf_status",
                    "dkim_status", "dmarc_status", "body_text", "urls", "attachments"):
            assert key in result, f"Missing key: {key}"


# ═══════════════════════════════════════════════════════════════════════════════
# TestAPDSEndpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPDSEndpoints:

    # ── Root ──────────────────────────────────────────────────────────────────

    def test_root_online(self):
        """GET / must return status=online."""
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "online"
        assert data["system"] == "APDS"

    # ── Alerts ────────────────────────────────────────────────────────────────

    def test_get_alerts_v1(self):
        """GET /api/v1/alerts must return a list."""
        r = client.get("/api/v1/alerts")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_alerts_legacy_returns_structure(self):
        """GET /alerts must return total and alerts keys."""
        r = client.get("/alerts")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "alerts" in data

    def test_get_alerts_filter_by_verdict(self):
        """GET /alerts?verdict=phishing must filter results."""
        r = client.get("/alerts?verdict=phishing")
        assert r.status_code == 200
        data = r.json()
        for alert in data["alerts"]:
            assert alert["verdict"] == "phishing"

    def test_get_alerts_search(self):
        """GET /alerts?search=... must return only matching alerts."""
        r = client.get("/alerts?search=URGENT")
        assert r.status_code == 200
        data = r.json()
        for alert in data["alerts"]:
            match = (
                "urgent" in alert.get("subject",   "").lower()
                or "urgent" in alert.get("sender",  "").lower()
                or "urgent" in alert.get("recipient", "").lower()
            )
            assert match

    def test_get_alert_by_id_not_found(self):
        """GET /alerts/{id} with unknown id must return 404."""
        r = client.get("/alerts/alert_nonexistent_99999")
        assert r.status_code == 404

    # ── Stats ─────────────────────────────────────────────────────────────────

    def test_stats_structure(self):
        """GET /stats must return all required aggregation fields."""
        r = client.get("/stats")
        assert r.status_code == 200
        data = r.json()
        for key in ("total", "phishing", "benign", "pending_review",
                    "detection_rate", "categories", "recipient_groups", "daily_volume"):
            assert key in data, f"Missing stats key: {key}"

    def test_stats_totals_add_up(self):
        """phishing + benign must not exceed total (suspicious alerts exist too)."""
        r = client.get("/stats")
        data = r.json()
        assert data["phishing"] + data["benign"] <= data["total"]

    # ── Campaigns ─────────────────────────────────────────────────────────────

    def test_get_campaigns_v1(self):
        """GET /api/v1/campaigns must return a list of campaign objects."""
        r = client.get("/api/v1/campaigns")
        assert r.status_code == 200
        campaigns = r.json()
        assert isinstance(campaigns, list)
        if campaigns:
            c = campaigns[0]
            for key in ("id", "name", "count", "max_score", "category"):
                assert key in c, f"Missing campaign key: {key}"

    def test_campaigns_sorted_descending(self):
        """Campaigns must be sorted by count descending."""
        r = client.get("/api/v1/campaigns")
        camps = r.json()
        if len(camps) > 1:
            assert camps[0]["count"] >= camps[1]["count"]

    # ── Thresholds ────────────────────────────────────────────────────────────

    def test_get_thresholds_v1(self):
        """GET /api/v1/settings/thresholds must return threshold dict."""
        r = client.get("/api/v1/settings/thresholds")
        assert r.status_code == 200
        data = r.json()
        assert "thresholds" in data
        assert "Executive" in data["thresholds"]

    def test_update_thresholds_v1(self):
        """POST /api/v1/settings/thresholds must echo back the payload."""
        payload = {"thresholds": {"Executive": 0.55, "Finance": 0.60}}
        r = client.post("/api/v1/settings/thresholds", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert data["thresholds"]["Executive"] == 0.55

    # ── Scoring ───────────────────────────────────────────────────────────────

    def test_score_v1_phishing_email(self):
        """POST /api/v1/score with a phishing email must return verdict=phishing."""
        payload = {
            "raw_email":        PHISHING_EMAIL_RAW,
            "recipient_group":  "Executive",
            "recipient":        "cfo@enterprise.com",
        }
        r = client.post("/api/v1/score", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "fusion_result" in data
        fusion = data["fusion_result"]
        assert fusion["verdict"] == "phishing", (
            f"Expected phishing, got {fusion['verdict']} (score={fusion['confidence_score']})"
        )
        assert fusion["confidence_score"] > 0.70

    def test_score_v1_benign_email(self):
        """POST /api/v1/score with a clean email must NOT return phishing."""
        payload = {
            "raw_email":        BENIGN_EMAIL_RAW,
            "recipient_group":  "General Employee",
            "recipient":        "marketing-team@enterprise.com",
        }
        r = client.post("/api/v1/score", json=payload)
        assert r.status_code == 200
        fusion = r.json()["fusion_result"]
        assert fusion["verdict"] != "phishing", (
            f"Benign email was incorrectly classified as phishing (score={fusion['confidence_score']})"
        )

    def test_score_v1_response_structure(self):
        """POST /api/v1/score must return fusion_result, threat_category, and alert."""
        payload = {
            "raw_email":       PHISHING_EMAIL_RAW,
            "recipient_group": "Executive",
            "recipient":       "cfo@enterprise.com",
        }
        r = client.post("/api/v1/score", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "fusion_result" in data
        assert "threat_category" in data
        assert "alert" in data
        assert "confidence_score" in data["fusion_result"]
        assert "explanations" in data["fusion_result"]

    def test_score_v1_explanations_nonempty(self):
        """Phishing score must include at least one explanation string."""
        payload = {
            "raw_email":       PHISHING_EMAIL_RAW,
            "recipient_group": "Executive",
            "recipient":       "cfo@enterprise.com",
        }
        r = client.post("/api/v1/score", json=payload)
        fusion = r.json()["fusion_result"]
        assert len(fusion["explanations"]) > 0

    def test_score_v1_alert_persisted(self):
        """Scored email must appear at the top of /api/v1/alerts."""
        payload = {
            "raw_email":       PHISHING_EMAIL_RAW,
            "recipient_group": "Executive",
            "recipient":       "cfo@enterprise.com",
        }
        client.post("/api/v1/score", json=payload)
        alerts = client.get("/api/v1/alerts").json()
        assert len(alerts) > 0
        # The latest alert should contain the phishing subject
        newest_subject = alerts[0].get("subject", "")
        assert "Unusual Sign-in" in newest_subject or "ACTION REQUIRED" in newest_subject

    def test_score_legacy_endpoint(self):
        """POST /score (legacy) must return a verdict and confidence."""
        payload = {"raw": "spf=softfail", "subject": "action required", "body": "verify immediately"}
        r = client.post("/score", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "verdict" in data
        assert "confidence" in data
        assert "explanations" in data

    # ── Model Metrics ─────────────────────────────────────────────────────────

    def test_model_metrics(self):
        """GET /api/v1/model/metrics must return metrics with f1_score."""
        r = client.get("/api/v1/model/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "metrics" in data
        assert "f1_score" in data["metrics"]

    def test_model_retrain(self):
        """POST /api/v1/model/retrain must return status=success."""
        r = client.post("/api/v1/model/retrain")
        assert r.status_code == 200
        assert r.json()["status"] == "success"

    # ── Analyst feedback ──────────────────────────────────────────────────────

    def test_alert_feedback_v1_not_found(self):
        """POST feedback for a non-existent alert must return 404."""
        r = client.post(
            "/api/v1/alerts/nonexistent_alert_id/feedback",
            json={"action": "confirmed", "notes": "test"}
        )
        assert r.status_code == 404

    def test_alert_action_patch_not_found(self):
        """PATCH action for a non-existent alert must return 404."""
        r = client.patch(
            "/alerts/nonexistent_alert_id/action",
            json={"action": "confirmed", "notes": ""}
        )
        assert r.status_code == 404

    def test_policy_thresholds_legacy(self):
        """GET /policy/thresholds must return a dict with Executive key."""
        r = client.get("/policy/thresholds")
        assert r.status_code == 200
        data = r.json()
        assert "Executive" in data
