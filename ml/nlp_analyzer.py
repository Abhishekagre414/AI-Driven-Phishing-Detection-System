"""
api/nlp_analyzer.py
-------------------
NLP-based phishing intent classifier for the APDS pipeline.

Architecture
============
No heavyweight transformer is loaded at runtime. Instead the engine uses a
hand-curated, weighted keyword lexicon organised by threat category.
Scores from each category are combined into a single global probability via
a sigmoid-like normalisation so the output is always in [0, 1].

Keyword weights (per category)
---------------------------------
Each keyword maps to a float weight that represents how strongly its presence
shifts the confidence score toward that threat category:

  2.5  – very strong indicator  (e.g. "reset password")
  2.0  – strong indicator
  1.8  – moderately strong
  1.5  – moderate indicator
  1.2  – weak indicator
  1.0  – baseline hit

Scoring formula (global)
------------------------
  total_threat = cred_score + bec_score + (0.5 * urgency_score) + generic_score + obfuscation_score
  val          = (total_threat - 1.5) / 4.0
  global_score = 1 / (1 + e^(-val))   # sigmoid normalisation

Category probabilities are independently normalised in [0, 1] via:
  prob = min(1.0, category_raw / max_possible_sum)
"""

import re
from typing import Dict, Any, List


class NLPAnalyzer:
    # ── Credential-Harvesting Keywords ───────────────────────────────────────
    # These phrases are commonly used in fake login / account-verification emails.
    KEYWORDS_CREDENTIALS: Dict[str, float] = {
        "reset password":           2.5,
        "update password":          2.0,
        "confirm password":         2.0,
        "verify your identity":     2.0,
        "verify identity":          2.0,
        "re-authenticate":          2.0,
        "login verification":       2.0,
        "security checkpoint":      2.0,
        "account verification":     1.8,
        "sign-in attempt":          1.5,
        "unusual sign-in":          1.5,
        "unusual activity":         1.5,
        "credential check":         1.5,
        "keep your password":       1.5,
        "click here to login":      2.2,
        "access suspended":         2.0,
        "renew credentials":        2.0,
        "two-factor authentication":1.2,
        "2fa confirmation":         1.2,
        "otp code":                 1.2,
    }

    # ── BEC / Business Email Compromise Keywords ──────────────────────────────
    # Phrases associated with wire-transfer fraud, gift-card scams, and
    # impersonation of executives.
    KEYWORDS_BEC: Dict[str, float] = {
        "wire transfer":            3.0,
        "bank details":             3.0,
        "routing number":           3.0,
        "direct deposit":           3.0,
        "payroll setup":            3.0,
        "invoice payment":          3.0,
        "swift code":               3.0,
        "ach transfer":             3.0,
        "financial transaction":    3.0,
        "unpaid invoice":           3.0,
        "change in bank":           3.0,
        "urgent payment":           3.0,
        "confidential deal":        3.0,
        "executive transfer":       3.0,
        "send money":               3.0,
        "purchase gift cards":      3.0,
        "google play card":         2.8,
        "steam gift card":          2.8,
        "temporary billing":        3.0,
        "reimbursement":            3.0,
    }

    # ── Urgency / Coercion Cues ───────────────────────────────────────────────
    # Phrases designed to pressure the recipient into acting without thinking.
    # These contribute at half-weight to the total threat score.
    KEYWORDS_URGENCY: Dict[str, float] = {
        "urgent":                   1.5,
        "immediate action":         1.5,
        "action required":          1.5,
        "suspended":                1.5,
        "terminated":               1.5,
        "deleted permanently":      1.5,
        "within 24 hours":          1.5,
        "before the deadline":      1.5,
        "last chance":              1.5,
        "account lock":             1.5,
        "unauthorized access":      1.5,
        "critical update":          1.5,
        "expires soon":             1.5,
        "pay immediately":          1.5,
        "failure to comply":        1.5,
        "disruption of service":    1.5,
        "restricted account":       1.6,
        "failure to respond":       1.7,
    }

    # ── Generic Phishing Lure Keywords ───────────────────────────────────────
    # Common lure themes: delivery notices, lottery wins, document sharing.
    KEYWORDS_GENERIC_PHISH: Dict[str, float] = {
        "shared a document":        1.5,
        "onedrive file":            1.5,
        "google doc":               1.5,
        "docuSign request":         1.5,
        "adobe sign":               1.5,
        "winning notification":     1.5,
        "lottery":                  1.5,
        "package delivery":         1.5,
        "dhl tracking":             1.5,
        "fedex shipment":           1.5,
        "usps delivery":            1.5,
        "refund check":             1.5,
        "tax refund":               1.5,
        "gift voucher":             1.5,
        "free credit":              1.5,
    }

    @classmethod
    def analyze_text(cls, text: str) -> Dict[str, Any]:
        """
        Analyzes body text for intent categories using semantic keyword grouping
        and calculates score probabilities using scaling.
        """
        text_lower = text.lower()

        # ── Step 1: Raw category scores via weighted keyword matching ──────
        # Sum the weights of every matched keyword per category.
        cred_score    = sum(weight for kw, weight in cls.KEYWORDS_CREDENTIALS.items()   if kw in text_lower)
        bec_score     = sum(weight for kw, weight in cls.KEYWORDS_BEC.items()            if kw in text_lower)
        urgency_score = sum(weight for kw, weight in cls.KEYWORDS_URGENCY.items()        if kw in text_lower)
        generic_score = sum(weight for kw, weight in cls.KEYWORDS_GENERIC_PHISH.items() if kw in text_lower)

        # ── Step 2: Extra heuristic bonuses ──────────────────────────────────
        # Time-deadline pattern: "within 3 hours", "expires in 24 hours" etc.
        has_deadline = bool(re.search(r'(within\s+\d+\s+(hour|day|min)|deadline|expires\s+in)', text_lower))
        if has_deadline:
            urgency_score += 1.5   # Strong urgency amplifier

        # Executive authority check: sender mentions CEO / CFO in body text
        is_exec_authority = bool(re.search(
            r'(president|ceo|cfo|director|founder|chairman|confidential request|are you at your desk)',
            text_lower
        ))
        if is_exec_authority:
            bec_score += 1.0       # BEC boost for impersonated authority figure

        # Obfuscation detection: clusters of non-word, non-space chars (e.g. «ᗷ➨🔗»)
        obfuscation_score = 1.0 if re.search(r'[^\s\w]{5,}', text_lower) else 0.0

        # ── Step 3: Normalised per-category probabilities ─────────────────
        # Normalise each raw score against a maximum possible hit total so the
        # per-category probability stays in [0, 1].
        scores = {
            "credential_harvesting": cred_score,
            "bec":                   bec_score,
            "generic_phishing":      generic_score,
        }

        # The maximum raw score achievable per category (sum of all weights).
        max_possible_sum = {
            "credential_harvesting": 12.0,   # calibrated to all KEYWORDS_CREDENTIALS weights
            "bec":                   6.0,    # calibrated to highest-weight BEC cluster
            "generic_phishing":      3.0,
        }

        probs: Dict[str, float] = {}
        max_cat = "benign"
        max_prob = 0.0
        for cat, sc in scores.items():
            val  = sc / max_possible_sum.get(cat, 1.0)
            prob = round(min(1.0, float(val)), 3)
            probs[cat] = prob
            if prob > max_prob:
                max_prob = prob
                max_cat  = cat

        # ── Step 4: Global threat score via sigmoid normalisation ──────────
        # Aggregate all threat dimensions, then pass through a sigmoid so the
        # output is always in [0, 1]. The formula mirrors the original bytecode:
        #   total = cred + bec + (0.5 * urgency) + generic + obfuscation
        #   val   = (total - 1.5) / 4.0
        #   score = 1 / (1 + e^(-val))
        total_threat = cred_score + bec_score + (0.5 * urgency_score) + generic_score + obfuscation_score
        global_score = 0.0
        if total_threat > 0:
            val          = (total_threat - 1.5) / 4.0
            global_score = round(1.0 / (1.0 + float(2.71828 ** -val)), 3)

        # If the global score is below the noise floor, treat as benign.
        if global_score < 0.15:
            max_cat = "benign"

        # ── Step 5: Build linguistic signal list ──────────────────────────
        # Emit a structured signal for each category that fired.
        signals: List[Dict[str, Any]] = []

        if cred_score > 0:
            signals.append({"signal": "credential_harvesting_intent", "weight": round(cred_score / 12.0, 3)})
        if bec_score > 0:
            signals.append({"signal": "bec_financial_intent",          "weight": round(bec_score / 6.0, 3)})
        if urgency_score > 0:
            signals.append({"signal": "urgency_coercion_cues",         "weight": round(min(1.0, urgency_score / 5.0), 3)})
        if generic_score > 0:
            signals.append({"signal": "lure_phishing_cues",            "weight": round(min(1.0, generic_score / 4.0), 3)})
        if obfuscation_score > 0:
            signals.append({"signal": "text_obfuscation_indicators",   "weight": round(obfuscation_score, 3)})

        return {
            "score":              global_score,
            "intent":             max_cat,
            "categories":         probs,
            "linguistic_signals": signals,
        }
