"""
api/fusion_engine.py
--------------------
Verdict fusion engine for the APDS pipeline.

Architecture
============
FusionEngine combines header authentication signals, NLP text analysis, and
URL risk scores into a single probability score and a human-readable verdict.
The fusion is inspired by SHAP (SHapley Additive exPlanations): each
contributing feature is assigned a signed delta that is summed with a
calibrated base value of 0.1.

SHAP-style feature attribution weights
---------------------------------------
  Header signals (positive / negative delta):
    SPF Pass              –0.08  (negative = lowers risk)
    SPF Softfail          +0.12
    SPF Fail              +0.25
    SPF Missing           +0.05
    DKIM Valid            –0.06
    DKIM Fail             +0.20
    DKIM Missing          +0.08
    DMARC Pass            –0.10
    DMARC Fail            +0.35
    DMARC Missing         +0.12
    Reply-To Mismatch     +0.30
    Suspicious Hop Count  +0.10 (per extra hop beyond 10)
    Display Name Spoof    +0.25

  NLP signal:
    Intent ≠ benign AND score ≥ 0.15  →  +min(score * 0.5, 0.45)

  URL signal:
    max_url_score ≥ 0.45  →  +min(max * 0.40, 0.45)
    per-indicator contribution (spoofing, shortener, bad SSL)

  Attachment signal:
    High-risk file type  +0.30 per attachment
    Macro-enabled doc    +0.40 per attachment

Verdict thresholds
------------------
  ≥ 0.70  →  phishing
  ≥ 0.40  →  suspicious
  < 0.40  →  benign
"""

from typing import Dict, Any, List


class FusionEngine:
    # Calibrated base value — a fresh email with no signal starts here.
    BASE_VALUE: float = 0.1

    @classmethod
    def fuse_verdict(
        cls,
        parsed_email: Dict[str, Any],
        nlp_result:   Dict[str, Any],
        url_result:   Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculates a final probability score, assigns a category,
        and generates a detailed breakdown of feature attribution (SHAP style).

        Parameters
        ----------
        parsed_email : output from EmailParser.parse_raw_email()
        nlp_result   : output from NLPAnalyzer.analyze_text()
        url_result   : output from URLScorer.evaluate_urls()

        Returns
        -------
        {
            "verdict":           str,   # "phishing" | "suspicious" | "benign"
            "threat_category":   str,   # "credential_harvesting" | "bec" | ...
            "confidence_score":  float, # final probability in [0, 1]
            "base_value":        float, # always 0.1
            "shap_contributions":dict,  # feature_name → signed delta
            "explanations":      list,  # human-readable strings
        }
        """
        shap_contributions: Dict[str, float] = {}
        explanations:       List[str]        = []

        # ── 1. Email authentication header signals ─────────────────────────
        header_score = 0.0

        # SPF ─────────────────────────────────────────────────────────────────
        spf = parsed_email.get("spf_status", "none")
        if spf == "pass":
            # Good SPF decreases phishing likelihood
            val = -0.08
            shap_contributions["SPF Check Passed"] = val
            header_score += val
        elif spf == "fail":
            # Hard SPF failure is a strong spoofing signal
            val = 0.25
            shap_contributions["SPF Authentication Fail"] = val
            explanations.append("SPF Authentication Fail")
            header_score += val
        elif spf in ("softfail", "neutral", "temperror", "permerror"):
            # Soft failures still indicate mail-path anomalies
            val = 0.12
            shap_contributions["SPF Authentication Fail"] = val
            explanations.append("SPF record verification returned " + spf)
            header_score += val
        else:
            # No SPF record at all
            val = 0.05
            shap_contributions["SPF Missing Record"] = val
            header_score += val

        # DKIM ────────────────────────────────────────────────────────────────
        dkim = parsed_email.get("dkim_status", "none")
        if dkim == "pass":
            val = -0.06
            shap_contributions["DKIM Signature Valid"] = val
            header_score += val
        elif dkim == "fail":
            val = 0.20
            shap_contributions["DKIM Validation Fail"] = val
            explanations.append("DKIM cryptographic signature check failed")
            header_score += val
        else:
            # dkim=none — signature absent
            val = 0.08
            shap_contributions["DKIM Missing Signature"] = val
            header_score += val

        # DMARC ───────────────────────────────────────────────────────────────
        dmarc = parsed_email.get("dmarc_status", "none")
        if dmarc == "pass":
            val = -0.10
            shap_contributions["DMARC Policy Pass"] = val
            header_score += val
        elif dmarc == "fail":
            # DMARC fail is the single strongest header indicator of spoofing
            val = 0.35
            shap_contributions["DMARC Policy Fail"] = val
            explanations.append("DMARC alignment checks failed (spoofing indicator)")
            header_score += val
        else:
            val = 0.12
            shap_contributions["DMARC Policy Missing"] = val
            header_score += val

        # ── 2. Reply-To mismatch (common in BEC attacks) ──────────────────
        if parsed_email.get("reply_to_mismatch", False):
            val = 0.30
            shap_contributions["Reply-To Domain Mismatch"] = val
            explanations.append(
                "Reply-to field does not match the sender domain ("
                + parsed_email.get("from_email", "") + ")"
            )
            header_score += val

        # ── 3. Hop count anomaly (message relayed through too many servers) ─
        hops = parsed_email.get("hop_count", 0)
        if hops > 10:
            val = 0.10
            shap_contributions["Suspicious Hops Count"] = val
            explanations.append(
                "Message passed through an abnormally high number of hops ("
                + str(hops) + ")"
            )
            header_score += val

        # ── 4. Display-name impersonation ─────────────────────────────────
        # Flag when the display name looks like a trusted brand but the actual
        # sending domain is external (e.g. "Microsoft Support <evil@random.net>").
        from_display_name = parsed_email.get("from_display_name", "")
        from_email        = parsed_email.get("from_email",        "")

        high_value_terms = ["microsoft", "google", "apple", "amazon", "paypal",
                             "ceo", "cfo", "president", "director", "bank",
                             "support", "security", "helpdesk", "it department"]
        free_domains     = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                             "protonmail.com", "aol.com", "icloud.com"]

        if (from_display_name
                and "@" in from_email
                and any(term in from_display_name.lower() for term in high_value_terms)
                and (from_email.split("@")[-1].lower() not in ["microsoft.com", "google.com"]
                     or any(free in from_email.lower() for free in free_domains))):
            val = 0.25
            shap_contributions["Display Name Impersonation"] = val
            explanations.append(
                "Sender name '" + from_display_name
                + "' mimics authority but uses external domain '"
                + from_email.split("@")[-1] + "'"
            )
            header_score += val

        # ── 5. NLP body analysis contribution ─────────────────────────────
        nlp_score  = nlp_result.get("score",  0.0)
        nlp_intent = nlp_result.get("intent", "benign")

        if nlp_intent != "benign" and nlp_score >= 0.15:
            # Scale NLP score contribution; cap at 0.45 so it cannot alone
            # exceed the phishing threshold without corroborating signals.
            val = round(min(nlp_score * 0.5, 0.45), 3)
            shap_contributions["Semantic Body Threat Cues"] = val

            if nlp_intent == "credential_harvesting":
                explanations.append("Body semantics contain credential harvesting request indicators")
            elif nlp_intent == "bec":
                explanations.append("Linguistic patterns match executive financial manipulation / BEC template")
            elif nlp_intent == "generic_phishing":
                explanations.append("Body text contains urgency language and link coercion cues")

        # ── 6. URL risk score contribution ────────────────────────────────
        url_max_score = url_result.get("max_score", 0.0)

        if url_max_score >= 0.45:
            val = round(min(url_max_score * 0.40, 0.45), 3)
            shap_contributions["Embedded Links Risk Score"] = val

            # Add per-URL indicator explanations
            for detail in url_result.get("details", []):
                for ind in detail.get("indicators", []):
                    if "spoofing" in ind:
                        explanations.append(
                            "Contains link typosquatting mimicking a trusted domain: "
                            + detail.get("domain", "")
                        )
                    elif ind == "redirect_shortener_used":
                        explanations.append(
                            "Redirect or URL shortener link detected to bypass inspection"
                        )
                    elif ind == "ssl_certificate_missing_or_invalid":
                        explanations.append(
                            "Embedded link domain '" + detail.get("domain", "")
                            + "' lacks valid SSL certificate"
                        )
        elif url_max_score > 0:
            # Low-risk URL: still contributes but below explanation threshold
            val = round(url_max_score * 0.40, 3)
            shap_contributions["Embedded Links Risk Score"] = val

        # ── 7. Dangerous attachment signals ──────────────────────────────
        attachments   = parsed_email.get("attachments", [])
        attach_weight = 0.0

        for att in attachments:
            if att.get("is_high_risk", False):
                attach_weight += 0.30
                explanations.append(
                    "High-risk attachment format detected: '"
                    + att.get("filename", "") + "'"
                )
            if att.get("has_macros", False):
                attach_weight += 0.40
                explanations.append(
                    "Office document containing macro script: '"
                    + att.get("filename", "") + "'"
                )

        if attach_weight > 0:
            shap_contributions["Dangerous Attachments Signal"] = round(min(attach_weight, 1.0), 3)

        # ── 8. Final score calculation ────────────────────────────────────
        # Sum the base value with all SHAP contributions.  Clamp to [0, 1].
        total_delta       = sum(shap_contributions.values())
        final_probability = round(min(max(cls.BASE_VALUE + total_delta, 0.0), 1.0), 3)

        # ── 9. Assign verdict ─────────────────────────────────────────────
        if final_probability >= 0.70:
            verdict = "phishing"
        elif final_probability >= 0.40:
            verdict = "suspicious"
        else:
            verdict = "benign"

        # ── 10. Infer threat category from NLP intent and URL signals ──────
        if verdict == "benign":
            threat_category = "benign"
        elif nlp_intent in ("credential_harvesting", "bec", "generic_phishing"):
            threat_category = nlp_intent
        elif any("spoofing" in ind for detail in url_result.get("details", [])
                 for ind in detail.get("indicators", [])):
            threat_category = "credential_harvesting"
        elif any(att.get("is_high_risk", False) for att in attachments):
            threat_category = "malware_delivery"
        else:
            threat_category = nlp_intent if nlp_intent != "benign" else "generic_phishing"

        # ── 11. Default explanation ───────────────────────────────────────
        if not explanations:
            explanations.append("No suspicious headers, language patterns, or URL risks detected.")

        # De-duplicate explanations while preserving order
        unique_explanations = list(dict.fromkeys(exp for exp in explanations if exp))

        return {
            "verdict":            verdict,
            "threat_category":    threat_category,
            "confidence_score":   final_probability,
            "base_value":         cls.BASE_VALUE,
            "shap_contributions": shap_contributions,
            "explanations":       unique_explanations,
        }
