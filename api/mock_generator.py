"""
api/mock_generator.py
---------------------
Synthetic email generator and database seeder for the APDS demo pipeline.

Usage
-----
    python -m api.mock_generator           # seeds alerts_db.json with 30 alerts

    from api.mock_generator import MockEmailGenerator
    raw = MockEmailGenerator.construct_rfc2822(template, date_str)
    alerts = MockEmailGenerator.generate_alerts_database(count=30)

The module contains five realistic email templates covering all threat
categories recognised by the APDS scoring engine:
    - benign             (legitimate internal email)
    - bec                (Business Email Compromise / gift-card scam)
    - credential_harvesting (Microsoft O365 spoofing)
    - generic_phishing   (DHL / FedEx delivery notice)
    - malware_delivery   (macro-enabled invoice attachment)
"""

import json
import os
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List

from api.email_parser import EmailParser
from api.nlp_analyzer import NLPAnalyzer
from api.url_scorer    import URLScorer
from api.fusion_engine import FusionEngine

# ── Email templates ─────────────────────────────────────────────────────────
# Each template is a dict that MockEmailGenerator.construct_rfc2822() turns
# into a properly-formatted RFC 2822 string that EmailParser can parse.

TEMPLATES: List[Dict[str, Any]] = [
    # ── 1. Benign: routine internal email ────────────────────────────────
    {
        "type": "benign",
        "sender_name":  "Sarah Jenkins",
        "sender_email": "sjenkins@enterprise.com",
        "subject":      "Q3 Marketing Strategy Sync",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass\n"
            "Received: from mail.enterprise.com (mail.enterprise.com [198.51.100.12])\n"
            "Received: from internal-switch.enterprise.com (10.0.1.5)\n"
        ),
        "body": (
            "Hi team,\n\n"
            "I've updated the slide deck for our Q3 planning session. "
            "Can everyone review slide 5 and add their updates before tomorrow morning?\n\n"
            "Here is the project dashboard: http://internal.enterprise.com/marketing/q3-sync\n\n"
            "Best,\nSarah"
        ),
        "recipient_group": "General Employee",
        "recipient":       "marketing-team@enterprise.com",
    },

    # ── 2. BEC: executive impersonation / gift-card scam ─────────────────
    {
        "type": "bec",
        "sender_name":  "Robert Davis (CEO)",
        "sender_email": "ceo.robert.davis@gmail.com",
        "subject":      "URGENT: Quick Task",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=pass dkim=none dmarc=fail\n"
            "Received: from mail-sourcer.gmail.com (192.0.2.45)\n"
            "Reply-To: executive.office.remotedesk@office-admin-desk.com\n"
        ),
        "body": (
            "Are you at your desk?\n\n"
            "I'm currently tied up in an board meeting and need you to handle an urgent "
            "request immediately. I need you to purchase 10 Apple gift cards worth $100 each "
            "for a client reimbursement. Please send me the clear photos of the codes on the "
            "back of the cards as soon as you get them.\n\n"
            "Do not call me, as I cannot talk right now. Please confirm receipt.\n\n"
            "Thanks,\nRobert Davis\nChief Executive Officer"
        ),
        "recipient_group": "Finance",
        "recipient":       "payroll.officer@enterprise.com",
    },

    # ── 3. Credential harvesting: Microsoft O365 spoofing ────────────────
    {
        "type": "credential_harvesting",
        "sender_name":  "Microsoft Office 365 Security Team",
        "sender_email": "no-reply@security-office365-updates.com",
        "subject":      "ACTION REQUIRED: Unusual Sign-in Detected for Security Alert",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=softfail dkim=none dmarc=none\n"
            "Received: from rogue-relay.unknownhost.net (198.51.100.220)\n"
        ),
        "body": (
            "Microsoft Office 365\n\n"
            "Your account has experienced an unusual sign-in attempt from a new location.\n\n"
            "Location: Moscow, Russia\n"
            "IP Address: 82.102.23.109\n\n"
            "To prevent permanent deletion of your account and suspension of your corporate "
            "email services, you must verify your identity immediately. Failure to verify "
            "within 24 hours will result in complete lockout of your workspace.\n\n"
            "Verify your identity here: http://microsoft.com-update.security-checkpoint.xyz/login.php\n\n"
            "Thank you,\nMicrosoft Security Team"
        ),
        "recipient_group": "Executive",
        "recipient":       "cfo@enterprise.com",
    },

    # ── 4. Generic phishing: DHL / delivery fee scam ─────────────────────
    {
        "type": "generic_phishing",
        "sender_name":  "DHL Express Delivery",
        "sender_email": "dhl-tracking@deliverysupport-hub.net",
        "subject":      "Your package delivery requires immediate action",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=neutral dkim=none dmarc=none\n"
            "Received: from anonymous-node.ru (185.190.140.23)\n"
        ),
        "body": (
            "Dear Customer,\n\n"
            "We were unable to deliver your DHL package today due to incorrect address "
            "information. A small customs clearance fee of $1.50 is outstanding.\n\n"
            "To schedule a redelivery, please update your billing address and complete payment "
            "using the link below within the next 48 hours.\n\n"
            "Update shipping details here: http://dhl-tracking-portal.net-billing-verify.ru/dhl/track\n\n"
            "DHL Express Services Ltd."
        ),
        "recipient_group": "General Employee",
        "recipient":       "developer@enterprise.com",
    },

    # ── 5. Malware delivery: macro-enabled invoice attachment ─────────────
    {
        "type": "malware_delivery",
        "sender_name":  "Accounting Services",
        "sender_email": "billing@external-accounting.org",
        "subject":      "New Invoice Payment Notification - INV-904812",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=fail dkim=none dmarc=fail\n"
            "Received: from accounting-mta.net (203.0.113.88)\n"
        ),
        "body": (
            "Dear Finance,\n\n"
            "Please find attached our invoice INV-904812 for consulting services rendered in Q1.\n\n"
            "Please process the payment immediately as this invoice is already 15 days past due.\n\n"
            "Regards,\nAccounting Team"
        ),
        "attachments": [
            {
                "filename":     "Invoice_Q1_Final_INV904812.xlsm",
                "content_type": "application/vnd.ms-excel.sheet.macroEnabled.12",
            }
        ],
        "recipient_group": "Finance",
        "recipient":       "billing-dept@enterprise.com",
    },

    # ── 6. Benign: HR benefits announcement ──────────────────────────────
    {
        "type": "benign",
        "sender_name":  "HR Department",
        "sender_email": "hr@enterprise.com",
        "subject":      "Quarterly Benefits Update & Open Enrollment",
        "headers":      (
            "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass\n"
            "Received: from mail.enterprise.com (mail.enterprise.com [198.51.100.12])\n"
        ),
        "body": (
            "Hello Everyone,\n\n"
            "It is that time of the year again. Open Enrollment for health and dental "
            "benefits begins next Monday. Please review the updated benefit guidebook "
            "attached and make your selections through the HR Portal.\n\n"
            "Portal Link: http://hr-portal.enterprise.com/benefits/2026\n\n"
            "HR Office"
        ),
        "attachments": [
            {
                "filename":     "Benefits_Enrollment_Guide_2026.pdf",
                "content_type": "application/pdf",
            }
        ],
        "recipient_group": "General Employee",
        "recipient":       "all-hands@enterprise.com",
    },
]


# ── Base64 stubs for attachment content ──────────────────────────────────────
_STUB_XLSM = "UEsDBBQAAAAIAIi1M1YAAAAAAAAAAAAAAAAGABwAdGVzdC50eHRVVAkAAzhNf2U4TX9ldXgL"
_STUB_PDF  = "JVBERi0xLjQKJcfsj6IKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIK"


class MockEmailGenerator:

    @staticmethod
    def construct_rfc2822(template: Dict[str, Any], date_str: str) -> str:
        """
        Creates a raw RFC 2822 email string from a template dictionary.

        For templates that include attachments the method builds a
        multipart/mixed MIME message with a text/plain body part and one
        attachment part per attachment descriptor in ``template["attachments"]``.
        """
        custom_headers = template.get("headers",
                                      "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass")

        # Standard envelope headers
        lines = [
            custom_headers.rstrip("\n"),
            f'From: "{template["sender_name"]}" <{template["sender_email"]}>',
            f'To: <{template["recipient"]}>',
            f'Subject: {template["subject"]}',
            f'Date: {date_str}',
            f'Message-ID: <{random.randint(100000, 999999)}.alert-pds@enterprise.com>',
        ]

        attachments = template.get("attachments", [])

        if attachments:
            # Build a multipart/mixed MIME message
            boundary = "----=_Part_Boundary_PDS"
            lines.append("MIME-Version: 1.0")
            lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
            lines.append("")
            lines.append(f"--{boundary}")
            lines.append("Content-Type: text/plain; charset=UTF-8")
            lines.append("Content-Transfer-Encoding: 7bit")
            lines.append("")
            lines.append(template["body"])

            for att in attachments:
                lines.append(f"--{boundary}")
                lines.append(f'Content-Type: {att["content_type"]}; name="{att["filename"]}"')
                lines.append(f'Content-Disposition: attachment; filename="{att["filename"]}"')
                lines.append("Content-Transfer-Encoding: base64")
                lines.append("")
                # Use a minimal valid stub for the attachment payload
                stub = _STUB_XLSM if att["filename"].endswith(".xlsm") else _STUB_PDF
                lines.append(stub)

            lines.append(f"--{boundary}--")
        else:
            # Simple single-part text message
            lines.append("")
            lines.append(template["body"])

        return "\n".join(lines)

    @classmethod
    def generate_alerts_database(cls, count: int = 30) -> List[Dict[str, Any]]:
        """
        Generates structured alert records, processes them through our scoring pipeline,
        and saves them to database format.

        Each alert is run through the full APDS pipeline:
          EmailParser → NLPAnalyzer → URLScorer → FusionEngine

        The analyst_action and analyst_notes fields are seeded with a mix of
        realistic outcomes to make the demo dashboard look credible.
        """
        CAMPAIGN_MAP = {
            "bec":                  "camp_bec_wire_01",
            "credential_harvesting": "camp_m365_harvest_02",
            "generic_phishing":     "camp_dhl_delivery_03",
        }
        CAMPAIGN_NAMES = {
            "camp_bec_wire_01":      "Executive Impersonation (Wire Transfer)",
            "camp_m365_harvest_02":  "Office 365 Credential Harvesting (Moscow IP)",
            "camp_dhl_delivery_03":  "DHL / FedEx Customs Delivery Scam",
        }

        base_time = datetime.utcnow()
        alerts:    List[Dict[str, Any]] = []

        for i in range(count):
            template = TEMPLATES[i % len(TEMPLATES)]
            offset   = timedelta(hours=i * 3, minutes=random.randint(0, 59))
            ts       = base_time - offset
            date_str = ts.strftime("%a, %d %b %Y %H:%M:%S +0000")

            raw_email = cls.construct_rfc2822(template, date_str)

            # Run through the full APDS pipeline
            parsed   = EmailParser.parse_raw_email(raw_email)
            body_text = parsed.get("body_text", "")
            urls      = parsed.get("urls", [])

            nlp_res  = NLPAnalyzer.analyze_text(body_text)
            url_res  = URLScorer.evaluate_urls(urls)
            fusion   = FusionEngine.fuse_verdict(parsed, nlp_res, url_res)

            verdict    = fusion.get("verdict", "benign")
            category   = fusion.get("threat_category", "benign")
            confidence = fusion.get("confidence_score", 0.0)

            # Simulate a realistic analyst review workflow
            if verdict == "phishing" and confidence > 0.95:
                analyst_action = random.choice(["confirmed", "confirmed", "overridden_benign"])
                analyst_notes  = ("Confirmed phishing threat vector."
                                  if analyst_action == "confirmed"
                                  else "False positive: verified internal vendor.")
            elif verdict == "suspicious" and confidence > 0.6:
                analyst_action = random.choice(["confirmed", "pending", "overridden_benign"])
                analyst_notes  = ("Investigated and confirmed."
                                  if analyst_action == "confirmed"
                                  else ("Marked benign after verification."
                                        if analyst_action == "overridden_benign" else ""))
            elif verdict == "benign":
                analyst_action = random.choices(
                    ["pending", "overridden_phishing", "confirmed"],
                    weights=[0.05, 0.02, 0.93]
                )[0]
                analyst_notes  = ""
            else:
                analyst_action = "pending"
                analyst_notes  = ""

            campaign_id = CAMPAIGN_MAP.get(category) if category != "benign" else None

            alert_id = f"alert_{1000 + i}"

            alert: Dict[str, Any] = {
                "id":               alert_id,
                "timestamp":        ts.isoformat(),
                "sender":           f'"{template["sender_name"]}" <{template["sender_email"]}>',
                "recipient":        template["recipient"],
                "recipient_group":  template["recipient_group"],
                "subject":          template["subject"],
                "verdict":          verdict,
                "threat_category":  category,
                "confidence_score": confidence,
                "raw_email":        raw_email,
                "parsed_details":   parsed,
                "nlp_analysis":     nlp_res,
                "url_analysis":     url_res,
                "fusion_result":    fusion,
                "analyst_action":   analyst_action,
                "analyst_notes":    analyst_notes,
                "campaign_id":      campaign_id,
            }
            alerts.append(alert)

        # Sort newest-first, matching the expected dashboard sort order
        alerts.sort(key=lambda a: a["timestamp"], reverse=True)
        return alerts

    @classmethod
    def seed_database_file(cls, filepath: str, count: int = 30) -> None:
        """
        Seeds the JSON alert database file if it does not exist.
        """
        if not os.path.exists(filepath):
            alerts = cls.generate_alerts_database(count)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=2, default=str)
            print(f"Seeded mock database with {len(alerts)} alerts at {filepath}")
        else:
            print(f"Database already exists at {filepath}")


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(__file__), "alerts_db.json")
    MockEmailGenerator.seed_database_file(db_path, count=30)
