export const mockAlerts = [
  {
    "id": "alert_1001",
    "timestamp": "2026-06-07T12:00:00.000Z",
    "sender": "Microsoft Office 365 Support <no-reply@security-office365-updates.com>",
    "recipient": "cfo@enterprise.com",
    "recipient_group": "Executive",
    "subject": "ACTION REQUIRED: Unusual Sign-in Detected for Security Alert",
    "verdict": "phishing",
    "threat_category": "credential_harvesting",
    "confidence_score": 1.0,
    "raw_email": "Authentication-Results: mx.google.com; spf=softfail dkim=none dmarc=none\nFrom: \"Microsoft Office 365 Support\" <no-reply@security-office365-updates.com>\nTo: <cfo@enterprise.com>\nSubject: ACTION REQUIRED: Unusual Sign-in Detected for Security Alert\nDate: Sat, 23 May 2026 15:20:00 +0000\n\nYour Microsoft Office 365 account has experienced an unusual sign-in attempt from Russia.\nTo prevent lockout and permanent deletion of your account, you must verify your identity immediately.\nPlease update your password here: http://microsoft.com-update.security-checkpoint.xyz/login.php\n\nMicrosoft Security Team",
    "parsed_details": {
      "parsed": true,
      "subject": "ACTION REQUIRED: Unusual Sign-in Detected for Security Alert",
      "from": "Microsoft Office 365 Support <no-reply@security-office365-updates.com>",
      "from_display_name": "Microsoft Office 365 Support",
      "from_email": "no-reply@security-office365-updates.com",
      "to": "cfo@enterprise.com",
      "reply_to": "",
      "reply_to_mismatch": false,
      "date": "Sat, 23 May 2026 15:20:00 +0000",
      "message_id": "",
      "hop_count": 0,
      "spf_status": "softfail",
      "dkim_status": "none",
      "dmarc_status": "none",
      "body_text": "Your Microsoft Office 365 account has experienced an unusual sign-in attempt from Russia.\nTo prevent lockout and permanent deletion of your account, you must verify your identity immediately.\nPlease update your password here: http://microsoft.com-update.security-checkpoint.xyz/login.php\n\nMicrosoft Security Team",
      "urls": [
        "http://microsoft.com-update.security-checkpoint.xyz/login.php"
      ],
      "attachments": []
    },
    "nlp_analysis": {
      "score": 0.706,
      "intent": "credential_harvesting",
      "categories": {
        "credential_harvesting": 0.417,
        "bec": 0.0,
        "generic_phishing": 0.0
      },
      "linguistic_signals": [
        {
          "signal": "credential_harvesting_intent",
          "weight": 0.417
        }
      ]
    },
    "url_analysis": {
      "max_score": 1.0,
      "average_score": 1.0,
      "details": [
        {
          "url": "http://microsoft.com-update.security-checkpoint.xyz/login.php",
          "domain": "security-checkpoint.xyz",
          "score": 1.0,
          "indicators": [
            "spoofing_microsoft_lookalike",
            "hyphenated_domain",
            "redirect_shortener_used"
          ],
          "ssl_valid": true,
          "domain_age_days": 450
        }
      ]
    },
    "fusion_result": {
      "verdict": "phishing",
      "threat_category": "credential_harvesting",
      "confidence_score": 1.0,
      "base_value": 0.1,
      "shap_contributions": {
        "SPF Authentication Fail": 0.12,
        "DKIM Missing Signature": 0.08,
        "DMARC Policy Missing": 0.12,
        "Display Name Impersonation": 0.25,
        "Semantic Body Threat Cues": 0.353,
        "Embedded Links Risk Score": 0.4
      },
      "explanations": [
        "SPF record verification returned softfail",
        "Sender name 'Microsoft Office 365 Support' mimics authority but uses external domain 'security-office365-updates.com'",
        "Body semantics contain credential harvesting request indicators",
        "Contains link typosquatting mimicking a trusted domain: security-checkpoint.xyz",
        "Redirect or URL shortener link detected to bypass inspection"
      ]
    },
    "analyst_action": "pending",
    "analyst_notes": "",
    "campaign_id": "camp_m365_harvest_02"
  },
  {
    "id": "alert_1002",
    "timestamp": "2026-06-07T11:30:00.000Z",
    "sender": "Robert Davis (CEO) <ceo.robert.davis@gmail.com>",
    "recipient": "payroll.officer@enterprise.com",
    "recipient_group": "Finance",
    "subject": "URGENT: Quick Task",
    "verdict": "phishing",
    "threat_category": "bec",
    "confidence_score": 0.95,
    "raw_email": "Authentication-Results: mx.google.com; spf=pass dkim=none dmarc=fail\nReceived: from mail-sourcer.gmail.com (192.0.2.45)\nReply-To: executive.office.remotedesk@office-admin-desk.com\nFrom: \"Robert Davis (CEO)\" <ceo.robert.davis@gmail.com>\nTo: <payroll.officer@enterprise.com>\nSubject: URGENT: Quick Task\nDate: Sat, 23 May 2026 02:27:34 +0000\n\nAre you at your desk?\n\nI'm currently tied up in an board meeting and need you to handle an urgent request immediately. I need you to purchase 10 Apple gift cards worth $100 each for a client reimbursement. Please send me the clear photos of the codes on the back of the cards.\n\nThanks,\nRobert Davis\nChief Executive Officer",
    "parsed_details": {
      "parsed": true,
      "subject": "URGENT: Quick Task",
      "from": "Robert Davis (CEO) <ceo.robert.davis@gmail.com>",
      "from_display_name": "Robert Davis (CEO)",
      "from_email": "ceo.robert.davis@gmail.com",
      "to": "payroll.officer@enterprise.com",
      "reply_to": "executive.office.remotedesk@office-admin-desk.com",
      "reply_to_mismatch": true,
      "date": "Sat, 23 May 2026 02:27:34 +0000",
      "message_id": "",
      "hop_count": 1,
      "spf_status": "pass",
      "dkim_status": "none",
      "dmarc_status": "fail",
      "body_text": "Are you at your desk?\n\nI'm currently tied up in an board meeting and need you to handle an urgent request immediately. I need you to purchase 10 Apple gift cards worth $100 each for a client reimbursement. Please send me the clear photos of the codes on the back of the cards.\n\nThanks,\nRobert Davis\nChief Executive Officer",
      "urls": [],
      "attachments": []
    },
    "nlp_analysis": {
      "score": 0.88,
      "intent": "bec",
      "categories": {
        "credential_harvesting": 0.0,
        "bec": 0.667,
        "generic_phishing": 0.0
      },
      "linguistic_signals": [
        {
          "signal": "bec_financial_intent",
          "weight": 0.667
        },
        {
          "signal": "urgency_coercion_cues",
          "weight": 0.75
        }
      ]
    },
    "url_analysis": {
      "max_score": 0.0,
      "average_score": 0.0,
      "details": []
    },
    "fusion_result": {
      "verdict": "phishing",
      "threat_category": "bec",
      "confidence_score": 0.95,
      "base_value": 0.1,
      "shap_contributions": {
        "DMARC Policy Fail": 0.35,
        "SPF Check Passed": -0.08,
        "DKIM Missing Signature": 0.08,
        "Reply-To Domain Mismatch": 0.30,
        "Semantic Body Threat Cues": 0.30
      },
      "explanations": [
        "DMARC alignment checks failed (spoofing indicator)",
        "Reply-to field does not match the sender domain (ceo.robert.davis@gmail.com)",
        "Linguistic patterns match executive financial manipulation / BEC template"
      ]
    },
    "analyst_action": "pending",
    "analyst_notes": "",
    "campaign_id": "camp_bec_wire_01"
  },
  {
    "id": "alert_1003",
    "timestamp": "2026-06-07T10:15:00.000Z",
    "sender": "DHL Express Delivery <dhl-tracking@deliverysupport-hub.net>",
    "recipient": "developer@enterprise.com",
    "recipient_group": "General Employee",
    "subject": "Your package delivery requires immediate action",
    "verdict": "phishing",
    "threat_category": "generic_phishing",
    "confidence_score": 0.85,
    "raw_email": "Authentication-Results: mx.google.com; spf=neutral dkim=none dmarc=none\nReceived: from anonymous-node.ru (185.190.140.23)\nFrom: \"DHL Express Delivery\" <dhl-tracking@deliverysupport-hub.net>\nTo: <developer@enterprise.com>\nSubject: Your package delivery requires immediate action\nDate: Sat, 23 May 2026 10:15:00 +0000\n\nDear Customer,\n\nWe were unable to deliver your DHL package today due to incorrect address information. A small customs clearance fee of $1.50 is outstanding.\n\nTo schedule a redelivery, please update your billing address and complete payment using the link below within the next 48 hours.\n\nUpdate shipping details here: http://dhl-tracking-portal.net-billing-verify.ru/dhl/track\n\nDHL Express Services Ltd.",
    "parsed_details": {
      "parsed": true,
      "subject": "Your package delivery requires immediate action",
      "from": "DHL Express Delivery <dhl-tracking@deliverysupport-hub.net>",
      "from_display_name": "DHL Express Delivery",
      "from_email": "dhl-tracking@deliverysupport-hub.net",
      "to": "developer@enterprise.com",
      "reply_to": "",
      "reply_to_mismatch": false,
      "date": "Sat, 23 May 2026 10:15:00 +0000",
      "message_id": "",
      "hop_count": 1,
      "spf_status": "neutral",
      "dkim_status": "none",
      "dmarc_status": "none",
      "body_text": "Dear Customer,\n\nWe were unable to deliver your DHL package today due to incorrect address information. A small customs clearance fee of $1.50 is outstanding.\n\nTo schedule a redelivery, please update your billing address and complete payment using the link below within the next 48 hours.\n\nUpdate shipping details here: http://dhl-tracking-portal.net-billing-verify.ru/dhl/track\n\nDHL Express Services Ltd.",
      "urls": [
        "http://dhl-tracking-portal.net-billing-verify.ru/dhl/track"
      ],
      "attachments": []
    },
    "nlp_analysis": {
      "score": 0.64,
      "intent": "generic_phishing",
      "categories": {
        "credential_harvesting": 0.0,
        "bec": 0.0,
        "generic_phishing": 0.5
      },
      "linguistic_signals": [
        {
          "signal": "lure_phishing_cues",
          "weight": 0.5
        },
        {
          "signal": "urgency_coercion_cues",
          "weight": 0.4
        }
      ]
    },
    "url_analysis": {
      "max_score": 0.85,
      "average_score": 0.85,
      "details": [
        {
          "url": "http://dhl-tracking-portal.net-billing-verify.ru/dhl/track",
          "domain": "net-billing-verify.ru",
          "score": 0.85,
          "indicators": [
            "hyphenated_domain",
            "spoofing_dhl_lookalike"
          ],
          "ssl_valid": false,
          "domain_age_days": 15
        }
      ]
    },
    "fusion_result": {
      "verdict": "phishing",
      "threat_category": "generic_phishing",
      "confidence_score": 0.85,
      "base_value": 0.1,
      "shap_contributions": {
        "SPF Authentication Fail": 0.12,
        "DKIM Missing Signature": 0.08,
        "DMARC Policy Missing": 0.12,
        "Display Name Impersonation": 0.25,
        "Semantic Body Threat Cues": 0.25,
        "Embedded Links Risk Score": 0.34
      },
      "explanations": [
        "SPF record verification returned neutral",
        "Body text contains urgency language and link coercion cues",
        "Contains link typosquatting mimicking a trusted domain: net-billing-verify.ru",
        "Embedded link domain 'net-billing-verify.ru' lacks valid SSL certificate"
      ]
    },
    "analyst_action": "pending",
    "analyst_notes": "",
    "campaign_id": "camp_dhl_delivery_03"
  },
  {
    "id": "alert_1004",
    "timestamp": "2026-06-07T09:00:00.000Z",
    "sender": "Accounting Services <billing@external-accounting.org>",
    "recipient": "billing-dept@enterprise.com",
    "recipient_group": "Finance",
    "subject": "New Invoice Payment Notification - INV-904812",
    "verdict": "phishing",
    "threat_category": "malware_delivery",
    "confidence_score": 0.90,
    "raw_email": "Authentication-Results: mx.google.com; spf=fail dkim=none dmarc=fail\nReceived: from accounting-mta.net (203.0.113.88)\nFrom: \"Accounting Services\" <billing@external-accounting.org>\nTo: <billing-dept@enterprise.com>\nSubject: New Invoice Payment Notification - INV-904812\nDate: Sat, 23 May 2026 09:00:00 +0000\n\nDear Finance,\n\nPlease find attached our invoice INV-904812 for consulting services rendered in Q1.\n\nPlease process the payment immediately as this invoice is already 15 days past due.\n\nRegards,\nAccounting Team",
    "parsed_details": {
      "parsed": true,
      "subject": "New Invoice Payment Notification - INV-904812",
      "from": "Accounting Services <billing@external-accounting.org>",
      "from_display_name": "Accounting Services",
      "from_email": "billing@external-accounting.org",
      "to": "billing-dept@enterprise.com",
      "reply_to": "",
      "reply_to_mismatch": false,
      "date": "Sat, 23 May 2026 09:00:00 +0000",
      "message_id": "",
      "hop_count": 1,
      "spf_status": "fail",
      "dkim_status": "none",
      "dmarc_status": "fail",
      "body_text": "Dear Finance,\n\nPlease find attached our invoice INV-904812 for consulting services rendered in Q1.\n\nPlease process the payment immediately as this invoice is already 15 days past due.\n\nRegards,\nAccounting Team",
      "urls": [],
      "attachments": [
        {
          "filename": "Invoice_Q1_Final_INV904812.xlsm",
          "content_type": "application/vnd.ms-excel.sheet.macroEnabled.12",
          "size_bytes": 10240,
          "is_high_risk": true,
          "has_macros": true
        }
      ]
    },
    "nlp_analysis": {
      "score": 0.45,
      "intent": "generic_phishing",
      "categories": {
        "credential_harvesting": 0.0,
        "bec": 0.0,
        "generic_phishing": 0.2
      },
      "linguistic_signals": [
        {
          "signal": "urgency_coercion_cues",
          "weight": 0.3
        }
      ]
    },
    "url_analysis": {
      "max_score": 0.0,
      "average_score": 0.0,
      "details": []
    },
    "fusion_result": {
      "verdict": "phishing",
      "threat_category": "malware_delivery",
      "confidence_score": 0.90,
      "base_value": 0.1,
      "shap_contributions": {
        "SPF Authentication Fail": 0.25,
        "DKIM Missing Signature": 0.08,
        "DMARC Policy Fail": 0.35,
        "Dangerous Attachments Signal": 0.70
      },
      "explanations": [
        "SPF Authentication Fail",
        "DKIM cryptographic signature check failed",
        "DMARC alignment checks failed (spoofing indicator)",
        "High-risk attachment format detected: 'Invoice_Q1_Final_INV904812.xlsm'",
        "Office document containing macro script: 'Invoice_Q1_Final_INV904812.xlsm'"
      ]
    },
    "analyst_action": "confirmed",
    "analyst_notes": "Verified fake invoice containing macro script.",
    "campaign_id": null
  },
  {
    "id": "alert_1005",
    "timestamp": "2026-06-07T08:30:00.000Z",
    "sender": "Sarah Jenkins <sjenkins@enterprise.com>",
    "recipient": "marketing-team@enterprise.com",
    "recipient_group": "General Employee",
    "subject": "Q3 Marketing Strategy Sync",
    "verdict": "benign",
    "threat_category": "benign",
    "confidence_score": 0.0,
    "raw_email": "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass\nFrom: \"Sarah Jenkins\" <sjenkins@enterprise.com>\nTo: <marketing-team@enterprise.com>\nSubject: Q3 Marketing Strategy Sync\nDate: Fri, 22 May 2026 19:27:34 +0000\n\nHi team,\n\nI've updated the slide deck for our Q3 planning session.\nHere is the project dashboard: http://internal.enterprise.com/marketing/q3-sync\n\nBest,\nSarah",
    "parsed_details": {
      "parsed": true,
      "subject": "Q3 Marketing Strategy Sync",
      "from": "Sarah Jenkins <sjenkins@enterprise.com>",
      "from_display_name": "Sarah Jenkins",
      "from_email": "sjenkins@enterprise.com",
      "to": "marketing-team@enterprise.com",
      "reply_to": "",
      "reply_to_mismatch": false,
      "date": "Fri, 22 May 2026 19:27:34 +0000",
      "message_id": "",
      "hop_count": 0,
      "spf_status": "pass",
      "dkim_status": "pass",
      "dmarc_status": "pass",
      "body_text": "Hi team,\n\nI've updated the slide deck for our Q3 planning session.\nHere is the project dashboard: http://internal.enterprise.com/marketing/q3-sync\n\nBest,\nSarah",
      "urls": [
        "http://internal.enterprise.com/marketing/q3-sync"
      ],
      "attachments": []
    },
    "nlp_analysis": {
      "score": 0.0,
      "intent": "benign",
      "categories": {
        "credential_harvesting": 0.0,
        "bec": 0.0,
        "generic_phishing": 0.0
      },
      "linguistic_signals": []
    },
    "url_analysis": {
      "max_score": 0.0,
      "average_score": 0.0,
      "details": [
        {
          "url": "http://internal.enterprise.com/marketing/q3-sync",
          "domain": "enterprise.com",
          "score": 0.0,
          "indicators": [],
          "ssl_valid": true,
          "domain_age_days": 450
        }
      ]
    },
    "fusion_result": {
      "verdict": "benign",
      "threat_category": "benign",
      "confidence_score": 0.0,
      "base_value": 0.1,
      "shap_contributions": {
        "SPF Check Passed": -0.08,
        "DKIM Signature Valid": -0.06,
        "DMARC Policy Pass": -0.1
      },
      "explanations": [
        "No suspicious headers, language patterns, or URL risks detected."
      ]
    },
    "analyst_action": "confirmed",
    "analyst_notes": "",
    "campaign_id": null
  },
  {
    "id": "alert_1006",
    "timestamp": "2026-06-07T07:45:00.000Z",
    "sender": "External IT Support <helpdesk@corporate-services-portal.com>",
    "recipient": "developer2@enterprise.com",
    "recipient_group": "General Employee",
    "subject": "Action Required: System Upgrade Complete",
    "verdict": "suspicious",
    "threat_category": "generic_phishing",
    "confidence_score": 0.58,
    "raw_email": "Authentication-Results: mx.google.com; spf=pass dkim=none dmarc=none\nFrom: \"External IT Support\" <helpdesk@corporate-services-portal.com>\nTo: <developer2@enterprise.com>\nSubject: Action Required: System Upgrade Complete\nDate: Sat, 23 May 2026 07:45:00 +0000\n\nDear team,\n\nOur system upgrade is complete. To resume remote work access, you are required to verify your profile details.\n\nPlease click here: http://corporate-services-portal.com-verify.info/login\n\nIT Helpdesk",
    "parsed_details": {
      "parsed": true,
      "subject": "Action Required: System Upgrade Complete",
      "from": "External IT Support <helpdesk@corporate-services-portal.com>",
      "from_display_name": "External IT Support",
      "from_email": "helpdesk@corporate-services-portal.com",
      "to": "developer2@enterprise.com",
      "reply_to": "",
      "reply_to_mismatch": false,
      "date": "Sat, 23 May 2026 07:45:00 +0000",
      "message_id": "",
      "hop_count": 1,
      "spf_status": "pass",
      "dkim_status": "none",
      "dmarc_status": "none",
      "body_text": "Dear team,\n\nOur system upgrade is complete. To resume remote work access, you are required to verify your profile details.\n\nPlease click here: http://corporate-services-portal.com-verify.info/login\n\nIT Helpdesk",
      "urls": [
        "http://corporate-services-portal.com-verify.info/login"
      ],
      "attachments": []
    },
    "nlp_analysis": {
      "score": 0.45,
      "intent": "generic_phishing",
      "categories": {
        "credential_harvesting": 0.0,
        "bec": 0.0,
        "generic_phishing": 0.3
      },
      "linguistic_signals": [
        {
          "signal": "urgency_coercion_cues",
          "weight": 0.3
        }
      ]
    },
    "url_analysis": {
      "max_score": 0.45,
      "average_score": 0.45,
      "details": [
        {
          "url": "http://corporate-services-portal.com-verify.info/login",
          "domain": "com-verify.info",
          "score": 0.45,
          "indicators": [
            "hyphenated_domain"
          ],
          "ssl_valid": false,
          "domain_age_days": 5
        }
      ]
    },
    "fusion_result": {
      "verdict": "suspicious",
      "threat_category": "generic_phishing",
      "confidence_score": 0.58,
      "base_value": 0.1,
      "shap_contributions": {
        "SPF Check Passed": -0.08,
        "DKIM Missing Signature": 0.08,
        "DMARC Policy Missing": 0.12,
        "Semantic Body Threat Cues": 0.15,
        "Embedded Links Risk Score": 0.18,
        "Display Name Impersonation": 0.13
      },
      "explanations": [
        "DKIM Missing Signature",
        "DMARC Policy Missing",
        "Body text contains urgency language and link coercion cues",
        "Embedded link domain 'com-verify.info' lacks valid SSL certificate"
      ]
    },
    "analyst_action": "pending",
    "analyst_notes": "",
    "campaign_id": null
  }
];
