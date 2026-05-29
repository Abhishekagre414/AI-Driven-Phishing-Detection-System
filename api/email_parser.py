import email
from email import policy
import re
from bs4 import BeautifulSoup
from typing import Dict, List, Any

# Regex to capture URLs
URL_REGEX = re.compile(
    r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE
)

# Common high-risk attachment extensions
HIGH_RISK_EXTS = {
    ".exe", ".scr", ".lnk", ".vbs", ".js", ".bat", ".cmd", ".ps1",
    ".docm", ".xlsm", ".pptm", ".dotm", ".doc", ".xls", ".jar", ".zip", ".rar"
}

class EmailParser:
    @staticmethod
    def parse_raw_email(raw_content: str) -> Dict[str, Any]:
        """
        Parses a raw RFC 2822 email string.
        Extracts headers, authentication status, hop count, body text,
        embedded URLs, and attachment metadata.
        """
        try:
            msg = email.message_from_string(raw_content, policy=policy.default)
        except Exception as e:
            return {
                "error": f"Failed to parse RFC 2822 structure: {str(e)}",
                "parsed": False
            }

        headers = {}
        for header_name in msg.keys():
            headers[header_name.lower()] = msg[header_name]

        # Extract basic headers
        subject = msg.get("Subject", "")
        from_header = msg.get("From", "")
        to_header = msg.get("To", "")
        reply_to = msg.get("Reply-To", "")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")

        # Display name spoofing analysis
        display_name = ""
        actual_email = ""
        from_match = re.match(r'^(.*?)\s*<(.*?)>$', from_header)
        if from_match:
            display_name = from_match.group(1).strip(' \'"')
            actual_email = from_match.group(2).strip()
        else:
            actual_email = from_header.strip()

        # Parse authentication headers (Authentication-Results, Received-SPF)
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"

        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")

        # Look in Authentication-Results
        if auth_results:
            auth_lower = auth_results.lower()
            if "spf=" in auth_lower:
                spf_match = re.search(r'spf=(\w+)', auth_lower)
                if spf_match:
                    spf_status = spf_match.group(1)
            if "dkim=" in auth_lower:
                dkim_match = re.search(r'dkim=(\w+)', auth_lower)
                if dkim_match:
                    dkim_status = dkim_match.group(1)
            if "dmarc=" in auth_lower:
                dmarc_match = re.search(r'dmarc=(\w+)', auth_lower)
                if dmarc_match:
                    dmarc_status = dmarc_match.group(1)

        # Fallback to Received-SPF
        if spf_status == "none" and received_spf:
            rec_spf_lower = received_spf.lower()
            for status in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
                if status in rec_spf_lower:
                    spf_status = status
                    break

        # Hop count check (number of Received headers)
        received_headers = msg.get_all("Received", [])
        hop_count = len(received_headers)

        # Check Reply-To mismatch
        reply_to_mismatch = False
        if reply_to:
            reply_email = reply_to
            reply_match = re.match(r'^.*<(.*?)>$', reply_to)
            if reply_match:
                reply_email = reply_match.group(1).strip()
            
            # Compare domains
            from_domain = actual_email.split("@")[-1].lower() if "@" in actual_email else ""
            reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                reply_to_mismatch = True

        # Extract body text and attachments
        body_text = ""
        html_body = ""
        attachments = []
        urls = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get_content_disposition()

                # Attachment detection
                if content_disposition == "attachment" or part.get_filename():
                    filename = part.get_filename() or "unnamed_attachment"
                    try:
                        content = part.get_payload(decode=True) or b""
                        size = len(content)
                    except Exception:
                        size = 0
                    
                    lower_fn = filename.lower()
                    has_macros = False
                    is_high_risk = any(lower_fn.endswith(ext) for ext in HIGH_RISK_EXTS)
                    
                    if lower_fn.endswith((".xlsm", ".docm", ".pptm", ".dotm")):
                        has_macros = True

                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": size,
                        "is_high_risk": is_high_risk,
                        "has_macros": has_macros
                    })
                else:
                    # Text payload
                    if content_type == "text/plain":
                        try:
                            body_text += part.get_payload(decode=True).decode(errors="ignore")
                        except Exception:
                            pass
                    elif content_type == "text/html":
                        try:
                            html_body += part.get_payload(decode=True).decode(errors="ignore")
                        except Exception:
                            pass
        else:
            # Single part message
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True).decode(errors="ignore")
                if content_type == "text/html":
                    html_body = payload
                else:
                    body_text = payload
            except Exception:
                pass

        # If there's html and no plain text, extract plain text from html
        cleaned_html_text = ""
        if html_body:
            soup = BeautifulSoup(html_body, "html.parser")
            cleaned_html_text = soup.get_text(separator=" ")
            if not body_text.strip():
                body_text = cleaned_html_text

            # Extract URLs from href attributes in HTML
            for a in soup.find_all("a", href=True):
                url = a["href"].strip()
                if url and not url.startswith(("mailto:", "tel:", "#")):
                    urls.append(url)

        # Regex URL extraction from body text
        text_urls = URL_REGEX.findall(body_text)
        urls.extend(text_urls)
        
        # De-duplicate URLs while preserving order
        seen = set()
        dedup_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                dedup_urls.append(url)

        return {
            "parsed": True,
            "subject": subject,
            "from": from_header,
            "from_display_name": display_name,
            "from_email": actual_email,
            "to": to_header,
            "reply_to": reply_to,
            "reply_to_mismatch": reply_to_mismatch,
            "date": date_str,
            "message_id": message_id,
            "hop_count": hop_count,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "body_text": body_text.strip(),
            "urls": dedup_urls,
            "attachments": attachments
        }
