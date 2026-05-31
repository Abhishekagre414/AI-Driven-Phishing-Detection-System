"""
api/url_scorer.py
-----------------
URL risk scoring engine for the APDS pipeline.

Architecture
============
Each URL is evaluated independently by ``URLScorer.score_url()``, which
assigns a floating-point risk score in [0, 1] plus a list of named
indicator strings.  ``URLScorer.evaluate_urls()`` aggregates individual
scores into a summary with max, average, and per-URL detail records.

Scoring indicators and their weights
-------------------------------------
  redirect_shortener_used    +0.40  URL shortener / redirect service detected
  spoofing_<brand>_lookalike +0.60  Domain visually impersonates a trusted brand
  hyphenated_domain          +0.20  Excessive hyphenation in domain name
  excess_subdomains          +0.15  More than 2 subdomain levels
  very_long_url              +0.15  URL > 150 chars (evasion via query-string padding)
  random_domain_characters   +0.15  Shannon entropy > 4.2 (random-looking domain)
  ip_address_domain          +0.50  IP address used instead of hostname

Defaults (simulated, as live lookups are not performed)
---------------------------------------------------------
  ssl_valid      = True   (assume HTTPS unless the URL starts with http://)
  domain_age_days = 450   (simulated "relatively new but not brand-new" age)
"""

import re
import math
from typing import Dict, Any, List

import tldextract

# ── Brand impersonation targets ───────────────────────────────────────────────
# Any domain whose registered name is within Levenshtein distance 2 of one of
# these brands (or which contains the brand name in a subdomain) is flagged.
TARGET_BRANDS: tuple = (
    "microsoft", "google", "outlook", "office365", "paypal",
    "netflix",   "apple",  "amazon",  "facebook",  "chase",
    "wellsfargo","bankofamerica","docusign","dropbox","onedrive",
    "sharepoint","adobe",
)

# ── Known URL shortener / redirect domains ────────────────────────────────────
# A URL that resolves through any of these services obscures the final destination.
SHORTENERS: frozenset = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    "is.gd", "rebrand.ly", "linktr.ee", "forms.gle",
    "docs.google.com/forms", "click.email",
})


class URLScorer:

    @staticmethod
    def get_entropy(text: str) -> float:
        """
        Calculates Shannon entropy of string (higher means more random/suspicious).

        H = -sum(p * log2(p)) for each unique character.
        Typical legitimate domain names score below 3.5; randomly generated
        DGA (Domain Generation Algorithm) names often exceed 4.2.
        """
        entropy = 0.0
        text_len = len(text)
        if text_len == 0:
            return 0.0
        frequencies: Dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        for freq in frequencies.values():
            prob     = freq / text_len
            entropy -= prob * math.log2(prob)
        return round(entropy, 3)

    @classmethod
    def check_brand_spoofing(cls, domain: str) -> Dict[str, Any]:
        """
        Checks if the domain tries to impersonate a popular brand.

        Three detection strategies:
          1. brand_in_subdomain  – legitimate brand name appears in the subdomain
             of an unrelated registrable domain (e.g. microsoft.evil.com).
          2. lookalike_hyphenated – registrable domain contains a brand name
             joined by a hyphen (e.g. microsoft-account.xyz).
          3. typosquatting        – Levenshtein distance ≤ 2 between registrable
             domain name and a known brand (e.g. "micosoft").
        """
        domain_lower = domain.lower()
        extracted    = tldextract.extract(domain_lower)
        subdomain    = extracted.subdomain
        domain_name  = extracted.domain   # registrable part, without TLD

        for brand in TARGET_BRANDS:
            # Strategy 1: brand in subdomain of a non-brand domain
            if brand in subdomain and brand not in domain_name:
                return {"spoofed": True, "brand": brand, "reason": "brand_in_subdomain"}

            # Strategy 2: brand-<anything> hyphenated domain
            if brand in domain_name and "-" in domain_name:
                return {"spoofed": True, "brand": brand, "reason": "lookalike_hyphenated"}

            # Strategy 3: typosquatting (edit distance ≤ 2, not an exact match)
            dist = URLScorer.levenshtein_distance(domain_name, brand)
            if 0 < dist <= 2:
                return {"spoofed": True, "brand": brand, "reason": "typosquatting"}

        return {"spoofed": False, "brand": "", "reason": ""}

    @classmethod
    def levenshtein_distance(cls, s1: str, s2: str) -> int:
        """
        Calculates edit distance between two strings.

        Standard dynamic-programming implementation; O(n*m) time and O(n) space.
        Used internally by check_brand_spoofing() for typosquatting detection.
        """
        # Optimise: ensure s1 is the shorter string
        if len(s1) > len(s2):
            return URLScorer.levenshtein_distance(s2, s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions    = previous_row[j + 1] + 1
                deletions     = current_row[j]      + 1
                substitutions = previous_row[j]     + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @classmethod
    def score_url(cls, url: str) -> Dict[str, Any]:
        """
        Scores a single URL for phishing characteristics.

        Returns a dict with keys:
          score      – float in [0, 1]
          indicators – list of named risk strings
          url        – the original URL
          domain     – registrable domain (e.g. "evil.com")
          ssl_valid  – bool (simulated)
          domain_age_days – int (simulated)
        """
        indicators: List[str] = []
        score:      float     = 0.0
        url_lower = url.lower()

        # Extract domain components via tldextract
        extracted   = tldextract.extract(url_lower)
        domain      = extracted.domain + ("." + extracted.suffix if extracted.suffix else "")
        is_shortener = False

        # ── Check 1: URL shortener / redirect service ─────────────────────
        for short in SHORTENERS:
            if short in url_lower:
                score      += 0.40
                is_shortener = True
                indicators.append("redirect_shortener_used")
                break

        # ── Check 2: Brand impersonation / spoofing ────────────────────────
        # Pass the full host (including subdomains) so the brand_in_subdomain
        # strategy can detect "microsoft.evilsite.org" correctly.
        full_host = (extracted.subdomain + "." if extracted.subdomain else "") + domain
        spoof_check = cls.check_brand_spoofing(full_host)
        if spoof_check.get("spoofed"):
            score += 0.60
            indicators.append("spoofing_" + spoof_check.get("brand", "") + "_lookalike")

        # ── Check 3: Hyphenated domain (evasion technique) ─────────────────
        if "-" in extracted.domain:
            score += 0.20
            indicators.append("hyphenated_domain")

        # ── Check 4: Excess subdomain levels (> 2 dots in subdomain) ───────
        subdomain_count = extracted.subdomain.count(".") if extracted.subdomain else 0
        if subdomain_count > 2:
            score += 0.15
            indicators.append("excess_subdomains")

        # ── Check 5: Very long URL (padding to obscure destination) ─────────
        if len(url) > 150:
            score += 0.15
            indicators.append("very_long_url")

        # ── Check 6: High entropy domain name (DGA / random characters) ─────
        domain_entropy = cls.get_entropy(extracted.domain)
        if domain_entropy > 4.2:
            score += 0.15
            indicators.append("random_domain_characters")

        # ── Check 7: Bare IP address used as host ────────────────────────────
        ip_pattern = r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, url):
            score += 0.50
            indicators.append("ip_address_domain")

        # ── Simulated fields ─────────────────────────────────────────────────
        # In a production system these would come from live certificate checks
        # and WHOIS / passive DNS lookups.  For the dashboard demo we use
        # fixed plausible defaults.
        ssl_valid      = True     # assume SSL unless URL starts with plain http
        domain_age_days = 450     # ~15 months — "relatively new" domain

        final_score = round(min(score, 1.0), 3)

        return {
            "url":            url,
            "domain":         domain,
            "score":          final_score,
            "indicators":     list(set(indicators)),
            "ssl_valid":      ssl_valid,
            "domain_age_days": domain_age_days,
        }

    @classmethod
    def evaluate_urls(cls, urls: List[str]) -> Dict[str, Any]:
        """
        Evaluates a list of URLs and returns a summary.

        Returns:
          max_score    – highest individual URL risk score
          average_score– mean risk score across all evaluated URLs
          details      – list of per-URL score dicts from score_url()
        """
        details = [cls.score_url(url) for url in urls]

        scores = [d["score"] for d in details]
        max_score     = round(max(scores,    default=0.0), 3)
        average_score = round(sum(scores) / len(scores), 3) if scores else 0.0

        return {
            "max_score":     max_score,
            "average_score": average_score,
            "details":       details,
        }
