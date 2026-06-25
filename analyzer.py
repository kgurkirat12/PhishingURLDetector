"""
Phishing URL Detection Engine
=============================
Core analysis module implementing rule-based phishing detection
with weighted scoring for comprehensive URL risk assessment.
"""

import re
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class CheckResult:
    """Result of a single phishing detection check."""
    name: str
    passed: bool
    detail: str
    weight: int = 0  # Points added to risk score if failed

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "weight": self.weight,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result for a URL."""
    url: str
    status: str  # "safe", "suspicious", "dangerous"
    risk_score: int  # 0-100
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "risk_score": self.risk_score,
            "checks": [c.to_dict() for c in self.checks],
        }


class PhishingAnalyzer:
    """
    Rule-based phishing URL analyzer.
    
    Applies multiple detection heuristics and produces a weighted
    risk score from 0 (completely safe) to 100 (definitely phishing).
    
    Score thresholds:
        0-30   → Safe
        31-60  → Suspicious
        61-100 → Dangerous
    """

    # Suspicious keywords commonly found in phishing URLs
    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "bank", "secure", "account", "update",
        "confirm", "password", "signin", "webscr", "ebayisapi",
        "billing", "suspend", "alert", "authenticate", "wallet",
        "paypal", "netflix", "apple", "microsoft", "amazo",
    ]

    # Known suspicious/free TLDs heavily used for phishing
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".buzz", ".club", ".work", ".link", ".click", ".surf",
        ".rest", ".icu", ".cam",
    ]

    # Known URL shortener domains
    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "buff.ly", "ow.ly", "rebrand.ly", "bl.ink", "short.io",
        "cutt.ly", "rb.gy",
    ]

    # Score thresholds
    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 60

    def analyze(self, url: str) -> AnalysisResult:
        """
        Perform comprehensive phishing analysis on a URL.
        
        Args:
            url: The URL string to analyze.
            
        Returns:
            AnalysisResult with risk score, status, and individual check results.
        """
        # Normalize the URL
        url = url.strip()
        if not url:
            return AnalysisResult(
                url=url,
                status="dangerous",
                risk_score=100,
                checks=[CheckResult("URL Validation", False, "Empty URL provided", 100)],
            )

        # Add scheme if missing for proper parsing
        parse_url = url
        if not re.match(r'^https?://', url, re.IGNORECASE):
            parse_url = "http://" + url

        try:
            parsed = urlparse(parse_url)
        except Exception:
            return AnalysisResult(
                url=url,
                status="dangerous",
                risk_score=100,
                checks=[CheckResult("URL Validation", False, "Invalid URL format", 100)],
            )

        # Run all checks
        checks = [
            self._check_https(url, parsed),
            self._check_at_symbol(url, parsed),
            self._check_suspicious_keywords(url, parsed),
            self._check_url_length(url, parsed),
            self._check_ip_address(url, parsed),
            self._check_subdomain_count(url, parsed),
            self._check_special_chars(url, parsed),
            self._check_tld_reputation(url, parsed),
            self._check_punycode(url, parsed),
            self._check_url_shortener(url, parsed),
        ]

        # Calculate total risk score (cap at 100)
        risk_score = min(100, sum(c.weight for c in checks if not c.passed))

        # Determine status
        if risk_score <= self.SAFE_THRESHOLD:
            status = "safe"
        elif risk_score < self.SUSPICIOUS_THRESHOLD:
            status = "suspicious"
        else:
            status = "dangerous"

        return AnalysisResult(
            url=url,
            status=status,
            risk_score=risk_score,
            checks=checks,
        )

    def _check_https(self, url: str, parsed) -> CheckResult:
        """Check if URL uses HTTPS (secure connection)."""
        if parsed.scheme == "https":
            return CheckResult(
                name="HTTPS Check",
                passed=True,
                detail="URL uses secure HTTPS protocol",
                weight=20,
            )
        return CheckResult(
            name="HTTPS Check",
            passed=False,
            detail="URL uses insecure HTTP — legitimate sites use HTTPS",
            weight=20,
        )

    def _check_at_symbol(self, url: str, parsed) -> CheckResult:
        """Check for @ symbol which can be used to mislead users about the real domain."""
        # Check in the netloc/authority portion (before query/fragment)
        url_without_scheme = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
        # Split off path/query
        authority_and_path = url_without_scheme.split('?')[0].split('#')[0]

        if '@' in authority_and_path:
            return CheckResult(
                name="@ Symbol Detection",
                passed=False,
                detail="URL contains '@' symbol — often used to disguise the real destination",
                weight=20,
            )
        return CheckResult(
            name="@ Symbol Detection",
            passed=True,
            detail="No misleading '@' symbol found in URL",
            weight=20,
        )

    def _check_suspicious_keywords(self, url: str, parsed) -> CheckResult:
        """Check for phishing-related keywords in the URL."""
        url_lower = url.lower()
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in url_lower]

        if found_keywords:
            kw_list = ", ".join(found_keywords[:5])
            extra = f" (+{len(found_keywords) - 5} more)" if len(found_keywords) > 5 else ""
            return CheckResult(
                name="Suspicious Keywords",
                passed=False,
                detail=f"Found suspicious keywords: {kw_list}{extra}",
                weight=min(10 + len(found_keywords) * 3, 25),
            )
        return CheckResult(
            name="Suspicious Keywords",
            passed=True,
            detail="No suspicious keywords detected in URL",
            weight=15,
        )

    def _check_url_length(self, url: str, parsed) -> CheckResult:
        """Check URL length — phishing URLs tend to be abnormally long."""
        length = len(url)

        if length > 150:
            return CheckResult(
                name="URL Length Analysis",
                passed=False,
                detail=f"URL is extremely long ({length} chars) — strong phishing indicator",
                weight=20,
            )
        elif length > 75:
            return CheckResult(
                name="URL Length Analysis",
                passed=False,
                detail=f"URL is suspiciously long ({length} chars)",
                weight=10,
            )
        return CheckResult(
            name="URL Length Analysis",
            passed=True,
            detail=f"URL length is normal ({length} chars)",
            weight=10,
        )

    def _check_ip_address(self, url: str, parsed) -> CheckResult:
        """Check if the URL uses an IP address instead of a domain name."""
        hostname = parsed.hostname or ""

        # Check for IPv4
        ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        # Check for IPv6 (simplified — enclosed in brackets in URLs)
        ipv6_in_url = hostname.startswith('[') or re.match(r'^[0-9a-fA-F:]+$', hostname)

        if ipv4_pattern.match(hostname) or ipv6_in_url:
            return CheckResult(
                name="IP Address Detection",
                passed=False,
                detail="URL uses an IP address instead of a domain name — strong phishing indicator",
                weight=30,
            )
        return CheckResult(
            name="IP Address Detection",
            passed=True,
            detail="URL uses a proper domain name",
            weight=30,
        )

    def _check_subdomain_count(self, url: str, parsed) -> CheckResult:
        """Check for excessive subdomains — phishers use many subdomains to confuse users."""
        hostname = parsed.hostname or ""

        # Remove www. prefix for counting
        if hostname.startswith("www."):
            hostname = hostname[4:]

        parts = hostname.split('.')

        # Subtract TLD and domain (e.g., example.com = 2 parts, so subdomains = parts - 2)
        subdomain_count = max(0, len(parts) - 2)

        if subdomain_count >= 4:
            return CheckResult(
                name="Subdomain Analysis",
                passed=False,
                detail=f"URL has {subdomain_count} subdomains — excessive subdomain depth is suspicious",
                weight=15,
            )
        elif subdomain_count >= 3:
            return CheckResult(
                name="Subdomain Analysis",
                passed=False,
                detail=f"URL has {subdomain_count} subdomains — unusual depth",
                weight=8,
            )
        return CheckResult(
            name="Subdomain Analysis",
            passed=True,
            detail=f"Subdomain depth is normal ({subdomain_count} {'subdomain' if subdomain_count == 1 else 'subdomains'})",
            weight=10,
        )

    def _check_special_chars(self, url: str, parsed) -> CheckResult:
        """Check for unusual density of special characters in the domain."""
        hostname = parsed.hostname or ""
        if not hostname:
            return CheckResult(
                name="Special Character Analysis",
                passed=False,
                detail="Could not extract hostname from URL",
                weight=10,
            )

        special_count = sum(1 for c in hostname if c in "-_~")
        total_len = len(hostname)

        if total_len == 0:
            ratio = 0
        else:
            ratio = special_count / total_len

        if ratio > 0.2 or special_count > 5:
            return CheckResult(
                name="Special Character Analysis",
                passed=False,
                detail=f"Domain contains {special_count} special characters — suspicious pattern",
                weight=10,
            )
        return CheckResult(
            name="Special Character Analysis",
            passed=True,
            detail="Domain character composition looks normal",
            weight=10,
        )

    def _check_tld_reputation(self, url: str, parsed) -> CheckResult:
        """Check if the TLD is known to be commonly used for phishing."""
        hostname = parsed.hostname or ""

        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return CheckResult(
                    name="TLD Reputation",
                    passed=False,
                    detail=f"Domain uses '{tld}' TLD — commonly associated with phishing",
                    weight=15,
                )
        return CheckResult(
            name="TLD Reputation",
            passed=True,
            detail="Domain TLD has a good reputation",
            weight=15,
        )

    def _check_punycode(self, url: str, parsed) -> CheckResult:
        """Check for internationalized domain names (punycode) used for homoglyph attacks."""
        hostname = parsed.hostname or ""

        if hostname.startswith("xn--") or ".xn--" in hostname:
            return CheckResult(
                name="Punycode / Homoglyph Detection",
                passed=False,
                detail="URL contains punycode (internationalized domain) — may be a homoglyph attack",
                weight=20,
            )

        # Also check the raw URL for unicode characters that could be homoglyphs
        try:
            decoded = unquote(url)
            non_ascii = [c for c in decoded if ord(c) > 127]
            if non_ascii:
                return CheckResult(
                    name="Punycode / Homoglyph Detection",
                    passed=False,
                    detail="URL contains non-ASCII characters — possible homoglyph attack",
                    weight=15,
                )
        except Exception:
            pass

        return CheckResult(
            name="Punycode / Homoglyph Detection",
            passed=True,
            detail="No homoglyph or punycode spoofing detected",
            weight=15,
        )

    def _check_url_shortener(self, url: str, parsed) -> CheckResult:
        """Check if the URL is from a known URL shortener service."""
        hostname = parsed.hostname or ""

        # Remove www. for comparison
        clean_host = hostname.lower()
        if clean_host.startswith("www."):
            clean_host = clean_host[4:]

        if clean_host in self.URL_SHORTENERS:
            return CheckResult(
                name="URL Shortener Detection",
                passed=False,
                detail=f"URL uses shortener service '{clean_host}' — hides the real destination",
                weight=10,
            )
        return CheckResult(
            name="URL Shortener Detection",
            passed=True,
            detail="URL does not use a shortener service",
            weight=10,
        )
