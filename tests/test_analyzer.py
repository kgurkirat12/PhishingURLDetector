"""
Unit tests for the PhishingAnalyzer detection engine.
Tests each detection rule individually and verifies scoring thresholds.
"""

import pytest
from analyzer import PhishingAnalyzer, AnalysisResult, CheckResult


@pytest.fixture
def analyzer():
    """Create a fresh PhishingAnalyzer instance."""
    return PhishingAnalyzer()


# ─── Test Safe URLs ──────────────────────────────────────────────────────────

class TestSafeUrls:
    """URLs that should be classified as safe."""

    def test_simple_https_url(self, analyzer):
        result = analyzer.analyze("https://google.com")
        assert result.status == "safe"
        assert result.risk_score <= 30

    def test_https_with_path(self, analyzer):
        result = analyzer.analyze("https://github.com/harsimran726")
        assert result.status == "safe"
        assert result.risk_score <= 30

    def test_https_with_www(self, analyzer):
        result = analyzer.analyze("https://www.wikipedia.org")
        assert result.status == "safe"
        assert result.risk_score <= 30

    def test_well_known_site(self, analyzer):
        result = analyzer.analyze("https://stackoverflow.com/questions")
        assert result.status == "safe"
        assert result.risk_score <= 30


# ─── Test Dangerous URLs ────────────────────────────────────────────────────

class TestDangerousUrls:
    """URLs that should be classified as dangerous."""

    def test_http_with_ip_and_login(self, analyzer):
        """HTTP + IP address + suspicious keyword = very dangerous."""
        result = analyzer.analyze("http://192.168.1.1/login")
        assert result.status == "dangerous"
        assert result.risk_score > 60

    def test_phishing_with_suspicious_tld_and_keywords(self, analyzer):
        """HTTP + suspicious TLD + multiple suspicious keywords."""
        result = analyzer.analyze("http://secure-bank-login.tk/verify/account")
        assert result.status == "dangerous"
        assert result.risk_score >= 60

    def test_at_symbol_with_ip(self, analyzer):
        """@ symbol combined with IP address."""
        result = analyzer.analyze("http://google.com@192.168.1.1/login")
        assert result.status == "dangerous"
        assert result.risk_score > 60

    def test_extremely_long_url(self, analyzer):
        """Very long URL is suspicious."""
        long_path = "a" * 200
        result = analyzer.analyze(f"http://evil.tk/{long_path}")
        assert result.status in ("suspicious", "dangerous")
        assert result.risk_score > 30


# ─── Test Suspicious URLs ───────────────────────────────────────────────────

class TestSuspiciousUrls:
    """URLs that should be classified as suspicious."""

    def test_http_only(self, analyzer):
        """HTTP without HTTPS should add some risk."""
        result = analyzer.analyze("http://example.com")
        assert result.risk_score > 0

    def test_url_shortener(self, analyzer):
        """URL shorteners hide the real destination."""
        result = analyzer.analyze("https://bit.ly/abc123")
        assert result.risk_score > 0
        # Find the shortener check
        shortener_check = next(
            (c for c in result.checks if "Shortener" in c.name), None
        )
        assert shortener_check is not None
        assert not shortener_check.passed

    def test_suspicious_tld(self, analyzer):
        result = analyzer.analyze("https://example.xyz")
        tld_check = next(
            (c for c in result.checks if "TLD" in c.name), None
        )
        assert tld_check is not None
        assert not tld_check.passed


# ─── Test Individual Checks ─────────────────────────────────────────────────

class TestHTTPSCheck:
    """Test HTTPS vs HTTP detection."""

    def test_https_passes(self, analyzer):
        result = analyzer.analyze("https://example.com")
        https_check = next(c for c in result.checks if "HTTPS" in c.name)
        assert https_check.passed

    def test_http_fails(self, analyzer):
        result = analyzer.analyze("http://example.com")
        https_check = next(c for c in result.checks if "HTTPS" in c.name)
        assert not https_check.passed
        assert https_check.weight == 20


class TestAtSymbolCheck:
    """Test @ symbol detection."""

    def test_no_at_symbol(self, analyzer):
        result = analyzer.analyze("https://example.com/path")
        at_check = next(c for c in result.checks if "@" in c.name)
        assert at_check.passed

    def test_at_symbol_in_url(self, analyzer):
        result = analyzer.analyze("https://user@example.com")
        at_check = next(c for c in result.checks if "@" in c.name)
        assert not at_check.passed
        assert at_check.weight == 20


class TestSuspiciousKeywords:
    """Test suspicious keyword detection."""

    def test_no_keywords(self, analyzer):
        result = analyzer.analyze("https://example.com")
        kw_check = next(c for c in result.checks if "Keyword" in c.name)
        assert kw_check.passed

    def test_login_keyword(self, analyzer):
        result = analyzer.analyze("https://example.com/login")
        kw_check = next(c for c in result.checks if "Keyword" in c.name)
        assert not kw_check.passed
        assert "login" in kw_check.detail.lower()

    def test_multiple_keywords(self, analyzer):
        result = analyzer.analyze("https://example.com/login/verify/bank")
        kw_check = next(c for c in result.checks if "Keyword" in c.name)
        assert not kw_check.passed


class TestUrlLength:
    """Test URL length analysis."""

    def test_normal_length(self, analyzer):
        result = analyzer.analyze("https://example.com")
        len_check = next(c for c in result.checks if "Length" in c.name)
        assert len_check.passed

    def test_long_url(self, analyzer):
        long_url = "https://example.com/" + "a" * 80
        result = analyzer.analyze(long_url)
        len_check = next(c for c in result.checks if "Length" in c.name)
        assert not len_check.passed

    def test_very_long_url(self, analyzer):
        very_long = "https://example.com/" + "x" * 160
        result = analyzer.analyze(very_long)
        len_check = next(c for c in result.checks if "Length" in c.name)
        assert not len_check.passed
        assert len_check.weight == 20


class TestIPAddressCheck:
    """Test IP address in URL detection."""

    def test_domain_passes(self, analyzer):
        result = analyzer.analyze("https://example.com")
        ip_check = next(c for c in result.checks if "IP" in c.name)
        assert ip_check.passed

    def test_ipv4_fails(self, analyzer):
        result = analyzer.analyze("http://192.168.1.1/phishing")
        ip_check = next(c for c in result.checks if "IP" in c.name)
        assert not ip_check.passed
        assert ip_check.weight == 30


class TestSubdomainCount:
    """Test excessive subdomain detection."""

    def test_normal_subdomains(self, analyzer):
        result = analyzer.analyze("https://www.example.com")
        sub_check = next(c for c in result.checks if "Subdomain" in c.name)
        assert sub_check.passed

    def test_excessive_subdomains(self, analyzer):
        result = analyzer.analyze("https://a.b.c.d.e.example.com")
        sub_check = next(c for c in result.checks if "Subdomain" in c.name)
        assert not sub_check.passed


class TestTLDReputation:
    """Test TLD reputation check."""

    def test_good_tld(self, analyzer):
        result = analyzer.analyze("https://example.com")
        tld_check = next(c for c in result.checks if "TLD" in c.name)
        assert tld_check.passed

    def test_suspicious_tld_tk(self, analyzer):
        result = analyzer.analyze("https://evil.tk")
        tld_check = next(c for c in result.checks if "TLD" in c.name)
        assert not tld_check.passed

    def test_suspicious_tld_xyz(self, analyzer):
        result = analyzer.analyze("https://evil.xyz")
        tld_check = next(c for c in result.checks if "TLD" in c.name)
        assert not tld_check.passed


class TestPunycodeCheck:
    """Test punycode/homoglyph detection."""

    def test_normal_domain(self, analyzer):
        result = analyzer.analyze("https://example.com")
        puny_check = next(c for c in result.checks if "Punycode" in c.name)
        assert puny_check.passed

    def test_punycode_domain(self, analyzer):
        result = analyzer.analyze("https://xn--googl-fsa.com")
        puny_check = next(c for c in result.checks if "Punycode" in c.name)
        assert not puny_check.passed


class TestUrlShortener:
    """Test URL shortener detection."""

    def test_normal_url(self, analyzer):
        result = analyzer.analyze("https://example.com")
        short_check = next(c for c in result.checks if "Shortener" in c.name)
        assert short_check.passed

    def test_bitly(self, analyzer):
        result = analyzer.analyze("https://bit.ly/abc123")
        short_check = next(c for c in result.checks if "Shortener" in c.name)
        assert not short_check.passed

    def test_tinyurl(self, analyzer):
        result = analyzer.analyze("https://tinyurl.com/abc")
        short_check = next(c for c in result.checks if "Shortener" in c.name)
        assert not short_check.passed


# ─── Test Edge Cases ─────────────────────────────────────────────────────────

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_url(self, analyzer):
        result = analyzer.analyze("")
        assert result.status == "dangerous"
        assert result.risk_score == 100

    def test_whitespace_url(self, analyzer):
        result = analyzer.analyze("   ")
        assert result.status == "dangerous"
        assert result.risk_score == 100

    def test_url_without_scheme(self, analyzer):
        """URL without http:// should still be analyzed."""
        result = analyzer.analyze("example.com")
        assert result.checks  # Should have check results
        assert isinstance(result.risk_score, int)

    def test_result_to_dict(self, analyzer):
        """Test serialization of results."""
        result = analyzer.analyze("https://google.com")
        d = result.to_dict()
        assert "url" in d
        assert "status" in d
        assert "risk_score" in d
        assert "checks" in d
        assert isinstance(d["checks"], list)

    def test_risk_score_capped_at_100(self, analyzer):
        """Risk score should never exceed 100."""
        # A URL that triggers many checks
        result = analyzer.analyze(
            "http://login-verify-bank-secure-account@192.168.1.1/"
            + "x" * 200
        )
        assert result.risk_score <= 100

    def test_all_checks_have_required_fields(self, analyzer):
        """Every check result should have name, passed, detail, weight."""
        result = analyzer.analyze("https://example.com")
        for check in result.checks:
            assert hasattr(check, "name")
            assert hasattr(check, "passed")
            assert hasattr(check, "detail")
            assert hasattr(check, "weight")
            assert isinstance(check.passed, bool)
            assert isinstance(check.weight, int)

    def test_ten_checks_performed(self, analyzer):
        """Should always run all 10 detection checks."""
        result = analyzer.analyze("https://example.com")
        assert len(result.checks) == 10
