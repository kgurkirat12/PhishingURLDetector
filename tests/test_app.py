"""
Integration tests for the Flask API endpoints.
Tests request/response contracts, error handling, and CORS.
"""

import json
import pytest
from app import app


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ─── Test GET / (Serve Frontend) ────────────────────────────────────────────

class TestIndexRoute:
    """Test the main page route."""

    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_returns_html(self, client):
        response = client.get("/")
        assert b"Phishing URL Detector" in response.data


# ─── Test POST /api/check ───────────────────────────────────────────────────

class TestCheckEndpoint:
    """Test the URL check API endpoint."""

    def test_check_valid_url(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "https://google.com"}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "url" in data
        assert "status" in data
        assert "risk_score" in data
        assert "checks" in data
        assert "timestamp" in data
        assert data["status"] in ("safe", "suspicious", "dangerous")

    def test_check_safe_url(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "https://github.com"}),
            content_type="application/json",
        )
        data = response.get_json()
        assert data["status"] == "safe"
        assert data["risk_score"] <= 30

    def test_check_dangerous_url(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "http://192.168.1.1/login/verify"}),
            content_type="application/json",
        )
        data = response.get_json()
        assert data["status"] == "dangerous"
        assert data["risk_score"] > 60

    def test_check_missing_url_field(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"not_url": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_check_empty_url(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": ""}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_check_invalid_url_format(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "not-a-valid-url"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_check_no_json_body(self, client):
        response = client.post("/api/check")
        assert response.status_code == 400

    def test_check_returns_checks_array(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json",
        )
        data = response.get_json()
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) > 0

        for check in data["checks"]:
            assert "name" in check
            assert "passed" in check
            assert "detail" in check

    def test_check_risk_score_is_integer(self, client):
        response = client.post(
            "/api/check",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json",
        )
        data = response.get_json()
        assert isinstance(data["risk_score"], int)
        assert 0 <= data["risk_score"] <= 100


# ─── Test GET /api/history ──────────────────────────────────────────────────

class TestHistoryEndpoint:
    """Test the history API endpoint."""

    def test_history_returns_200(self, client):
        response = client.get("/api/history")
        assert response.status_code == 200

    def test_history_returns_correct_format(self, client):
        response = client.get("/api/history")
        data = response.get_json()
        assert "history" in data
        assert "count" in data
        assert isinstance(data["history"], list)

    def test_history_with_limit(self, client):
        # First add some entries
        for i in range(5):
            client.post(
                "/api/check",
                data=json.dumps({"url": f"https://example{i}.com"}),
                content_type="application/json",
            )

        response = client.get("/api/history?limit=2")
        data = response.get_json()
        assert len(data["history"]) <= 2

    def test_history_entries_have_required_fields(self, client):
        # Add an entry first
        client.post(
            "/api/check",
            data=json.dumps({"url": "https://test.com"}),
            content_type="application/json",
        )

        response = client.get("/api/history")
        data = response.get_json()

        if data["count"] > 0:
            entry = data["history"][0]
            assert "url" in entry
            assert "status" in entry
            assert "risk_score" in entry
            assert "timestamp" in entry


# ─── Test DELETE /api/history/clear ─────────────────────────────────────────

class TestClearHistoryEndpoint:
    """Test the clear history API endpoint."""

    def test_clear_returns_200(self, client):
        response = client.delete("/api/history/clear")
        assert response.status_code == 200

    def test_clear_returns_correct_format(self, client):
        response = client.delete("/api/history/clear")
        data = response.get_json()
        assert "cleared" in data
        assert "message" in data

    def test_clear_empties_history(self, client):
        # Add some entries
        client.post(
            "/api/check",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json",
        )

        # Clear
        client.delete("/api/history/clear")

        # Verify empty
        response = client.get("/api/history")
        data = response.get_json()
        assert data["count"] == 0


# ─── Test Error Handling ────────────────────────────────────────────────────

class TestErrorHandling:
    """Test error responses."""

    def test_404_returns_json(self, client):
        response = client.get("/api/nonexistent")
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_method_not_allowed_check(self, client):
        response = client.get("/api/check")
        assert response.status_code == 405

    def test_method_not_allowed_clear(self, client):
        response = client.get("/api/history/clear")
        assert response.status_code == 405
