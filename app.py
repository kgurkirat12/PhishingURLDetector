"""
Phishing URL Detection Web App
==============================
Flask application providing API endpoints for URL phishing analysis
and serving the frontend interface.

Endpoints:
    GET  /                  → Serve the frontend
    POST /api/check         → Analyze a URL for phishing indicators
    GET  /api/history       → Retrieve scan history
    DELETE /api/history/clear → Clear scan history
"""

import os
import re
import requests
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from analyzer import PhishingAnalyzer
from history import HistoryManager

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
CORS(app)

# Initialize core components
analyzer = PhishingAnalyzer()
history_manager = HistoryManager(persist=True)

# Optional: Google Safe Browsing API key
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main frontend page."""
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check_url():
    """
    Analyze a URL for phishing indicators.
    
    Request JSON:
        { "url": "https://example.com" }
        
    Response JSON:
        {
            "url": "https://example.com",
            "status": "safe" | "suspicious" | "dangerous",
            "risk_score": 0-100,
            "checks": [...],
            "timestamp": "ISO-8601",
            "safe_browsing": { ... }  // optional
        }
    """
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Basic URL format validation
    url_pattern = re.compile(
        r'^(https?://)?'                    # Optional scheme
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*'  # Subdomains
        r'[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'       # Domain
        r'(\.[a-zA-Z]{2,})'                # TLD
        r'(:\d+)?'                          # Optional port
        r'(/.*)?$'                          # Optional path
        , re.IGNORECASE
    )

    # Also allow IP-based URLs
    ip_url_pattern = re.compile(
        r'^(https?://)?'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'(:\d+)?'
        r'(/.*)?$'
    )

    if not url_pattern.match(url) and not ip_url_pattern.match(url):
        return jsonify({"error": "Invalid URL format. Please enter a valid URL."}), 400

    # Run phishing analysis
    result = analyzer.analyze(url)

    # Build response
    response = result.to_dict()
    response["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Optional: Check Google Safe Browsing API
    safe_browsing_result = _check_safe_browsing(url)
    if safe_browsing_result is not None:
        response["safe_browsing"] = safe_browsing_result

        # If Safe Browsing flags it, boost the risk score
        if safe_browsing_result.get("flagged"):
            response["risk_score"] = min(100, response["risk_score"] + 30)
            if response["risk_score"] > 60:
                response["status"] = "dangerous"
            elif response["risk_score"] > 30:
                response["status"] = "suspicious"

    # Save to history
    history_manager.add_entry(
        url=url,
        status=response["status"],
        risk_score=response["risk_score"],
    )

    return jsonify(response), 200


@app.route("/api/history", methods=["GET"])
def get_history():
    """
    Retrieve scan history.
    
    Query params:
        limit (int, optional): Max number of entries to return.
        
    Response JSON:
        {
            "history": [...],
            "count": 10
        }
    """
    limit = request.args.get("limit", type=int)
    entries = history_manager.get_history(limit=limit)

    return jsonify({
        "history": entries,
        "count": len(entries),
    }), 200


@app.route("/api/history/clear", methods=["DELETE"])
def clear_history():
    """
    Clear all scan history.
    
    Response JSON:
        { "cleared": 10, "message": "History cleared successfully" }
    """
    count = history_manager.clear_history()

    return jsonify({
        "cleared": count,
        "message": "History cleared successfully",
    }), 200


# ─── Helper Functions ──────────────────────────────────────────────────────────

def _check_safe_browsing(url: str) -> dict | None:
    """
    Check a URL against the Google Safe Browsing API (optional).
    
    Returns None if API key is not configured.
    Returns dict with 'flagged' boolean and threat details if configured.
    """
    if not SAFE_BROWSING_API_KEY:
        return None

    api_url = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "phishing-url-detector",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(api_url, json=payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if matches:
            threats = [m.get("threatType", "UNKNOWN") for m in matches]
            return {
                "flagged": True,
                "threats": threats,
                "detail": f"Google Safe Browsing flagged this URL: {', '.join(threats)}",
            }
        return {
            "flagged": False,
            "detail": "URL not found in Google Safe Browsing threat database",
        }
    except Exception:
        return None  # Silently fail — rule-based analysis is primary


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
