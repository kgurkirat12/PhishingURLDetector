# 🛡️ Phishing URL Detector

**Analyze. Detect. Protect.**

A web-based application that detects whether a given URL is safe or potentially a phishing attack using advanced rule-based detection. Built with Python (Flask) and a premium cybersecurity-themed UI.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-green?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)

---

## ✨ Features

### Core Features
- **URL Input & Validation** — Enter a URL and validate the format before analysis
- **10-Rule Phishing Detection Engine** — Comprehensive rule-based analysis:
  1. HTTPS vs HTTP check
  2. `@` symbol detection (URL spoofing)
  3. Suspicious keyword scanning (login, verify, bank, etc.)
  4. URL length analysis
  5. IP address in URL detection
  6. Excessive subdomain analysis
  7. Special character density check
  8. TLD reputation scoring
  9. Punycode/homoglyph attack detection
  10. URL shortener detection
- **Risk Score (0-100)** — Weighted scoring with three severity levels:
  - ✅ **Safe** (0-30)
  - ⚠️ **Suspicious** (31-60)
  - 🚨 **Dangerous** (61-100)

### Bonus Features
- **URL History Tracking** — View and re-scan past URLs
- **Color Indicators** — Green/Amber/Red status with animated score ring
- **Premium UI/UX** — Dark cybersecurity theme with glassmorphism & animations
- **Google Safe Browsing API** — Optional integration for extra validation

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) |
| **Backend** | Python 3.11, Flask 3.1 |
| **Testing** | pytest + pytest-cov |
| **Deployment** | Gunicorn, Render/Railway ready |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+ installed
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/kgurkirat12/phishing-url-detector.git
   cd phishing-url-detector
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment** (optional)
   ```bash
   copy .env.example .env
   # Edit .env to add your Google Safe Browsing API key (optional)
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open in browser**
   ```
   http://localhost:5000
   ```

---

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=. --cov-report=term-missing

# Run specific test file
python -m pytest tests/test_analyzer.py -v
```

---

## 📡 API Documentation

### `POST /api/check`
Analyze a URL for phishing indicators.

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "status": "safe",
  "risk_score": 0,
  "checks": [
    { "name": "HTTPS Check", "passed": true, "detail": "URL uses secure HTTPS protocol", "weight": 15 }
  ],
  "timestamp": "2026-06-25T12:00:00Z"
}
```

### `GET /api/history`
Retrieve scan history. Optional `?limit=N` query parameter.

### `DELETE /api/history/clear`
Clear all scan history.

---

## 🌐 Deployment

### Render (Recommended)
1. Push code to GitHub
2. Connect repo on [render.com](https://render.com)
3. Render auto-detects the `render.yaml` blueprint
4. Deploy!

### Railway
1. Push code to GitHub
2. Create new project on [railway.app](https://railway.app)
3. Connect your repo
4. Railway detects the `Procfile` automatically

---

## 📁 Project Structure

```
├── app.py                  # Flask application & API routes
├── analyzer.py             # Phishing detection engine (10 rules)
├── history.py              # Scan history management
├── requirements.txt        # Python dependencies
├── Procfile                # Deployment process file
├── render.yaml             # Render deployment config
├── templates/
│   └── index.html          # Frontend page
├── static/
│   ├── css/style.css       # Dark cybersecurity theme
│   └── js/app.js           # Frontend logic & animations
└── tests/
    ├── test_analyzer.py    # 35+ analyzer tests
    ├── test_app.py         # API integration tests
    └── test_history.py     # History manager tests
```

---

---

## 📄 License

This project is licensed under the MIT License.
