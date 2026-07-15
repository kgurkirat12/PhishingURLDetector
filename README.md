# 🛡 Mini Penetration Testing Toolkit

## 📌 Project Overview

The Mini Penetration Testing Toolkit is a web-based security application developed using Python and Flask. It performs basic security analysis of websites by scanning common security parameters and generating detailed security reports.

This project is designed for educational purposes to demonstrate basic penetration testing concepts and website vulnerability assessment.

---

# 🚀 Features

- 🌐 URL Scanner
- 🔌 Common Port Scanner
- 🔒 SSL Certificate Checker
- 💉 SQL Injection Detection
- 🛡 Cross-Site Scripting (XSS) Detection
- 📊 Security Score Calculation
- ⚠️ Risk Level Classification
- 📄 PDF Security Report Generation
- 📁 CSV Scan History
- 💻 User-Friendly Web Interface

---

# 🛠 Technologies Used

- Python 3
- Flask
- HTML5
- CSS3
- Bootstrap 5
- Requests
- ReportLab
- Socket Programming
- SSL Module

---

# 📂 Project Structure

```
Mini_Penetration_Testing_Toolkit/
│
├── app.py
├── scanner.py
├── port_scanner.py
├── ssl_checker.py
├── sql_scanner.py
├── xss_detector.py
├── report.py
├── pdf_report.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── index.html
│   └── report.html
│
├── static/
│   └── style.css
│
├── reports/
│   ├── scan_history.csv
│   └── security_report.pdf
```

---

# ⚙️ Installation

Clone the repository

```
git clone <repository-link>
```

Move into the project folder

```
cd Mini_Penetration_Testing_Toolkit
```

Install required packages

```
pip install -r requirements.txt
```

Run the application

```
python app.py
```

Open your browser

```
http://127.0.0.1:5000
```

---

# 🔍 Modules

### 1. URL Scanner

Checks whether the website is reachable and displays:

- HTTP Status Code
- Response Time
- Web Server Information

### 2. Port Scanner

Scans commonly used ports including:

- FTP (21)
- SSH (22)
- SMTP (25)
- DNS (53)
- HTTP (80)
- POP3 (110)
- IMAP (143)
- HTTPS (443)
- MySQL (3306)

### 3. SSL Certificate Checker

Displays

- SSL Status
- Certificate Issuer
- Expiry Date

### 4. SQL Injection Scanner

Performs basic SQL Injection testing using common payloads.

### 5. XSS Scanner

Checks for common XSS attack patterns.

### 6. Security Score

Calculates a security score out of 100 based on scan results.

### 7. Report Generation

Generates

- PDF Report
- CSV Scan History

---

# 📊 Output

After every scan the toolkit displays:

- Website Status
- HTTP Status Code
- Response Time
- Open Ports
- SSL Information
- SQL Injection Result
- XSS Result
- Security Score
- Risk Level

It also saves

- PDF Report
- CSV History

---

# 📈 Future Improvements

- Automatic Multi-Website Scanning
- WHOIS Lookup
- DNS Information
- Security Headers Analysis
- CVE Database Integration
- Email Report
- Login Authentication
- Dashboard Analytics

---

# 🎯 Learning Outcomes

This project demonstrates:

- Website Security Testing
- Basic Penetration Testing Concepts
- Flask Web Development
- Socket Programming
- SSL Certificate Verification
- Report Generation
- Modular Python Programming

---

# 👩‍💻 Developed By

**Gurkirat Kaur**

Mini Penetration Testing Toolkit

Python & Flask Project

2026