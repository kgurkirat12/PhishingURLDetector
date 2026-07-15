from flask import Flask, render_template, request
from urllib.parse import urlparse

from scanner import scan_url
from port_scanner import scan_ports
from ssl_checker import check_ssl
from sql_scanner import check_sql_injection
from xss_detector import check_xss
from report import save_report
from pdf_report import create_pdf

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    url = request.form["url"].strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Website Scanner
    result = scan_url(url)

    hostname = urlparse(url).hostname

    # Port Scanner
    ports = scan_ports(hostname)

    # SSL Checker
    ssl_info = check_ssl(hostname)

    # SQL Injection Test
    sql_result = check_sql_injection(url)

    # XSS Test
    xss_result = check_xss(url)

    # -------------------------
    # Security Score
    # -------------------------

    score = 100

    if len(ports) > 2:
        score -= 10

    if ssl_info["status"] != "Valid":
        score -= 30

    if sql_result["vulnerable"]:
        score -= 40

    if not xss_result["safe"]:
        score -= 20

    if score < 0:
        score = 0

    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    # Save CSV Report
    save_report(url, score, risk)

    # Generate PDF Report
    create_pdf(
        url=url,
        score=score,
        risk=risk,
        result=result,
        ssl_info=ssl_info
    )

    return render_template(
        "report.html",
        url=url,
        result=result,
        ports=ports,
        ssl_info=ssl_info,
        sql_result=sql_result,
        xss_result=xss_result,
        score=score,
        risk=risk
    )


if __name__ == "__main__":
    app.run(debug=True)