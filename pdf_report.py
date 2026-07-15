from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import os


def create_pdf(url, score, risk, result, ssl_info):
    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_report.pdf"

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>Mini Penetration Testing Toolkit</b>", styles["Title"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph(f"<b>Website:</b> {url}", styles["Normal"]))

    story.append(Paragraph(f"<b>Security Score:</b> {score}/100", styles["Normal"]))

    story.append(Paragraph(f"<b>Risk Level:</b> {risk}", styles["Normal"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph("<b>Website Scan</b>", styles["Heading2"]))

    story.append(Paragraph(f"Status: {result['status']}", styles["Normal"]))

    story.append(Paragraph(f"Status Code: {result.get('status_code','N/A')}", styles["Normal"]))

    story.append(Paragraph(f"Server: {result.get('server','N/A')}", styles["Normal"]))

    story.append(Paragraph(f"Response Time: {result.get('response_time','N/A')} sec", styles["Normal"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph("<b>SSL Certificate</b>", styles["Heading2"]))

    story.append(Paragraph(f"Status: {ssl_info['status']}", styles["Normal"]))

    story.append(Paragraph(f"Issuer: {ssl_info.get('issuer','N/A')}", styles["Normal"]))

    story.append(Paragraph(f"Expiry: {ssl_info.get('expiry','N/A')}", styles["Normal"]))

    doc.build(story)

    return filename