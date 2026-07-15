import csv
import os

REPORT_FILE = "reports/scan_history.csv"


def save_report(url, score, risk):
    """
    Save each scan to a CSV file.
    """

    os.makedirs("reports", exist_ok=True)

    file_exists = os.path.isfile(REPORT_FILE)

    with open(REPORT_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Website",
                "Security Score",
                "Risk Level"
            ])

        writer.writerow([
            url,
            score,
            risk
        ])