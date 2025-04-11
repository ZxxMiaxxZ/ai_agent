import os
def save_report(report_text: str, filename: str = "recon_report.txt") -> str:
    print("=== Saving Report ===")
    print("Filename:", filename)
    print("Report:", report_text[:100])  # log phần đầu report
    os.makedirs("pentest_results/reports", exist_ok=True)
    path = os.path.join("pentest_results/reports", filename)

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(report_text)
        return f"Report saved to {path}"
    except Exception as e:
        return f"Error saving report: {e}"
