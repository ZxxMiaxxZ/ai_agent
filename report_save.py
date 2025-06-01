import os

def save_report(report_text: str, filename: str = "report.txt") -> str:
    # Luôn chỉ lấy phần tên file cuối cùng
    filename_only = os.path.basename(filename.strip())
    # Ghi đè vào thư mục reports
    path = os.path.join("pentest_results", "reports", filename_only)
    # Bảo đảm thư mục tồn tại
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(report_text)
        return f"Report saved to {os.path.abspath(path)}"
    except Exception as e:
        return f"Error saving report: {e}"
