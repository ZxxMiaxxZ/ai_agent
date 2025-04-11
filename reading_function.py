import os

def read_file(file_name: str, base_dir: str = "pentest_results/recon") -> str:
    # Nếu file_name đã là absolute path hoặc đã chứa base_dir thì giữ nguyên
    if os.path.isabs(file_name) or file_name.startswith(base_dir):
        file_path = file_name
    else:
        file_path = os.path.join(base_dir, file_name)

    if not os.path.exists(file_path):
        return f"File not found: {os.path.abspath(file_path)}"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file {file_path}: {e}"
