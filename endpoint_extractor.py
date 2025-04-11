# endpoint_extractor.py
import os

def extract_endpoints(file_path="pentest_results/recon/gobuster_scan.txt", base_url="http://localhost:8083") -> list:
    """Extract endpoints from gobuster scan file."""
    if not os.path.exists(file_path):
        return []

    endpoints = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("/") and "Status:" in line:
                path = line.split()[0]
                name = path.strip("/").replace("/", "-") or "root"
                full_url = f"{base_url}{path}"
                endpoints.append((name, full_url))  # ("login", "http://localhost:42000/login")
    return endpoints
