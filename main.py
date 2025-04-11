# main.py
import os
import autogen
from recon_team import create_recon_team
from vuln_team import create_vuln_team

# from exploit_team import create_exploit_team
# from report_team import create_report_team

# Tạo thư mục cần thiết
def ensure_directories():
    """Tạo các thư mục cần thiết nếu chưa tồn tại"""
    directories = [
        "pentest_results",
        "pentest_results/recon", 
        "pentest_results/vulnscan",
        "pentest_results/exploit",
        "pentest_results/reports"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Đã tạo thư mục: {directory}")

# Cấu hình LLM
config_list = [
    {
        "api_type": "openai",
        "base_url": None,
        "api_key": "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",
        "model": "gpt-4o-mini"
    }
]

llm_config = {
    "seed": 30,
    "config_list": config_list,
    "temperature": 0.3,
}

# Thực thi khi chạy trực tiếp file này
if __name__ == "__main__":
    # Đảm bảo thư mục tồn tại
    ensure_directories()
    
    print("=== PENTESTING WORKFLOW ===")
    print("1. Reconnaissance")
    print("2. Vulnerability Scanning")
    print("3. Exploitation (coming soon)")
    print("4. Reporting (coming soon)")
    print("============================")
    
    choice = input("Select a phase to execute (1-4): ")
    
    if choice == "1":
        # Tạo và khởi chạy nhóm Recon
        recon = create_recon_team(llm_config, interaction_mode="ALWAYS")
        recon["user_proxy"].initiate_chat(
            recon["manager"], 
            message="I need you to perform reconnaissance on a web target. Please ask me what URL or IP address I want to scan, then follow your recon workflow."
        )
    
    elif choice == "2":
        vuln = create_vuln_team(llm_config, interaction_mode="ALWAYS")
        vuln["user_proxy"].initiate_chat(
            vuln["manager"],
            message="Reconnaissance is complete. Use its output to run vulnerability scanners accordingly."
        )

    
    elif choice == "3":
        print("Exploitation not implemented yet")
        # exploit_team = create_exploit_team(llm_config)
        # run_exploitation(exploit_team)
        
    elif choice == "4":
        print("Reporting not implemented yet")
        # report_team = create_report_team(llm_config)
        # generate_report(report_team)
        
    else:
        print("Invalid choice")