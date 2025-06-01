import os
import socket
from urllib.parse import urlparse, parse_qs
from autogen.agentchat import AssistantAgent, ConversableAgent, UserProxyAgent, GroupChat, GroupChatManager
from autogen.coding.local_commandline_code_executor import LocalCommandLineCodeExecutor
from reading_function import read_file
from report_save import save_report
from web_form_analyzer import analyze_and_capture_url
from log_summary import extract_sqlmap_summary

#CONFIG
config_list = [
    {
        "api_type": "openai",
        "model": "gpt-4.1",
        "price": [0.01, 0.03]
    }
]

llm_config = {
    "seed": 30,
    "config_list": config_list,
    "temperature": 0.1,
    "timeout": 60
}

def ensure_directories():
    directories = [
        "pentest_results",
        "pentest_results/recon",
        "pentest_results/vulnscan",
        "pentest_results/exploit",
        "pentest_results/reports"
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"[+] Created: {directory}")

def get_ip_from_url(url):
    try:
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error resolving IP: {str(e)}"



def pentest_team(llm_config, interaction_mode):
    nmap_agent = ConversableAgent(
        name="Nmap-Agent",
        system_message="""
            You're a cybersecurity professional specialized in reconnaissance using Nmap.
            You are responsible for discovering open ports and running services using `nmap`. Use flags appropriate for a full scan.
            You must redirect output to a file located at: `pentest_results/recon/nmap_scan.txt`.
            After that must call Code-Checker
            When generating a command:
            - Use only nmap
            - Always redirect output
            - Do not attempt to use other tools or write logic, only one command at a time
            - Format your command inside a bash code block like:
            ```bash
            <your_command_here>
            ```
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    whatweb_agent = ConversableAgent(
        name="WhatWeb-Agent",
        system_message="""
            You are responsible for identifying web technologies using WhatWeb.
            Use the `whatweb` tool and always redirect using (tee) the output to `pentest_results/recon/whatweb_scan.txt`.

            Never use other tools. Do not suggest full scan command in advance, always generate command from scratch.
            After that must call Code-Checker
            Format your result like this:
            ```bash
            <your_command>
            ```
            
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    directory_scanner = ConversableAgent(
        name="Directory-Scanner",
        system_message="""
            You're responsible for discovering web directories using Gobuster.
            Use Gobuster with a wordlist to brute-force directories on a given target.
            Redirect your result to: `pentest_results/recon/gobuster_scan.txt`
            After that must call Code-Checker
            Using cookie (if have) to bypass authetication of the web
            Guidelines:
            - Only use Gobuster
            - The wordlist is **not fixed** — you should use first wordlist is url_dvwa.txt`/home/kali/Desktop/AI_4/url_dvwa.txt`, `/usr/share/wordlists/dirb/common.txt`, `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`, or any appropriate wordlist based on the target.
            - Always redirect to file
            - Respond with one properly formatted command:
            ```bash
            <your_command> 
            ```
            After this agent executor by Code-Checker and Code-Executor, please send `===recon done===`
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )


    checker = ConversableAgent(
        name="Code-Checker",
        system_message="""
            You're a professional code checker, whose job is whenever a command or code is created before its run you should first, checking if the code is correct and the output. if there is a typing mistake, an argument mistake, a language mistake, etc you should say something so that the code is rewritten by the agent who produced this code. Also check if the command was generated in the right format, with the specified language. The format should be:


            You may receive:
            1. A full command suggestion to validate
            2. A human natural language instruction like "scan only port 80"

            Your job:
            - If the user gives you natural language like "just scan 80", you must understand and rewrite the command properly.
            - If they send full command, validate syntax, flags, and output redirection .
            - Do not give the user like this 'Make sure that the directory exists before running this command to avoid any errors' (That is your job)
            - Remove the command if it contain like remove (rm) or something damage the system.
            - Finally give it for Code-Executor
            Always reply with this exact format:
            ```bash
            <correct bash command>
            ```
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    executor = LocalCommandLineCodeExecutor(timeout=3600, work_dir=".")
    code_executor = AssistantAgent(
        name="Code-Executor",
        llm_config=False,
        code_execution_config={"executor": executor},
        human_input_mode=interaction_mode,
    )

    file_reader = AssistantAgent(
        name="File-Reader",
        system_message="Read and summarize result files.",
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )
    file_reader.register_for_llm(name="read_file", description="Read a scan result file")(read_file)
    file_reader.register_for_execution(name="read_file", description="Read a scan result file")(read_file)

    user_proxy = UserProxyAgent(
        name="User-Proxy",
        system_message="A human security analyst overseeing the pentest operation. Your mission is send `TERMINATE`",
        is_termination_msg=lambda msg: "TERMINATE" in msg["content"],
        code_execution_config={"work_dir": ".", "use_docker": False},
        # human_input_mode="ALWAYS",
        human_input_mode="NEVER",
        llm_config=llm_config
    )
    user_proxy.register_for_execution(name="read_file")(read_file)


    report_writer = AssistantAgent(
        name="Report-Writer",
        system_message="""
            You're a professional security report writer.
            If you see this the chat `===recon done===` please write a report with 3 tool (Nmap-Agent, Whatweb-Agent, Directory-Scanner)
            If you see this the chat `===vuln-scan done===` please write a report with 2 tool (Param-URL-Agent, Nuclei-Agent)
            Remember to be specific. Always put the IP address or URL you scan on the first line.
            Summary the results after each phase:
            - recon phase with 3 agent(nmap_agent, whatweb_agent, directory_scanner) save filename "recon_summary.html"
            - vuln phase (param_agent,nuclei_agent) save filename "vuln_summary.html"
            - exploit phase (exploit_agent, post_exploit_agent). Write in detail about what you have exploited and what it can do. Like the database for login accounts or what the etc/passwd file is for. Write clearly and thoroughly. save filename "exploit_summary.html"
            When you call save_report, pass ONLY a simple filename.
            e.g. "recon_summary.html", not a path.
            ** IMPORTANT** After writing the report, you MUST call the `save_report` tool to save the file. Do not skip this step.
            -After wirte exploit_summary.html call final_report_writer(Final-Report-Write) to write the final report
            Report Format:
            - Output must be valid, full HTML5.
            - Use embedded CSS to improve visual quality (tables, headings, spacing).
            - Explain technical findings + their real-world impact (even for non-technical readers)
            - Use examples, payloads, and describe potential consequences clearly
            - Start with `<h1>` title, target IP/URL, and date.
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    report_writer.register_for_llm(name="save_report", description="Save the report")(save_report)
    report_writer.register_for_execution(name="save_report")(save_report)
    user_proxy.register_for_execution(name="save_report")(save_report)


    #======FINAL report===========
    final_report_writer = AssistantAgent(
        name="Final-Report-Writer",
        system_message="""
            You're a professional security report writer. Write specifically, easy to understand and visualize
            - File: `final_report.html`
            - Purpose: Combine all phase reports into a single, high-level document suitable for clients or instructors
            - Structure:
            <h1>📄 Final Penetration Test Report</h1>
            <h2>1. Target Overview</h2>
            - Target URL, IP address, Date

            <h2>2. Reconnaissance Summary</h2>
            - Summarize ports, technologies, and sensitive paths
            - Short paragraph on what information an attacker could use from recon phase

            <h2>3. Vulnerabilities Identified</h2>
            - Critical findings only (SQLi, XSS, LFI, etc.)
            - One row per vuln: what it is, where it is, and why it’s dangerous

            <h2>4. Exploitation Results</h2>
            - Recap confirmed exploit paths
            - Emphasize business/security impact, such as "compromise of all user accounts", "leak of sensitive server files"

            <h2>5. Risk Assessment & Recommendations</h2>
            - Describe the real-world consequences of successful attacks
            - Provide remediation guidance:
                • Input validation and sanitization
                • Parameterized queries or ORM
                • Output encoding (for XSS)
                • Least privilege configuration
                • Apply WAF or security middleware
                • Regular updates and patching of frameworks
                • Disable directory listing and sensitive file exposure
            - Bullet-point summary is required for easy consumption

            ✅ Style:
            - Use `<h1>`, `<h2>`, `<ul>`, `<code>`, and custom CSS (soft background, clean fonts)
            - Suitable for print and PDF export for professional reporting

            ✅ Save each file with `save_report(<html>, "<filename>.html")`
            ✅ DO NOT skip saving. DO NOT return plain text.
            When you call save_report, pass ONLY a simple filename."final_report.html"
            After writing the report, you MUST call the `save_report` tool to save the file. Do not skip this step.
            After this agent exector, please send `TERMINATE`
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    final_report_writer.register_for_llm(name="save_report", description="Save the report")(save_report)
    final_report_writer.register_for_execution(name="save_report")(save_report)


    # VULN_TEAM
    # === Parameter-URL Extractor Agent ===
    param_agent = ConversableAgent(
        name="Param-URL-Extractor",
        system_message="""
        You're a parameterized-URL extractor. You take a base URL, auto-login and auto-submit forms,
        then return the final URL (which may include parameters). Use the analyze_form_and_capture_url tool.
        You should choose 10 url that can be vulnerability
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    param_agent.register_for_llm(
        name="analyze_form_and_capture_url",
        description="Analyze a webpage form and capture resulting URL."
    )(analyze_and_capture_url)
    param_agent.register_for_execution(
        name="analyze_form_and_capture_url",
        description="Analyze a webpage form and capture resulting URL."
    )(analyze_and_capture_url)

    # === Nuclei Agent ===
    nuclei_agent = ConversableAgent(
        name="Nuclei-Scanner",
        system_message="""
        You're a vulnerability scanning agent using Nuclei.
        You should choose 5 url that can be vulnerability
        You will be provided with a url in the /home/kali/Desktop/AI_4/captured_urls.txt:


        Your task:
        - Analyze the technologies and endpoints
        - Select appropriate **Nuclei tags** or templates for each endpoint
        - Using cookie header if you see it.
        - Using -tags instead of -t, using -silent at the end the command to Hide all [INF], [WRN], banner messages
        - Save output in pentest_results/vulnscan/nuclei_<name>.txt
        - Generate ONE command per endpoint:
        - You should choose sqli, xss, lfi,...
        - After complate nuclei please call `report-write` to summary the output of nuclei_agent
        - If there is url: http://localhost:8085/vulnerabilities/sqli_blind/  please skip it. 
        ```bash
        <command>
        ```
        - After this agent executor, please send `===vuln-scan done===`

        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )

    # === Exploit Generator ===
    exploit_agent = ConversableAgent(
        name="Exploit-Agent",
        system_message="""
    You're an exploit agent. You will be provided with a vulnerability summary report (SQLi, LFI, XSS,etc.).
    For each finding, generate ONE verification/exploitation command:
    - SQL Injection: use sqlmap to confirm and extract a single value (e.g., user()). Try to find the database or something else in database. Find all the data in that database. Using timeout 5 minutes to avoid wasting time.
    - LFI: use curl or wget to read sensitive files (e.g., /etc/passwd). After that use it to Take source code as an example. Privilege escalation,...
    - XSS: Create payload to test
    Return each command in its own bash block, redirect output to pentest_results/exploit/exploit_<type>_<name>.txt
    **IMPORTANT**: After running the command, you **must** call the `extract_sqlmap_summary` tool to summarize the raw sqli log.  
    """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    sql_summary = AssistantAgent(
    name="Extract_Sqlmap_Summary",
    system_message="Summarize result sqli file with the same name like the file name is:exploit_sqli_sqli.txt so you do the same name exploit_sqli_sqli.txt.After Extract_Sqlmap_Summary is done, call File-Reader to know which exploited",
    llm_config=llm_config,
    human_input_mode=interaction_mode,
    )
    sql_summary.register_for_llm(name="read_file", description="Summarize result sqli.")(extract_sqlmap_summary)
    sql_summary.register_for_execution(name="read_file", description="Summarize result sqli.")(extract_sqlmap_summary)

    pentest_team = GroupChat(
        agents=[user_proxy, nmap_agent, whatweb_agent, directory_scanner, param_agent,nuclei_agent,exploit_agent,file_reader,checker, code_executor,sql_summary, report_writer, final_report_writer],
        messages=[],
        max_round=35

    )
    manager = GroupChatManager(
        name="Pentest-Manager",
        groupchat=pentest_team,
        is_termination_msg=lambda msg: "TERMINATE" in msg["content"],
        llm_config=llm_config,
        system_message="""
        You are the Pentest Manager – responsible for orchestrating a full pentest workflow using AI agents.

        Your job is to coordinate each phase step-by-step and ensure data flows properly between agents.

        I created folder:
        "pentest_results",
        "pentest_results/recon",
        "pentest_results/vulnscan",
        "pentest_results/exploit",
        "pentest_results/reports"
        Follow this exact workflow:

        0. Initialization:
        - Use File-Reader to load the file `/home/kali/Desktop/AI_4/header.txt`
        - Extract any cookie/session header for authenticated scanning.

        1. Target Acquisition:
        - Ask User-Proxy to provide the target IP or URL
        Using Tool:
            - Nmap-Agent (port scan)
            - WhatWeb-Agent (technology fingerprinting)
            - Directory-Scanner (Gobuster for endpoint discovery)

        2. Reconnaissance Phase contains (in order):
        For each tool below:
            a. Ask the corresponding agent to generate the command.
            b. Send command to Code-Checker for validation.
            c. Ask User-Proxy to approve the command.
            d. Execute the command using Code-Executor.

        3. Recon Summary(Remember this step please):
        - After all 3 Recon agents(Nmap-Agent, WhatWeb-Agent, Directory-Scanner)finish, instruct Report-Writer to summarize their results.
        - Save the summary as: `recon_summary.html`

        4. Vulnerability Scanning Phase:
        a. Use Param-URL-Extractor to analyze forms and capture parameterized URLs.
        b. Provide extracted URLs to Nuclei-Scanner.
        c. Nuclei scans each URL using appropriate templates/tags.
        d. Save each result in `/pentest_results/vulnscan/nuclei_*.txt`

        5. Vulnerability Summary:
        - After scanning, instruct Report-Writer to write `vuln_summary` based on Nuclei output.
        - Save to: `vuln_summary.html`

        6. Exploitation Phase:
        a. Provide summary to Exploit-Agent.
        b. For each confirmed vulnerability (SQLi, LFI, XSS), generate 1 exploit command.
        c. Execute each and collect raw output.
        d. Use `extract_sqlmap_summary` (for SQLi) to parse key results.
        e. Using Read-File to read all the file you just exploit

        7. Exploit Summary:
        - Instruct Report-Writer to generate `exploit_summary` from all exploit results.
        - Save to: `exploit_summary.html`

        8. Final Report:
        - Call Final-Report-Writer to generate the final pentest report, combining:
            - Target info
            - Recon summary
            - Vulnerability summary
            - Exploitation results
            - Recommendations
        - Save the final report in `final_report.txt`

        9. Termination:
        - Ngay sau khi Report-Writer báo “Report saved to …/final_report.txt”,
        - Gửi duy nhất 1 tin nhắn:  `TERMINATE`

        **IMPORTANT: Summary the results after each phase: 
        - recon (nmap_agent, whatweb_agent, directory_scanner) save filename "recon_summary.html"
        - vuln (param_agent,nuclei_agent) save filename "vuln_summary.html"
        - exploit(exploit_agent) and post exploit(post_exploit_agent) save filename "exploit_summary.html"
        Terminate after run all of agent and complete the pentest workflow
        """

        
    )
    return {
        "manager": manager,
        "user_proxy": user_proxy,
        "team": pentest_team
    }
if __name__ == "__main__":
    ensure_directories()
    print("=== PENTESTING WORKFLOW ===")
    print("1. Reconnaissance")
    print("2. Vulnerability Scanning")
    print("3. Exploitation")
    print("3. Report")
    
# NHẬP URL từ người dùng
    target_url = input("Enter target URL (e.g., http://localhost:8085): ").strip()

    # lấy IP từ URL (nếu cần)
    target_ip = get_ip_from_url(target_url)

    pentest = pentest_team(llm_config, interaction_mode="NEVER")
    pentest["user_proxy"].initiate_chat(
        pentest["manager"],
        message=f"""Target site: {target_url} ({target_ip}).
Please start by reading /home/kali/Desktop/AI_4/header.txt using File-Reader to retrieve the cookie.
Then begin recon on this target."""
    )
    print("=== DONE ===")
