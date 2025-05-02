import os
import socket
from urllib.parse import urlparse, parse_qs
from autogen.agentchat import AssistantAgent, ConversableAgent, UserProxyAgent, GroupChat, GroupChatManager
from autogen.coding.local_commandline_code_executor import LocalCommandLineCodeExecutor
from reading_function import read_file
from report_save import save_report
from web_form_analyzer import analyze_and_capture_url

#CONFIG
config_list = [
    {
        "api_type": "openai",
        "base_url": None,
        "api_key": "key_here",
        "model": "gpt-4.1",
        "price": [0.01, 0.03]
    }
]

llm_config = {
    "seed": 30,
    "config_list": config_list,
    "temperature": 0.1,
}
#interract
interaction_mode="ALWAYS"

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



def pentest_team(llm_config, interaction_mode="NEVER"):
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
            - The wordlist is **not fixed** — you may use `/home/kali/Desktop/AI_4/url_dvwa.txt`, `/usr/share/wordlists/dirb/common.txt`, `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`, or any appropriate wordlist based on the target.
            - Always redirect to file
            - Respond with one properly formatted command:
            ```bash
            <your_command> 
            ```
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    crawler_agent = ConversableAgent(
        name="Endpoint-Crawler",
        system_message="""
            You're in charge of crawling endpoints using Hakrawler.
            Use the `hakrawler` tool to discover URLs with parameters and endpoints.

            Requirements:
            - Depth of crawling should be at least 2
            - Save output to: `pentest_results/recon/hakrawler_scan.txt`
            - Only use hakrawler
            - Return only command inside:
            ```bash
            <command>
            ```
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    checker = ConversableAgent(
        name="Code-Checker",
        system_message="""
            You're a professional code checker, whose job is whenever a command or code is created before its run you should first, checking if the code is correct. if there is a typing mistake, an argument mistake, a language mistake, etc you should say something so that the code is rewritten by the agent who produced this code. Also check if the command was generated in the right format, with the specified language. The format should be:


            You may receive:
            1. A full command suggestion to validate
            2. A human natural language instruction like "scan only port 80"

            Your job:
            - If the user gives you natural language like "just scan 80", you must understand and rewrite the command properly.
            - If they send full command, validate syntax, flags, and output redirection .
            - Do not give the user like this 'Make sure that the directory exists before running this command to avoid any errors' (That is your job)
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
        system_message="A human security analyst overseeing the pentest operation. You must confirm commands after validation by Code-Checker before they are executed.",
        is_termination_msg=lambda msg: "TERMINATE" in msg["content"],
        code_execution_config={"work_dir": ".", "use_docker": False},
        human_input_mode=interaction_mode,
        llm_config=llm_config
    )
    user_proxy.register_for_execution(name="read_file")(read_file)


    report_writer = AssistantAgent(
        name="Report-Writer",
        system_message="""
            You're a professional security report writer.
            Remember to be specific. Always put the IP address or URL you scan on the first line.
            Summary the results

            After writing the report, you MUST call the `save_report` tool to save the file. Do not skip this step.
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    report_writer.register_for_llm(name="save_report", description="Save the final recon report")(save_report)
    report_writer.register_for_execution(name="save_report")(save_report)
    user_proxy.register_for_execution(name="save_report")(save_report)



    recon_summarizer = ConversableAgent(
        name="Recon-Summarizer",
        system_message="Analyze recon results, highlight key findings. ",
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )


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
    # register the tool both for LLm planning and execution
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
        You will be provided with a url in the /home/kali/Desktop/AI_3/captured_urls.txt:


        Your task:
        - Analyze the technologies and endpoints
        - Select appropriate **Nuclei tags** or templates for each endpoint
        - Using cookie header if you see it.
        - Save output in pentest_results/vulnscan/nuclei_<name>.txt
        - Generate ONE command per endpoint:
        ```bash
        <command>
        ```

        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )

    # === Exploit Generator ===
    exploit_agent = ConversableAgent(
        name="Exploit-Agent",
        system_message="""
    You're an exploit agent. You will be provided with a vulnerability summary report (SQLi, LFI, etc.).
    For each finding, generate ONE verification/exploitation command:
    - SQL Injection: use sqlmap to confirm and extract a single value (e.g., user()).
    - LFI: use curl or wget to read sensitive files (e.g., /etc/passwd).
    Return each command in its own bash block, redirect output to pentest_results/exploit/exploit_<type>_<name>.txt
    """,
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

    pentest_team = GroupChat(
        agents=[user_proxy, nmap_agent, whatweb_agent, directory_scanner, param_agent,nuclei_agent,exploit_agent,file_reader,checker, code_executor, report_writer],
        messages=[],
        max_round=50
    )
    manager = GroupChatManager(
        name="Recon-Manager",
        groupchat=pentest_team,
        llm_config=llm_config,
        system_message="""
        You are the manager of the pentest team.
        Your role is to coordinate a precise and complete  phase.

        Follow these exact steps:
        0. Use File-Reader to load header.txt.
        1. Ask for target (e.g., IP or URL).
        2. For each tool below, generate command -> validate with Code-Checker -> approve -> execute -> read result:
            - Nmap-Agent
            - WhatWeb-Agent
            - Directory-Scanner
        3 Save report `recon`
        3. Run nuclei to scan the vulnerable and save report `vuln_scan`
        4. Exploit the vulnerable and save report `exploit`
        5. Write the final report (summary).
        This message will end the recon phase.
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
    
    pentest = pentest_team(llm_config, interaction_mode="ALWAYS")
    pentest["user_proxy"].initiate_chat(
        pentest["manager"],
        message="Please start by reading /home/kali/Desktop/AI_3/header.txt using File-Reader to retrieve the cookie. After that, ask for the Target URL or IP. The URL is : localhost:8085"
    )
