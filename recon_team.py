import os
import socket
from urllib.parse import urlparse, parse_qs
from autogen.agentchat import AssistantAgent, ConversableAgent, UserProxyAgent, GroupChat, GroupChatManager
from autogen.coding.local_commandline_code_executor import LocalCommandLineCodeExecutor
from reading_function import read_file
from report_save import save_report

def get_ip_from_url(url):
    try:
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error resolving IP: {str(e)}"



def create_recon_team(llm_config, interaction_mode="NEVER"):
    os.makedirs("pentest_results/recon", exist_ok=True)

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
    user_proxy.register_for_execution(name="save_report")(save_report)
    user_proxy.register_for_execution(name="read_file")(read_file)


    report_writer = AssistantAgent(
        name="Report-Writer",
        system_message="""
            You're a professional security report writer.
            Remember to be specific. Always put the IP address or URL you scan on the first line.
            Your task is to generate a **summary report** from the reconnaissance phase of a pentest. This summary must include findings from:
            1. **Nmap** (open ports, services, OS info)
            2. **WhatWeb** (web technologies used)
            3. **Gobuster** (directories/files discovered)
           
            *Remember*
            Do not write any command or suggest any tool.
            Use bullet point format for clarity.
            Group findings by tool name.
            At the end of your report, suggest **general next steps** (e.g., "Proceed to vulnerability scanning").

            After writing the report, you MUST call the `save_report` tool to save the file. Do not skip this step.
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    report_writer.register_for_llm(name="save_report", description="Save the final recon report")(save_report)
    report_writer.register_for_execution(name="save_report")(save_report)


    recon_summarizer = ConversableAgent(
        name="Recon-Summarizer",
        system_message="Analyze recon results, highlight key findings. ",
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )


    recon_team = GroupChat(
        agents=[user_proxy, file_reader, nmap_agent,checker, code_executor, whatweb_agent, directory_scanner, report_writer],
        messages=[],
        max_round=50
    )
    recon_manager = GroupChatManager(
        name="Recon-Manager",
        groupchat=recon_team,
        llm_config=llm_config,
        system_message="""
        You are the manager of the reconnaissance team.
        Your role is to coordinate a precise and complete recon phase.

        You MUST follow this strict sequence of actions for each tool:
        0. Reading header.txt to get cookie.
        1. Ask for target IP/URL.
        2. Nmap-Agent generate command ➔ Code-Checker ➔ User-Proxy approve ➔ Code-Executor run.
        3. WhatWeb-Agent same flow.
        4. Directory-Scanner same flow.
        5. Endpoint-Crawler same flow.
        6. After all tools done, call Report-Writer to summarize recon results.
        7. After Report-Writer finishes:
        - Send message "TERMINATE" to User-Proxy to end recon phase.
        ✅ No tool should be skipped.
        """
)   




    return {
        "manager": recon_manager,
        "team": recon_team,
        "user_proxy": user_proxy,
        "agents": {
            "nmap": nmap_agent,
            "directory": directory_scanner,
            "whatweb": whatweb_agent,
            "checker": checker,
            "executor": code_executor,
            "report_writer": report_writer,
        }
    }
