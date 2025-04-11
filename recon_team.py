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

def normalize_hakrawler_urls(file_path="pentest_results/recon/hakrawler_scan.txt") -> list:
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    normalized = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("http"):
            continue
        parsed = urlparse(line)
        path = parsed.path
        query = parse_qs(parsed.query)
        if query:
            parts = [f"{k}=*" for k in sorted(query.keys())]
            pattern = f"{path}?" + "&".join(parts)
        else:
            pattern = path
        normalized.add(pattern)

    return sorted(normalized)

def create_recon_team(llm_config, interaction_mode="ALWAYS"):
    os.makedirs("pentest_results/recon", exist_ok=True)

    nmap_agent = ConversableAgent(
        name="Nmap-Agent",
        system_message="""
            You're a cybersecurity professional specialized in reconnaissance using Nmap.
            You are responsible for discovering open ports and running services using `nmap`. Use flags appropriate for a full scan.
            You must redirect output to a file located at: `pentest_results/recon/nmap_scan.txt`.

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

            Guidelines:
            - Only use Gobuster
            - The wordlist is **not fixed** — you may use `/usr/share/wordlists/dirb/common.txt`, `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`, or any appropriate wordlist based on the target.
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
            - If they send full command, validate syntax, flags, and output redirection.

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
    #file_reader.register_for_llm(name="read_file", description="Read a scan result file")(read_file)

    user_proxy = UserProxyAgent(
        name="User-Proxy",
        system_message="A human security analyst overseeing the pentest operation. You must confirm commands after validation by Code-Checker before they are executed.",
        code_execution_config={"work_dir": ".", "use_docker": False},
        human_input_mode=interaction_mode,
        llm_config=llm_config
    )
    user_proxy.register_for_execution(name="save_report")(save_report)
    #user_proxy.register_for_execution(name="read_file")(read_file)


# 4. **Hakrawler** (endpoints with query parameters, if any)
    report_writer = AssistantAgent(
        name="Report-Writer",
        system_message="""
            You're a professional security report writer.

            Your task is to generate a **summary report** from the reconnaissance phase of a pentest. This summary must include findings from:
            1. **Nmap** (open ports, services, OS info)
            2. **WhatWeb** (web technologies used)
            3. **Gobuster** (directories/files discovered)
           

            🛑 Do not write any command or suggest any tool.
            ✅ Use bullet point format for clarity.
            ✅ Group findings by tool name.
            ✅ At the end of your report, suggest **general next steps** (e.g., "Proceed to vulnerability scanning").

            After writing the report, you MUST call the `save_report` tool to save the file. Do not skip this step.
        """,
        llm_config=llm_config,
        human_input_mode="ALWAYS",
    )
    report_writer.register_for_llm(name="save_report", description="Save the final recon report")(save_report)
    report_writer.register_for_execution(name="save_report")(save_report)


    recon_summarizer = ConversableAgent(
        name="Recon-Summarizer",
        system_message="Analyze recon results, highlight key findings.",
        llm_config=llm_config,
        human_input_mode=interaction_mode,
    )

# crawler_agent,file_reader,

    recon_team = GroupChat(
        agents=[user_proxy, nmap_agent, whatweb_agent, directory_scanner,
                checker, code_executor, report_writer,  recon_summarizer],
        messages=[],
        max_round=50
    )
    #
#         The summary MUST use `normalize_hakrawler_urls()` to include Hakrawler endpoints at the end.
        # ⛔ After each execution:
        # 5.5 You MUST immediately call the File-Reader to read the output file (e.g., `nmap_scan.txt`, `whatweb_scan.txt`, etc).
        # 🟢 When calling File-Reader, clearly specify the filename. File-Reader will show raw results.



        # ⛔ Do NOT move to the next tool until the result from File-Reader has been shown and understood.
        # You are the one who must make sure that agents do NOT get confused about whether a tool has been executed or not.

# and File-Reader has read each output,
# 🛑 NEVER skip the File-Reader step even if the command executed with exitcode 0 and no error.
    recon_manager = GroupChatManager(
        name="Recon-Manager",
        groupchat=recon_team,
        llm_config=llm_config,
        system_message="""
        You are the manager of the reconnaissance team.
        Your role is to coordinate a precise and complete recon phase.

        You MUST follow this strict sequence of actions for each tool:

        1. Ask the user (User-Proxy) to provide the target (IP or URL).
        2. Nmap-Agent generates a command for Nmap.
        3. Pass the command to Code-Checker for syntax validation.
        4. Ask User-Proxy to approve the validated command.
        5. If approved, forward the command to Code-Executor to run.
        6. Repeat the same process (steps 2–5) for each of these agents:
            - WhatWeb-Agent
            - Directory-Scanner
            - Endpoint-Crawler


        7. After all 4 tools have been executed call the Report-Writer agent.

        8. The Report-Writer must generate a recon summary.
  

        9. Once the report is written, you MUST call `save_report` to save it in the recon folder.

        ✅ You are responsible for making sure that **no tool is skipped**, **every output file is processed**, and **results are visible**.

       
    """
)




#            "file_reader": file_reader
#            "crawler": crawler_agent,
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
