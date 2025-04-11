# vuln_team.py
import os
from autogen.agentchat import AssistantAgent, ConversableAgent, UserProxyAgent, GroupChat, GroupChatManager
from autogen.coding.local_commandline_code_executor import LocalCommandLineCodeExecutor
from reading_function import read_file
from report_save import save_report

def create_vuln_team(llm_config, interaction_mode="ALWAYS"):
    os.makedirs("pentest_results/vulnscan", exist_ok=True)

    # === Scanner Agents ===
    scanner_agents = []

    # Only Nuclei scanner is included in this setup
    tool_name = "Nuclei"
    template = "nuclei -u {url} -o pentest_results/vulnscan/nuclei_{name}.txt"

    nuclei_agent = ConversableAgent(
        name=f"{tool_name}-Scanner",
        system_message=f"""
        You're responsible for vulnerability scanning using {tool_name}.
        You will receive gobuster scan output and decide which endpoints are worth scanning.
        Then, generate one Nuclei command per URL:
        ```bash
        {template}
        ```
        Replace {{url}} with full URL, and {{name}} with sanitized endpoint name (like login, products).
        """,
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )
    scanner_agents.append(nuclei_agent)

    # === Utility Agents ===
    checker = ConversableAgent(
        name="Command-Checker",
        system_message="You check shell commands and make sure they are valid and redirect output to .txt files.",
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )

    executor = LocalCommandLineCodeExecutor(timeout=3600, work_dir=".")
    code_executor = AssistantAgent(
        name="Code-Executor",
        llm_config=False,
        code_execution_config={"executor": executor},
        human_input_mode="NEVER"
    )

    file_reader = AssistantAgent(
        name="File-Reader",
        system_message="Reads scanner output files.",
        llm_config=llm_config,
        human_input_mode="NEVER"
    )
    file_reader.register_for_llm(
        name="read_file",
        description="Read a scanner output file"
    )(read_file)
    file_reader.register_for_execution(
        name="read_file",
        description="Read a scanner output file"
    )(read_file)


    reporter = AssistantAgent(
        name="Report-Writer",
        system_message="Summarizes scanner results. Do not write code. Always call saving-report after writing.",
        llm_config=llm_config,
        human_input_mode="ALWAYS"
    )
    reporter.register_for_llm(
        name="saving-report",
        description="Save a scanner report"
    )(save_report)

    reporter.register_for_execution(
        name="saving-report",
        description="Save a scanner report"
    )(save_report)
    # === User Proxy ===
    user_proxy = UserProxyAgent(
        name="User-Proxy",
        system_message="A human analyst supervising the scan.",
        is_termination_msg=lambda msg: "TERMINATE" in msg["content"],
        code_execution_config={"work_dir": ".", "use_docker": False},
        human_input_mode=interaction_mode,
        llm_config=llm_config
    )

    # === GroupChat ===
    agents = [user_proxy] + scanner_agents + [checker, code_executor, file_reader, reporter]

    vuln_team = GroupChat(
        agents=agents,
        messages=[],
        max_round=100
    )

    manager = GroupChatManager(
        name="Vuln-Manager",
        groupchat=vuln_team,
        llm_config=llm_config,
        system_message="""
        You're in charge of coordinating the vuln scan.
        Steps:
        1. Read gobuster_scan.txt file.
        2. Send its content to Nuclei agent.
        3. Let Nuclei agent decide which endpoints are worth scanning.
        4. Nuclei agent outputs bash command for each target.
        5. Command-Checker approves.
        6. Code-Executor runs.
        8. Report-Writer summarizes and saves report.
        """
    )

    # === Give gobuster raw content to Nuclei agent ===
    if os.path.exists("pentest_results/recon/gobuster_scan.txt"):
        with open("pentest_results/recon/gobuster_scan.txt", "r", encoding="utf-8") as f:
            gobuster_content = f.read()

        vuln_team.messages.append({
            "name": nuclei_agent.name,
            "role": "user",
            "content": f"Here is the Gobuster output. Please extract the best endpoints to scan using Nuclei.\n\n```\n{gobuster_content}\n```"
        })

    return {
        "manager": manager,
        "user_proxy": user_proxy,
        "team": vuln_team
    }
