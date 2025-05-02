import os
from autogen.agentchat import AssistantAgent, ConversableAgent, UserProxyAgent, GroupChat, GroupChatManager
from autogen.coding.local_commandline_code_executor import LocalCommandLineCodeExecutor
from reading_function import read_file
from report_save import save_report
from web_form_analyzer import analyze_and_capture_url


def create_vuln_team(llm_config, interaction_mode):    
    # Ensure output folder exists
    os.makedirs("pentest_results/vulnscan", exist_ok=True)

    # === Parameter-URL Extractor Agent ===
    param_agent = ConversableAgent(
        name="Param-URL-Extractor",
        system_message="""
        You're a parameterized-URL extractor. You take a base URL, auto-login and auto-submit forms,
        then return the final URL (which may include parameters). Use the analyze_form_and_capture_url tool.
        You should choose 5 url that can be vulnerability
        """,
        llm_config=llm_config,
        human_input_mode="NEVER"
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

    # === Command Checker ===
    checker = ConversableAgent(
        name="Command-Checker",
        system_message="You validate shell commands, ensuring output redirection to .txt files.",
        llm_config=llm_config,
        human_input_mode=interaction_mode
    )

    # === Code Executor ===
    executor = LocalCommandLineCodeExecutor(timeout=3600, work_dir=".")
    code_executor = AssistantAgent(
        name="Code-Executor",
        llm_config=False,
        code_execution_config={"executor": executor},
        human_input_mode=interaction_mode
    )

    # === File Reader ===
    file_reader = AssistantAgent(
        name="File-Reader",
        system_message="Reads scanner output files and returns their content.",
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

    # === Report Writer ===
    reporter = AssistantAgent(
        name="Report-Writer",
        system_message="Summarizes scanner results into bullet points. Always call saving-report after writing.",
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
        system_message="A human analyst supervising the scan. Approve commands before execution.",
        is_termination_msg=lambda msg: "TERMINATE" in msg["content"],
        code_execution_config={"work_dir": ".", "use_docker": False},
        human_input_mode=interaction_mode,
        llm_config=llm_config
    )

    # Collect all agents
    agents = [
        user_proxy,
        param_agent,
        nuclei_agent,
        checker,
        code_executor,
        file_reader,
        reporter
    ]

    # Create group chat
    vuln_team = GroupChat(
        agents=agents,
        messages=[{
            "name": user_proxy.name,
            "role": "user",
            "content": "Please provide the target base URL to extract parameterized URLs."
        }],
        max_round=100
    )

    # Manager to orchestrate the flow
    manager = GroupChatManager(
        name="Vuln-Manager",
        groupchat=vuln_team,
        llm_config=llm_config,
        system_message="""
    You're in charge of coordinating the vulnerability scan using Nuclei.

    1. Use Param-URL-Extractor to get 5 vulnerable URLs.
    2. Read recon report to understand target structure.
    3. Pass findings to Nuclei-Scanner, generate scan commands.
    4. Validate with Command-Checker.
    5. Have User-Proxy approve each command.
    6. Execute command with Code-Executor.
    7. Read output with File-Reader.
    8. Summarize findings with Report-Writer and save.

    ✅ After finishing all scanning and report saving, SEND "TERMINATE" to User-Proxy to end phase.
    """
    )


    return {
        "manager": manager,
        "user_proxy": user_proxy,
        "team": vuln_team
    }
