#web_form_analyzer.py
import os
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from autogen.agentchat import ConversableAgent

HEADER_FILE = "header.txt"
LOG_FILE = "captured_urls.txt"

def analyze_and_capture_url(base_url: str) -> str:
    """
    Mở trang bằng Playwright, load cookie, tự login (nếu cần),
    auto-fill form (text/hidden/select), submit, lưu kết quả vào file và trả về page.url sau cùng.
    """
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        # 1. Load cookie nếu có
        if os.path.exists(HEADER_FILE):
            raw = open(HEADER_FILE, "r", encoding="utf-8").read().strip()
            if raw.lower().startswith("cookie:"):
                raw = raw.split("Cookie:", 1)[1].strip()
            cookies = []
            for part in raw.split(";"):
                part = part.strip()
                if "=" not in part:
                    continue
                name, val = part.split("=", 1)
                cookies.append({
                    'name': name.strip(),
                    'value': val.strip(),
                    'url': base_url
                })
            if cookies:
                context.add_cookies(cookies)
        # 2. Mở page
        page = context.new_page()
        try:
            page.goto(base_url, timeout=5000)
        except PlaywrightTimeoutError:
            pass
        # 3. Tự login DVWA nếu gặp form login
        if page.query_selector("form[action*='login.php']"):
            page.fill("input[name='username']", "admin")
            page.fill("input[name='password']", "password")
            page.click("input[type='submit']")
            page.wait_for_load_state("networkidle")
            page.goto(base_url)
        # 4. Tìm và điền form
        form = page.query_selector("form")
        if form:
            # 4.1 Fill inputs
            for inp in form.query_selector_all("input[name]"):
                typ = (inp.get_attribute("type") or "text").lower()
                name = inp.get_attribute("name")
                if typ in ["text","hidden","search","email","url","number","password"]:
                    page.fill(f"input[name='{name}']", "1")
            # 4.2 Select dropdowns
            for sel in form.query_selector_all("select[name]"):
                name = sel.get_attribute("name")
                opts = sel.query_selector_all("option[value]")
                if opts:
                    page.select_option(f"select[name='{name}']", opts[0].get_attribute("value"))
            # 5. Submit form
            btn = form.query_selector("input[type='submit'],button[type='submit']")
            if btn:
                btn.click()
            else:
                page.evaluate("document.querySelector('form').submit()")
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except:
                pass
        # 6. Kết quả cuối cùng
        result_url = page.url
        browser.close()
    # 7. Lưu kết quả vào file (append)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(result_url + "\n")
    except Exception as e:
        print(f"[!] Error writing to log file {LOG_FILE}: {e}")
    return result_url


def create_web_form_analyzer_agent(llm_config):
    agent = ConversableAgent(
        name="Web-Form-Analyzer",
        system_message=(
            "You're a web form analyzer: given a URL, "
            "you fetch the page, load cookies (header.txt), "
            "auto-login if needed, fill & submit the form, "
            "save the final URL to a log file, and return it."
        ),
        llm_config=llm_config,
        human_input_mode="ALWAYS"
    )
    agent.register_for_execution(
        name="analyze_form_and_capture_url",
        description="Analyze a webpage form and capture resulting URL."
    )(analyze_and_capture_url)
    return agent

if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8085/vulnerabilities/xss_d/"
    print(f"[+] Testing URL: {test_url}")
    final = analyze_and_capture_url(test_url)
    print(f"[+] Captured final URL: {final}")
