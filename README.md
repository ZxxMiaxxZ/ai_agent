# 🔐 AI-Powered Penetration Testing Agent (AG2-based)

This project automates web application penetration testing using AI agents orchestrated via the [AG2](https://github.com/ag2ai/ag2) framework. It supports reconnaissance, vulnerability scanning, exploitation, and reporting phases — all coordinated by intelligent agents.

---

## 🚀 Features

- ✅ Auto login + form analysis using Playwright (v1). In v2 (interact_web) it like "browser-use" agent. 
- 🔎 Reconnaissance: Nmap, Gobuster, WhatWeb
- 🛡️ Vulnerability scan: Nuclei with auto URL + cookie injection
- 💥 Exploitation: SQLi, LFI, XSS with sqlmap and curl
- 🧠 Agent coordination with AG2 (multi-agent orchestration)
- 📄 Final report auto-generated after each test (in html)
- 🔁 Modular and easy to extend new tools

---

## 🛠 Installation

### 1. Clone the repo
git clone https://github.com/ZxxMiaxxZ/ai_agent

### 2. Install Python dependencies
pip install -r requirements.txt
playwright install
### 3. Install external CLI tools (required)
sudo apt update
sudo apt install nmap gobuster whatweb sqlmap
sudo snap install nuclei

### 4. Test with dvwa
docker pull vulnerables/web-dvwa
docker run -d -p 8085:80 --name dvwa vulnerables/web-dvwa

### 5. Pentest process with security low (in setting dvwa)
Access the web and take the cookie 
Cookie: PHPSESSID=<your_session>; security=low

Save it in header.txt




