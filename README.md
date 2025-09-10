# 🔒 Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)  [![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A Python-based web vulnerability scanner designed to detect common security flaws such as **XSS, SQL Injection, Insecure Cookies, Missing Security Headers, and CSRF**.  

It uses **crawling + payload injection** techniques to discover vulnerabilities and provides a **Flask UI** for interaction. The scanner also integrates with **VirusTotal API** for malicious URL checks and generates reports in **JSON, CSV, HTML, and PDF** formats.

---

## 📑 Table of Contents
1. [Features](#-features)  
2. [Project Structure](#-project-structure)  
3. [Installation](#%EF%B8%8F-installation)
4. [Usage](#-usage)  
5. [Sample Results](#-sample-results)  
6. [Active Scans](#-active-scans)  
7. [Passive Scans](#%EF%B8%8F-passive-scans)  
8. [Dashboard](#-dashboard)  
9. [Roadmap](#-roadmap)  
10. [References](#-references)
11. [Disclaimer](#%EF%B8%8F-disclaimer)
12. [License](#-license)

---

## 🚀 Features

- 🌐 **Crawler**: Automatically extracts internal links, forms, cookies, and sessions.  
- 💉 **Payload Injection**: Tests parameters with crafted payloads.  
- 🔍 **Vulnerability Detection**:  
  - Cross-Site Scripting (**XSS**)  
  - SQL Injection (**SQLi**)  
  - Cross-Site Request Forgery (**CSRF**)  
  - Insecure Cookies  
  - Missing Security Headers  
- 📊 **Severity Classification**: Categorizes vulnerabilities (Low, Medium, High).  
- 🧾 **Flask Web Interface**: Start/stop scans, live logs, results table, and charts.  
- 🔎 **VirusTotal Integration**: Checks if a scanned URL is flagged as malicious.  
- 📁 **Reporting**: Export scan results to **JSON, CSV, HTML, or PDF**.  

---

## 📁 Project Structure

```
web_vuln_scanner/
├── app.py                  # Flask app (UI + routes)
├── Scanner/
│   ├── __init__.py
│   ├── crawler.py          # Crawling logic, link & form extraction
│   ├── activescan.py       # XSS, SQLi, CSRF, Header, Cookie detection
│   ├── payloads.py         # Injection payloads & severity mapping
│   ├── report.py           # Report generation (JSON/CSV/HTML/PDF)
│   └── logger.py           # Logging of vulnerabilities and evidence
├── templates/              # HTML templates (Flask UI)
├── requirements.txt        # Dependencies
└── README.md               # Documentation
```

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner

# (Optional) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Run the Flask scanner
python app.py

```

👉 Visit the web interface:  
[http://127.0.0.1:5000/](http://127.0.0.1:5000/)

---

## 🌐 Usage

1. Launch the Flask UI (`python app.py`).  
2. Enter the **target URL** and set scan depth.  
3. Click **Start Scan**.  
4. Watch **Live Logs** as vulnerabilities are detected.  
5. Review results in the **table & charts**.  
6. (Optional) Check URL reputation with **VirusTotal**.  
7. Export reports to **JSON, CSV, HTML, or PDF**.  

---

## 🧪 Sample Results

```json
"vulns": [
  {
    "type": "missing_security_headers",
    "url": "http://testphp.vulnweb.com",
    "evidence": "content-security-policy,x-frame-options,x-content-type-options,strict-transport-security,referrer-policy",
    "severity": "Low-Medium",
    "params": "None",
    "payload": "None"
  },
  {
    "type": "csrf_missing",
    "url": "http://testphp.vulnweb.com/search.php?test=query",
    "evidence": "Form on http://testphp.vulnweb.com missing anti-CSRF token",
    "severity": "Medium",
    "params": "searchFor,goButton",
    "payload": "None"
  },
  {
    "type": "xss",
    "url": "http://testphp.vulnweb.com/search.php?test=query",
    "evidence": "form reflected payload",
    "severity": "High",
    "params": "searchFor,goButton",
    "payload": "<script>alert(1)</script>"
  },
  {
    "type": "sqli",
    "url": "http://testphp.vulnweb.com/search.php?test=query",
    "evidence": "form reflected payload",
    "severity": "High",
    "params": "searchFor,goButton",
    "payload": "' OR '1'='1' -- "
  }
],
"meta": {
  "id": "66b2077b",
  "duration": 6.321440935134888
}
```

RESULTS:

<img width="1106" height="894" alt="image" src="https://github.com/user-attachments/assets/6f5c45f7-9734-41f7-97ac-d84cde5e1266" />
---
<img width="1078" height="788" alt="image" src="https://github.com/user-attachments/assets/5a563f92-1570-433f-88a9-a770bf1164a0" />


---

## 🔎 Active Scans

| Vulnerability     | Detection Method                                    | Severity |
| ----------------- | --------------------------------------------------- | -------- |
| XSS               | Reflection of payload in response text              | Medium   |
| SQL Injection     | SQL error patterns in response                      | High     |
| Command Injection | Response contains execution results (e.g., `uid=`)  | High     |
| Open Redirect     | Redirects to external URLs via vulnerable parameter | Medium   |

---

## 🛡️ Passive Scans

- **Security Headers**: CSP, X-Frame-Options, X-XSS-Protection, Strict-Transport-Security  
- **Cookies**: HttpOnly, Secure, SameSite flags  

---

## 📊 Dashboard

- **Live Logs**: Shows crawling & vulnerability findings in real-time.  
- **Charts**:  
  - Bar chart → Vulnerability counts by type  
  - Donut chart → Severity distribution  
- **Table**: Lists vulnerabilities with type, URL, parameter, payload, severity, and evidence.  
- **Reports**: Export to HTML or PDF with charts.  

---

## 📌 Roadmap

✅ XSS, SQLi, and CSRF detection  
✅ Web crawler with forms, cookies, and sessions  
✅ Flask-based UI with charts  
✅ VirusTotal API integration  
✅ JSON/CSV/HTML/PDF report export  


---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)  
- [BeautifulSoup Documentation](https://www.crummy.com/software/BeautifulSoup/)  
- [Flask Documentation](https://flask.palletsprojects.com/)  
- [VirusTotal API](https://developers.virustotal.com/reference/overview)  

---

## 🛡️ Disclaimer

This tool is intended for **educational and ethical testing purposes only**.  
⚠️ Do not use it on websites you do not own or do not have explicit permission to test.  

---

## 📜 License

This project is licensed under the **MIT License**.  
