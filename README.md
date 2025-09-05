# Web Application Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A powerful **Web Application Scanner** for detecting vulnerabilities like **XSS, SQL Injection, Command Injection, and Open Redirect** in URLs and forms. It supports both static and dynamic web pages, with optional **Playwright rendering** for JavaScript-heavy pages.  

---

## Table of Contents
1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Scanning Workflow](#scanning-workflow)
5. [Active Scans](#active-scans)
6. [Passive Scans](#passive-scans)
7. [Reports](#reports)
8. [License](#license)

---

## Features
- Crawls and scans websites with depth and page limits.
- Detects vulnerabilities in URL parameters and forms:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Command Injection
  - Open Redirect
- Supports **dynamic content rendering** via Playwright.
- Passive scanning for:
  - Security headers
  - Cookie flags
- Logs vulnerabilities in a structured format with severity levels.
- Easily extensible for adding new payloads or scan types.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/webapp-scanner.git
cd webapp-scanner
```



2. Create a virtual environment and install dependencies:
```
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
pip install -r requirements.txt

```
pip install playwright
playwright install


## USAGE

from Scanner.scanner import Scanner

# Initialize scanner
scanner = Scanner(
    start_url="http://example.com",
    max_depth=2,
    max_pages=100,
    force_dynamic="auto"  # options: 'always', 'never', 'auto'
)

# Run scan
scanner.run()

# Access results
print(scanner.vulns)  # List of detected vulnerabilities



## Scanning Workflow

1. Crawling
   Starts at start_url.
   Collects links and forms recursively within the same domain.
   Handles both GET and POST forms.
2. Dynamic Rendering
   Optional Playwright browser rendering for JavaScript-heavy pages.
   Captures dynamic content and cookies.
3. Active Scanning
   Injects payloads into URL parameters and form inputs.
   Detects XSS, SQLi, Command Injection, Open Redirect.
4. Passive Scanning
   Checks for missing security headers (CSP, X-Frame-Options, etc.)
   Checks cookies for secure and HttpOnly flags.


##  Active scan
| Vulnerability     | Detection Method                                    | Severity |
| ----------------- | --------------------------------------------------- | -------- |
| XSS               | Reflection of payload in response text              | Medium   |
| SQL Injection     | SQL error patterns in response                      | High     |
| Command Injection | Response contains execution results (e.g., `uid=`)  | High     |
| Open Redirect     | Redirects to external URLs via vulnerable parameter | Medium   |

## Passive Scans

Security Headers: CSP, X-Frame-Options, X-XSS-Protection, Strict-Transport-Security.

Cookies: HttpOnly, Secure, SameSite flags.


## Reports
Vulnerabilities are stored in a structured Python list.
Each vulnerability includes:
- Type
- URL
- Evidence
- Severity
- Parameter

Optional: You can extend the scanner to export HTML or PDF reports with charts.

## License

This project is licensed under the MIT License
