<p align="center">
  <img src="https://github.com/user-attachments/assets/1cc0270c-a135-4eac-862e-43de6d6ff015" width="50%">
</p>

  
 ![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
 ![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react)
 ![Flask](https://img.shields.io/badge/Backend-Flask-black?style=for-the-badge&logo=flask)
 ![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?style=for-the-badge&logo=typescript)
 ![MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)


> [!WARNING]
>
> **Vuln-Scanner-Pro is currently under development.**
>
> Some features may still be under development, and bugs or unexpected behavior may occur.
>
> If you encounter an issue, please open a GitHub Issue with steps to reproduce it.


  A browser-based web vulnerability assessment tool with a live terminal-style feed.Built with <b>React</b> and <b>Python</b>,  Enter a target URL, run a full suite of security checks, watch progress in real time, and download a detailed findings report.

## Disclaimer

This tool is intended **only for authorized security testing, educational purposes, and research**.

Do **not** scan websites, servers, or networks without explicit permission from the owner.

The author is **not responsible** for any misuse of this software.

---

# Features

## Vulnerability Detection

- Security Headers Analysis
- Server Information Disclosure
- Directory Listing Detection
- Sensitive File Exposure (e.g. exposed .git, backup files, config files)
- Open Redirect Detection
- Local File Inclusion (LFI)
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Cross-Origin Resource Sharing (CORS) Misconfiguration
- Server-Side Request Forgery (SSRF)
- Command Injection Detection
- Clickjacking Detection

---

## Reconnaissance

- DNS Enumeration
- Port Scanning
- SSL/TLS Certificate Analysis
- Technology Fingerprinting

---

## Report Generation

Generate reports in multiple formats:

- JSON
- TXT
- HTML
- Microsoft Word (.docx)
---

# Tech Stack

| Layer | Stack |
|---|---|
| Scan engine / API | Python |
| Frontend | React + TypeScript, Vite, Tailwind |
| API contracts | OpenAPI spec with generated TypeScript/Zod clients |
| Database layer | Drizzle ORM |
| Monorepo tooling | pnpm workspaces |
| Python Libraries | requests - beautifulsoup4 - lxml - dnspython - python-docx |

---

# Project Structure

```
Vuln-Scanner-Pro
│
├── artifacts
│   ├── api-server
│   └── vuln-scanner-ui
│
├── lib
│
├── scripts
│
├── package.json
├── pnpm-workspace.yaml
└── README.md
```

---

# Installation

## Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Vuln-Scanner-Pro.git
cd Vuln-Scanner-Pro
```

---

## Install Frontend Dependencies

```bash
pnpm install
```

---

## Install Backend Dependencies

```bash
cd artifacts/api-server

pip install -r requirements.txt
```

---

# Running the Project

## Start the Backend

```bash
cd artifacts/api-server

PORT=8080 python app.py
```

---

## Start the Frontend

```bash
cd artifacts/api-server/vuln-scanner-ui
PORT=5173 BASE_PATH=// pnpm run dev
```

---

# Screenshots

## Dashboard

<p align="center">
<img src="docs/images/dashboard.png" width="900">
</p>

---

## Live Scan

<p align="center">
<img src="docs/images/terminal.png" width="900">
</p>

---

## Scan Results

<p align="center">
<img src="docs/images/results.png" width="900">
</p>

---

## Report

<p align="center">
<img src="docs/images/report.png" width="900">
</p>

---

# Future Improvements

- Authentication
- User accounts
- Scheduled scans
- Crawl depth configuration
- Additional vulnerability modules
- Export to PDF
- CVSS scoring
- OWASP Top 10 mapping
- Plugin architecture

---

# License

This project is licensed under the MIT License.

---

# Contributing

Contributions, feature requests, and bug reports are welcome.

Please open an Issue before submitting major changes.

---

# Author

**Ammara**

Cybersecurity Student

Ethical Hacking • Penetration Testing • Secure Software Development


