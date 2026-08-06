# Vuln-Scanner-Pro 

<p align="center">
  <strong>A Modern Web Vulnerability Scanner for Security Testing & Reconnaissance</strong>
</p>

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

python app.py
```

---

## Start the Frontend

```bash
cd artifacts/api-server/vuln-scanner-ui
pnpm --filter @workspace/vuln-scanner-ui run dev
or
pnpm dev
```

---

# Screenshots

Add screenshots here after publishing.

Example:

```
docs/images/dashboard.png
docs/images/results.png
docs/images/report.png
```

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
