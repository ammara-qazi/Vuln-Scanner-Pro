# WebVulnScanner

A browser-based web vulnerability assessment tool for authorized offensive security testing. Enter a target URL, run a full suite of scans, watch live terminal output, and download detailed findings reports.

## Run & Operate

- API server runs automatically via workflow: `artifacts/api-server: API Server`
- Frontend runs automatically via workflow: `artifacts/vuln-scanner-ui: web`
- API available at `/api` — proxied to port 8080 (Flask/Python)
- Frontend at `/` — Vite React app (port assigned by workflow)

## Stack

- **Frontend:** React + Vite + Tailwind (artifacts/vuln-scanner-ui) — green terminal aesthetic
- **Backend:** Python 3.11 + Flask (artifacts/api-server) — pure JSON API
- **Scanner modules:** beautifulsoup4, requests, lxml, dnspython, python-docx
- pnpm workspaces, Node.js 24, TypeScript 5.9 (for frontend)

## Where things live

- `artifacts/api-server/app.py` — Flask app, all API routes
- `artifacts/api-server/core/checks/` — individual vuln check modules
- `artifacts/api-server/core/dns_recon.py` — DNS reconnaissance
- `artifacts/api-server/core/port_scanner.py` — TCP port scanner
- `artifacts/api-server/core/ssl_check.py` — SSL/TLS inspection
- `artifacts/api-server/core/tech_fingerprint.py` — tech detection
- `artifacts/api-server/core/report_writer.py` — JSON/TXT/HTML/DOCX export
- `artifacts/vuln-scanner-ui/src/` — React frontend (green terminal theme)

## Architecture decisions

- Python Flask chosen as backend (user's original tool was Flask/Python)
- No database — scan jobs live in-memory (fine for single-user local tool)
- All API routes under `/api` prefix matching the reverse proxy path
- Jobs run in background threads; frontend polls `/api/status/:id` every 1.2s
- Reports written to `artifacts/api-server/reports/` on first download request

## Product

**12 vulnerability checks:** Security Headers, Server Info Disclosure, Directory Listing, Sensitive File Exposure, Open Redirect, LFI, XSS, SQL Injection, CORS Misconfiguration, SSRF, Command Injection, Clickjacking

**4 recon modules:** DNS Enumeration (subdomains + records + zone transfer test), Port Scanner (20 common ports), SSL/TLS Inspector (cert expiry, weak protocols, self-signed), Technology Fingerprinting (CMS/framework/language detection)

**Report exports:** JSON, TXT, HTML, DOCX (Word)

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

_Populate as you build — sharp edges, "always run X before Y" rules._

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
