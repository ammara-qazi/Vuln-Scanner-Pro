---
name: WebVulnScanner architecture
description: Key architectural decisions for the scanner app — scan job lifecycle, modules, report flow
---

**Scan jobs:** Held in a Python dict (JOBS) in memory. Each job runs in a background threading.Thread. Jobs are lost on server restart — this is intentional for the current single-user local-tool use case.

**Check modules:** 12 vuln checks in `core/checks/` + 4 recon modules in `core/` (dns_recon, port_scanner, ssl_check, tech_fingerprint). Each returns a list of finding dicts with keys: type, severity, url, location, description, evidence, recommendation.

**Reports:** Generated on first download request, cached as files in `artifacts/api-server/reports/`. Formats: JSON, TXT, HTML, DOCX.

**Frontend:** React+Vite at `/` (artifacts/vuln-scanner-ui). Polls GET /api/status/:id every 1200ms. No generated API hooks — uses raw fetch() calls. Green terminal aesthetic (#080d08 bg, #00ff41 primary green).

**Why no codegen:** Backend is Python Flask, not TypeScript/Express. The OpenAPI/Orval workflow only applies to the TS backend.
