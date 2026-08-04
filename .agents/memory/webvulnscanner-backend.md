---
name: WebVulnScanner backend
description: Python Flask backend for WebVulnScanner — critical config quirks to know before editing
---

The API server is Python Flask, not TypeScript/Express. The artifact.toml was updated to run:
`cd /home/runner/workspace/artifacts/api-server && pip install -r requirements.txt -q && python app.py`

**Why absolute path:** The managed workflow runs from a different CWD than `/home/runner/workspace`, so `cd artifacts/api-server` fails silently with "No such file or directory". Always use the full absolute path in the run command.

**How to apply:** Any future changes to the api-server run command in artifact.toml must use the absolute path `/home/runner/workspace/artifacts/api-server`.

All Flask routes are mounted under `/api` to match the reverse proxy path. The artifact.toml paths entry is `["/api"]`.
