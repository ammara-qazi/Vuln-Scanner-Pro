"""cmdi.py - command injection detection (error-based + time-based blind)."""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional

# Error-based payloads and response signatures
ERROR_PAYLOADS = [
    (";id;",           ["uid=", "gid="]),
    ("| id",           ["uid=", "gid="]),
    ("& whoami",       ["root", "www-data", "apache", "nginx", "nobody"]),
    ("`id`",           ["uid=", "gid="]),
    ("$(id)",          ["uid=", "gid="]),
    ("; cat /etc/passwd", ["root:x:0:0:"]),
    ("| cat /etc/passwd", ["root:x:0:0:"]),
    ("& type C:\\Windows\\win.ini &", ["[extensions]"]),
]

# Time-based blind payload
SLEEP_PAYLOAD = "; sleep 5 ;"
SLEEP_THRESHOLD = 4.0  # seconds


def _test_error(client, url_or_form, param_or_field, is_form, form=None) -> dict:
    for payload, sigs in ERROR_PAYLOADS:
        if is_form:
            data = {f["name"]: "test" for f in form["inputs"]}
            data[param_or_field] = payload
            method = form["method"]
            url = form["action"]
            resp = (client.post(url, data=data) if method == "post"
                    else client.get(url, params=data))
        else:
            parsed = urlparse(url_or_form)
            query  = parse_qs(parsed.query)
            tq = {k: v[0] for k, v in query.items()}
            tq[param_or_field] = payload
            resp = client.get(urlunparse(parsed._replace(query=urlencode(tq))))

        if resp is None:
            continue
        body = resp.text
        for sig in sigs:
            if sig in body:
                return {
                    "payload":   payload,
                    "signature": sig,
                }
    return {}


def _test_time_based(client, url_or_form, param_or_field, is_form, form=None) -> bool:
    try:
        if is_form:
            data = {f["name"]: "test" for f in form["inputs"]}
            data[param_or_field] = SLEEP_PAYLOAD
            method = form["method"]
            url = form["action"]
            start = time.time()
            resp = (client.post(url, data=data) if method == "post"
                    else client.get(url, params=data))
        else:
            parsed = urlparse(url_or_form)
            query  = parse_qs(parsed.query)
            tq = {k: v[0] for k, v in query.items()}
            tq[param_or_field] = SLEEP_PAYLOAD
            start = time.time()
            resp = client.get(urlunparse(parsed._replace(query=urlencode(tq))))
        elapsed = time.time() - start
        return elapsed >= SLEEP_THRESHOLD
    except Exception:
        return False


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        has_params = bool(page.url_params)
        has_forms  = bool(page.forms)
        if not has_params and not has_forms:
            continue
        if progress_cb:
            progress_cb(f"[cmdi] Testing {page.url}")

        # Test URL params
        for param in page.url_params:
            hit = _test_error(client, page.url, param, False)
            if hit:
                findings.append({
                    "type":     "Command Injection (Error-Based)",
                    "severity": "Critical",
                    "url":      page.url,
                    "location": f"GET parameter '{param}'",
                    "description": f"Parameter '{param}' executes OS commands — response contained '{hit['signature']}'.",
                    "evidence":    f"Payload: {hit['payload']} → response contained: {hit['signature']}",
                    "recommendation": "Never pass user input to OS commands. Use safe APIs instead.",
                })
                continue
            if _test_time_based(client, page.url, param, False):
                findings.append({
                    "type":     "Command Injection (Time-Based Blind)",
                    "severity": "Critical",
                    "url":      page.url,
                    "location": f"GET parameter '{param}'",
                    "description": f"Parameter '{param}' caused a {SLEEP_THRESHOLD}s+ response delay with a sleep payload.",
                    "evidence":    f"Payload: {SLEEP_PAYLOAD}",
                    "recommendation": "Never pass user input to OS commands. Use safe APIs instead.",
                })

        # Test form fields
        for form in page.forms:
            for field in form["inputs"]:
                hit = _test_error(client, None, field["name"], True, form)
                if hit:
                    findings.append({
                        "type":     "Command Injection (Error-Based)",
                        "severity": "Critical",
                        "url":      page.url,
                        "location": f"Form field '{field['name']}' ({form['method'].upper()} {form['action']})",
                        "description": f"Field '{field['name']}' executes OS commands.",
                        "evidence":    f"Payload: {hit['payload']} → signature: {hit['signature']}",
                        "recommendation": "Never pass user input to OS commands.",
                    })

    return findings
