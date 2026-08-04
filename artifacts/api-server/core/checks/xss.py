"""xss.py - reflected XSS detection via marker payload reflection."""
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional


def _payloads():
    tok = uuid.uuid4().hex[:8]
    return [
        f"<script>alert('WVS_{tok}')</script>",
        f"\"'><svg onload=alert('WVS_{tok}')>",
        f"<img src=x onerror=alert('WVS_{tok}')>",
        f"javascript:alert('WVS_{tok}')",
        f"'><details open ontoggle=alert('WVS_{tok}')>",
    ]


def _reflected(body: str, payload: str) -> bool:
    return payload in body


def _test_params(client, page) -> list:
    findings = []
    if not page.url_params:
        return findings
    parsed = urlparse(page.url)
    query  = parse_qs(parsed.query)
    for param in page.url_params:
        for payload in _payloads():
            tq = {k: v[0] for k, v in query.items()}
            tq[param] = payload
            url = urlunparse(parsed._replace(query=urlencode(tq)))
            resp = client.get(url)
            if resp and _reflected(resp.text, payload):
                findings.append({
                    "type":     "Reflected Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "url":      page.url,
                    "location": f"GET parameter '{param}'",
                    "description": f"Parameter '{param}' is reflected without HTML-encoding.",
                    "evidence":    f"Payload reflected verbatim: {payload}",
                    "recommendation": "HTML-encode all user-controlled output; implement a strong CSP.",
                    "test_url": url,
                })
                break
    return findings


def _test_forms(client, page) -> list:
    findings = []
    for form in page.forms:
        action, method, inputs = form["action"], form["method"], form["inputs"]
        for target_field in inputs:
            for payload in _payloads():
                data = {f["name"]: "test" for f in inputs}
                data[target_field["name"]] = payload
                resp = (client.post(action, data=data)
                        if method == "post"
                        else client.get(action, params=data))
                if resp and _reflected(resp.text, payload):
                    findings.append({
                        "type":     "Reflected/Stored Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "url":      page.url,
                        "location": f"Form field '{target_field['name']}' ({method.upper()} {action})",
                        "description": f"Field '{target_field['name']}' reflects payload without encoding.",
                        "evidence":    f"Payload reflected: {payload}",
                        "recommendation": "HTML-encode output; validate and sanitise all input.",
                    })
                    break
    return findings


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        if progress_cb:
            progress_cb(f"[xss] Testing {page.url}")
        findings.extend(_test_params(client, page))
        findings.extend(_test_forms(client, page))
    return findings
