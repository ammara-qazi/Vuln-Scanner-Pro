"""sqli.py - error-based + boolean-blind SQL injection detection."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='2", "' OR 1=1--"]
TRUE_PAYLOAD   = "' OR '1'='1"
FALSE_PAYLOAD  = "' OR '1'='2"

DB_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "sqlite_error",
    "pg_query()",
    "postgresql query failed",
    "ora-01756",
    "supplied argument is not a valid mysql",
    "syntax error at or near",
    "sqlstate[",
    "microsoft sql server",
    "odbc sql server driver",
    "mysql_fetch_array()",
]


def _find_sig(body: str) -> str:
    lower = body.lower()
    for sig in DB_ERROR_SIGS:
        if sig in lower:
            return sig
    return ""


def _submit(client, method, url, data):
    if method == "post":
        return client.post(url, data=data)
    return client.get(url, params=data)


def _test_params(client, page) -> list:
    findings = []
    if not page.url_params:
        return findings
    parsed = urlparse(page.url)
    query  = parse_qs(parsed.query)

    for param in page.url_params:
        # Error-based
        for payload in ERROR_PAYLOADS:
            tq = {k: v[0] for k, v in query.items()}
            tq[param] = payload
            url = urlunparse(parsed._replace(query=urlencode(tq)))
            resp = client.get(url)
            if resp is None:
                continue
            sig = _find_sig(resp.text)
            if sig:
                findings.append({
                    "type":     "SQL Injection (Error-Based)",
                    "severity": "Critical",
                    "url":      page.url,
                    "location": f"GET parameter '{param}'",
                    "description": f"Injecting '{payload}' into '{param}' triggered a database error.",
                    "evidence":    f"DB error signature detected: '{sig}'",
                    "recommendation": "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                    "test_url": url,
                })
                return findings  # one finding per page is enough

        # Boolean-blind
        base = {k: v[0] for k, v in query.items()}
        td = {**base, param: TRUE_PAYLOAD}
        fd = {**base, param: FALSE_PAYLOAD}
        r_t = client.get(urlunparse(parsed._replace(query=urlencode(td))))
        r_f = client.get(urlunparse(parsed._replace(query=urlencode(fd))))
        if r_t and r_f and abs(len(r_t.text) - len(r_f.text)) > 20:
            findings.append({
                "type":     "SQL Injection (Boolean-Based Blind)",
                "severity": "Critical",
                "url":      page.url,
                "location": f"GET parameter '{param}'",
                "description": f"Response length differs between TRUE/FALSE payloads for '{param}', indicating blind SQLi.",
                "evidence":    f"TRUE={len(r_t.text)}B vs FALSE={len(r_f.text)}B",
                "recommendation": "Use parameterised queries / prepared statements.",
            })
    return findings


def _test_forms(client, page) -> list:
    findings = []
    for form in page.forms:
        action, method, inputs = form["action"], form["method"], form["inputs"]
        for target_field in inputs:
            for payload in ERROR_PAYLOADS:
                data = {f["name"]: "1" for f in inputs}
                data[target_field["name"]] = payload
                resp = _submit(client, method, action, data)
                if resp is None:
                    continue
                sig = _find_sig(resp.text)
                if sig:
                    findings.append({
                        "type":     "SQL Injection (Error-Based)",
                        "severity": "Critical",
                        "url":      action,
                        "location": f"Form field '{target_field['name']}' ({method.upper()})",
                        "description": f"Injecting '{payload}' into '{target_field['name']}' triggered a database error.",
                        "evidence":    f"DB error signature: '{sig}'",
                        "recommendation": "Use parameterised queries / prepared statements.",
                    })
                    break

            # Boolean-blind on forms
            base = {f["name"]: "1" for f in inputs}
            td = {**base, target_field["name"]: TRUE_PAYLOAD}
            fd = {**base, target_field["name"]: FALSE_PAYLOAD}
            r_t = _submit(client, method, action, td)
            r_f = _submit(client, method, action, fd)
            if r_t and r_f and abs(len(r_t.text) - len(r_f.text)) > 20:
                findings.append({
                    "type":     "SQL Injection (Boolean-Based Blind)",
                    "severity": "Critical",
                    "url":      action,
                    "location": f"Form field '{target_field['name']}' ({method.upper()})",
                    "description": "Response length differs between TRUE/FALSE payloads.",
                    "evidence":    f"TRUE={len(r_t.text)}B vs FALSE={len(r_f.text)}B",
                    "recommendation": "Use parameterised queries / prepared statements.",
                })
    return findings


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        if progress_cb:
            progress_cb(f"[sqli] Testing {page.url}")
        findings.extend(_test_params(client, page))
        findings.extend(_test_forms(client, page))
    return findings
