"""server_info.py - flags information-disclosing headers and verbose error signatures."""
import re

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Runtime", "X-Version",
]
VERSION_RE = re.compile(r"\d+\.\d+")

ERROR_SIGNATURES = [
    ("PHP Warning",                     "PHP"),
    ("PHP Fatal error",                  "PHP"),
    ("PHP Parse error",                  "PHP"),
    ("Stack trace:",                     "Generic"),
    ("at System.",                       ".NET"),
    ("Microsoft OLE DB Provider",        ".NET/SQL Server"),
    ("Traceback (most recent call last)","Python"),
    ("Django Version",                   "Django"),
    ("Whitelabel Error Page",            "Spring Boot"),
    ("java.lang.",                       "Java"),
    ("javax.servlet",                    "Java Servlet"),
    ("RuntimeError",                     "Ruby/Python"),
    ("ActionController::",               "Ruby on Rails"),
]


def run(client, url: str) -> list:
    findings = []
    resp = client.get(url)
    if resp is None:
        return findings

    for hdr in INFO_HEADERS:
        val = resp.headers.get(hdr)
        if not val:
            continue
        has_version = bool(VERSION_RE.search(val))
        findings.append({
            "type":     "Server Information Disclosure",
            "severity": "Medium" if has_version else "Low",
            "url":      url,
            "location": f"HTTP header: {hdr}",
            "description": (
                f"The '{hdr}' header exposes server software details, helping attackers "
                "fingerprint known CVEs."
            ),
            "evidence":    f"{hdr}: {val}",
            "recommendation": f"Suppress or genericise the '{hdr}' header.",
        })

    body = resp.text or ""
    for sig, tech in ERROR_SIGNATURES:
        if sig in body:
            findings.append({
                "type":     "Verbose Error / Stack Trace Disclosure",
                "severity": "Medium",
                "url":      url,
                "location": "Response body",
                "description": (
                    f"Response contains a {tech} error/stack trace, potentially leaking "
                    "internal file paths, class names, or query text."
                ),
                "evidence":    f"Matched: '{sig}'",
                "recommendation": "Disable debug/verbose error output in production.",
            })
    return findings
