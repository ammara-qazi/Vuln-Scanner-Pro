"""ssrf.py - Server-Side Request Forgery (SSRF) detection."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional

# Parameters that commonly accept URLs / resource paths
URL_PARAMS = {
    "url", "uri", "link", "src", "source", "path", "file", "load",
    "fetch", "resource", "dest", "destination", "target", "redirect",
    "return", "next", "data", "img", "image", "feed", "ref", "page",
    "webhook", "callback", "host", "proxy", "remote",
}

# Internal SSRF canary payloads
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://169.254.169.254/",                         # Generic cloud metadata
    "http://metadata.google.internal/",                # GCP metadata
    "http://127.0.0.1/",                               # localhost
    "http://localhost/",                               # localhost alias
    "http://0.0.0.0/",                                # all interfaces
    "http://[::1]/",                                   # IPv6 localhost
    "http://2130706433/",                              # 127.0.0.1 decimal
    "http://0x7f000001/",                              # 127.0.0.1 hex
]

# Response patterns that indicate SSRF success
SSRF_SIGNATURES = [
    "ami-id", "instance-id", "instance-type", "placement",  # AWS
    "computeMetadata", "serviceAccounts",                     # GCP
    "MSI-APPID",                                              # Azure
    "root:x:0:0",                                            # /etc/passwd via 127.0.0.1
]


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        suspicious_params = [p for p in page.url_params
                             if p.lower() in URL_PARAMS]
        if not suspicious_params:
            continue
        if progress_cb:
            progress_cb(f"[ssrf] Testing {page.url}")

        parsed = urlparse(page.url)
        query  = parse_qs(parsed.query)

        for param in suspicious_params:
            for payload in SSRF_PAYLOADS:
                tq = {k: v[0] for k, v in query.items()}
                tq[param] = payload
                url  = urlunparse(parsed._replace(query=urlencode(tq)))
                resp = client.get(url)
                if resp is None:
                    continue
                body = resp.text
                for sig in SSRF_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "type":     "Server-Side Request Forgery (SSRF)",
                            "severity": "Critical",
                            "url":      page.url,
                            "location": f"GET parameter '{param}'",
                            "description": (
                                f"Parameter '{param}' causes the server to fetch an internal URL. "
                                "An attacker can probe internal services, cloud metadata, or internal APIs."
                            ),
                            "evidence":    f"Signature '{sig}' found when requesting '{payload}'",
                            "recommendation": (
                                "Validate and allowlist all server-side URL targets. "
                                "Block requests to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16."
                            ),
                            "test_url": url,
                        })
                        return findings  # stop at first confirmed SSRF

        # Also test forms with URL-like parameters
        for form in page.forms:
            url_inputs = [i for i in form["inputs"]
                          if i["name"].lower() in URL_PARAMS]
            for inp in url_inputs:
                for payload in SSRF_PAYLOADS[:3]:
                    data = {f["name"]: "test" for f in form["inputs"]}
                    data[inp["name"]] = payload
                    resp = (client.post(form["action"], data=data)
                            if form["method"] == "post"
                            else client.get(form["action"], params=data))
                    if resp is None:
                        continue
                    for sig in SSRF_SIGNATURES:
                        if sig in resp.text:
                            findings.append({
                                "type":     "Server-Side Request Forgery (SSRF)",
                                "severity": "Critical",
                                "url":      page.url,
                                "location": f"Form field '{inp['name']}' ({form['method'].upper()} {form['action']})",
                                "description": f"Form field '{inp['name']}' may be vulnerable to SSRF.",
                                "evidence":    f"Signature '{sig}' in response to payload '{payload}'",
                                "recommendation": "Allowlist all server-side URL targets; block internal ranges.",
                            })
    return findings
