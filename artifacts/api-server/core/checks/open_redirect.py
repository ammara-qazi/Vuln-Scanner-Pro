"""open_redirect.py - detects open redirect vulnerabilities."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Callable, Optional

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https:evil.com",
    "/%09/evil.com",
    "/\\evil.com",
]

REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "returnUrl", "return_url", "goto",
    "dest", "destination", "target", "link", "redir", "redirect_uri",
    "callback", "continue", "forward", "location", "back",
}


def run(client, pages, progress_cb: Optional[Callable] = None) -> list:
    findings = []
    for page in pages:
        if progress_cb:
            progress_cb(f"[redirect] Testing {page.url}")
        parsed = urlparse(page.url)
        query  = parse_qs(parsed.query)

        for param in page.url_params:
            for payload in REDIRECT_PAYLOADS:
                tq = {k: v[0] for k, v in query.items()}
                tq[param] = payload
                url = urlunparse(parsed._replace(query=urlencode(tq)))
                try:
                    resp = client.session.get(
                        url, timeout=client.timeout, allow_redirects=False
                    )
                except Exception:
                    continue
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "evil.com" in loc or loc.startswith("//evil"):
                        findings.append({
                            "type":     "Open Redirect",
                            "severity": "Medium",
                            "url":      page.url,
                            "location": f"GET parameter '{param}'",
                            "description": (
                                f"The application redirects to an attacker-controlled URL "
                                f"via the '{param}' parameter."
                            ),
                            "evidence":    f"Location: {loc}",
                            "recommendation": "Validate redirect targets against a strict allowlist or use relative paths only.",
                        })
                        break
    return findings
