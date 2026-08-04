"""headers.py - checks for missing security headers and insecure cookies."""

CHECKED_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "No Content-Security-Policy header. CSP is the primary defence against XSS — "
        "it restricts which scripts, styles and resources the browser will execute.",
    ),
    "X-Frame-Options": (
        "Medium",
        "No X-Frame-Options header. The page may be embeddable in a hidden iframe, "
        "enabling clickjacking attacks.",
    ),
    "Strict-Transport-Security": (
        "Medium",
        "No HSTS header. Users may be downgraded to plain HTTP and exposed to MITM attacks.",
    ),
    "X-Content-Type-Options": (
        "Low",
        "No X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses, "
        "enabling content-type confusion attacks.",
    ),
    "Referrer-Policy": (
        "Low",
        "No Referrer-Policy. Full Referer URLs (including paths and query strings) "
        "may leak to third-party origins.",
    ),
    "Permissions-Policy": (
        "Low",
        "No Permissions-Policy header. Powerful browser features (camera, microphone, "
        "geolocation) are not explicitly restricted.",
    ),
    "Cross-Origin-Opener-Policy": (
        "Low",
        "No Cross-Origin-Opener-Policy header. The browsing context may be accessible "
        "to cross-origin pages, facilitating Spectre-style attacks.",
    ),
    "Cross-Origin-Resource-Policy": (
        "Low",
        "No Cross-Origin-Resource-Policy header. Resources may be loaded cross-origin "
        "without restriction.",
    ),
    "X-XSS-Protection": (
        "Info",
        "No X-XSS-Protection header (legacy IE header). Not critical in modern browsers "
        "but worth setting to '1; mode=block'.",
    ),
}


def run(client, url: str) -> list:
    findings = []
    resp = client.get(url)
    if resp is None:
        return findings
    hdrs = resp.headers

    for name, (severity, desc) in CHECKED_HEADERS.items():
        if name not in hdrs:
            findings.append({
                "type":     "Missing Security Header",
                "severity": severity,
                "url":      url,
                "location": name,
                "description": desc,
                "evidence": f"Header '{name}' absent from response.",
                "recommendation": f"Add the '{name}' response header with an appropriate policy.",
            })

    # Insecure cookie flags
    for sc in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")]:
        if not sc:
            continue
        lower = sc.lower()
        cookie_name = sc.split("=")[0].strip()
        for flag, sev, desc in [
            ("secure",   "Medium", "Cookie transmitted over plain HTTP may be intercepted."),
            ("httponly", "Medium", "Cookie readable via JavaScript — vulnerable to XSS token theft."),
            ("samesite", "Low",    "No SameSite attribute — weaker CSRF protection."),
        ]:
            if flag not in lower:
                findings.append({
                    "type":     "Insecure Cookie Flag",
                    "severity": sev,
                    "url":      url,
                    "location": f"Set-Cookie: {cookie_name}",
                    "description": desc,
                    "evidence": sc[:300],
                    "recommendation": f"Add the '{flag.capitalize()}' attribute to the Set-Cookie header.",
                })
    return findings
