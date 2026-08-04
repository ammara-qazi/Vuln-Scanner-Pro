"""clickjacking.py - checks for missing frame protection and meta frame-busting."""
import re
from typing import Optional


def run(client, target: str) -> list:
    findings = []
    resp = client.get(target)
    if resp is None:
        return findings

    headers = resp.headers
    body    = resp.text or ""

    xfo = headers.get("X-Frame-Options", "").upper()
    csp = headers.get("Content-Security-Policy", "")

    has_xfo              = bool(xfo and xfo in ("DENY", "SAMEORIGIN"))
    has_csp_frame        = bool(re.search(r"frame-ancestors", csp, re.I))
    has_js_frame_buster  = bool(re.search(r"(top\.location|self\s*!==?\s*top|window\.top)", body, re.I))

    if not has_xfo and not has_csp_frame:
        findings.append({
            "type":     "Clickjacking Vulnerability",
            "severity": "Medium",
            "url":      target,
            "location": "HTTP response headers",
            "description": (
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set. "
                "The page can be embedded in a hidden iframe on an attacker-controlled site, "
                "tricking users into clicking UI elements they cannot see."
            ),
            "evidence":    (
                f"X-Frame-Options: {'(absent)' if not xfo else xfo} | "
                f"CSP frame-ancestors: {'(absent)' if not has_csp_frame else '(present)'}"
            ),
            "recommendation": (
                "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use "
                "Content-Security-Policy: frame-ancestors 'self'."
            ),
        })
    elif xfo and xfo not in ("DENY", "SAMEORIGIN"):
        findings.append({
            "type":     "Misconfigured X-Frame-Options",
            "severity": "Low",
            "url":      target,
            "location": "X-Frame-Options header",
            "description": (
                f"X-Frame-Options is set to '{xfo}', which may not be a valid or effective value."
            ),
            "evidence":    f"X-Frame-Options: {xfo}",
            "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
        })

    if has_js_frame_buster and not has_xfo and not has_csp_frame:
        findings.append({
            "type":     "JavaScript-Only Frame Busting (Insufficient)",
            "severity": "Info",
            "url":      target,
            "location": "Response body",
            "description": (
                "JavaScript frame-busting code was detected, but JavaScript-only protection "
                "can be bypassed using sandbox attributes. Use HTTP headers instead."
            ),
            "evidence":    "top.location / window.top check in page source",
            "recommendation": "Replace or supplement JavaScript frame-busting with X-Frame-Options or CSP frame-ancestors.",
        })

    return findings
