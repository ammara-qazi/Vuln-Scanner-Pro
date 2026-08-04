"""cors.py - CORS misconfiguration detection."""
import requests
from typing import Optional

EVIL_ORIGIN = "https://evil-attacker.com"


def run(client, target: str) -> list:
    findings = []
    try:
        # Test 1: reflect arbitrary origin
        r = requests.get(
            target,
            headers={"Origin": EVIL_ORIGIN},
            timeout=10,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*" and acac == "true":
            findings.append({
                "type":     "CORS Wildcard + Credentials (Critical Misconfiguration)",
                "severity": "Critical",
                "url":      target,
                "location": "CORS Headers",
                "description": (
                    "ACAO: * combined with ACAC: true is a critical misconfiguration. "
                    "Any website can make credentialed cross-origin requests and read responses. "
                    "Note: Browsers block this combination by spec, but some proxies/frameworks mishandle it."
                ),
                "evidence":    f"ACAO: {acao} | ACAC: {acac}",
                "recommendation": "Never combine ACAO:* with ACAC:true. Use explicit allowed origins.",
            })
        elif acao == EVIL_ORIGIN:
            if acac == "true":
                findings.append({
                    "type":     "CORS Origin Reflection + Credentials",
                    "severity": "Critical",
                    "url":      target,
                    "location": "CORS Headers",
                    "description": (
                        "The server reflects the attacker-supplied Origin header AND sets "
                        "Access-Control-Allow-Credentials: true, allowing any website to "
                        "make credentialed cross-origin requests and steal authenticated responses."
                    ),
                    "evidence":    f"ACAO: {acao} | ACAC: {acac}",
                    "recommendation": "Validate CORS origins against a strict allowlist. Never reflect arbitrary Origin values.",
                })
            else:
                findings.append({
                    "type":     "CORS Arbitrary Origin Reflected",
                    "severity": "Medium",
                    "url":      target,
                    "location": "CORS Headers",
                    "description": (
                        "The server reflects arbitrary Origin headers, allowing any website "
                        "to read non-credentialed cross-origin responses."
                    ),
                    "evidence":    f"ACAO: {acao}",
                    "recommendation": "Restrict CORS to explicitly allowed origins.",
                })
        elif acao == "*":
            findings.append({
                "type":     "CORS Wildcard Allow-Origin",
                "severity": "Low",
                "url":      target,
                "location": "CORS Headers",
                "description": (
                    "The server allows any origin to read responses (ACAO: *). "
                    "This is acceptable for truly public APIs but dangerous for authenticated endpoints."
                ),
                "evidence":    f"ACAO: *",
                "recommendation": "Ensure ACAO:* is only set on endpoints that should be publicly readable.",
            })

        # Test 2: null origin (can be sent by sandboxed iframes)
        r2 = requests.get(
            target,
            headers={"Origin": "null"},
            timeout=10,
        )
        acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "null":
            findings.append({
                "type":     "CORS Null Origin Accepted",
                "severity": "High",
                "url":      target,
                "location": "CORS Headers",
                "description": (
                    "The server allows CORS requests from Origin: null, which can be "
                    "sent by sandboxed iframes, local HTML files, or data: URIs, "
                    "potentially enabling cross-site data theft."
                ),
                "evidence":    f"ACAO: null (reflected)",
                "recommendation": "Do not allow 'null' as a trusted CORS origin.",
            })

    except Exception:
        pass
    return findings
