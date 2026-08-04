"""tech_fingerprint.py - detect CMS, frameworks, languages and server tech."""
import re
import logging
from typing import Callable, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("webvulnscanner.tech")

# (header_name, regex_pattern, tech_label)
HEADER_SIGNATURES: list = [
    ("Server",                r"nginx",              "Nginx"),
    ("Server",                r"Apache",             "Apache"),
    ("Server",                r"Microsoft-IIS",      "IIS"),
    ("Server",                r"LiteSpeed",          "LiteSpeed"),
    ("Server",                r"cloudflare",         "Cloudflare"),
    ("X-Powered-By",          r"PHP/(.+)",           "PHP"),
    ("X-Powered-By",          r"ASP\.NET",           ".NET/ASP.NET"),
    ("X-Powered-By",          r"Express",            "Node.js/Express"),
    ("X-Powered-By",          r"Next\.js",           "Next.js"),
    ("X-Generator",           r"(.+)",               "CMS Generator"),
    ("X-Drupal-Cache",        r".*",                 "Drupal"),
    ("X-Joomla-Cache",        r".*",                 "Joomla"),
    ("X-Magento-Cache-Debug", r".*",                 "Magento"),
    ("CF-Ray",                r".*",                 "Cloudflare CDN"),
    ("X-Shopify-Stage",       r".*",                 "Shopify"),
    ("X-WP-Nonce",            r".*",                 "WordPress"),
]

# (cookie_name_pattern, tech_label)
COOKIE_SIGNATURES = [
    (r"PHPSESSID",       "PHP"),
    (r"ASP\.NET_SessionId", ".NET/ASP.NET"),
    (r"JSESSIONID",      "Java/JEE"),
    (r"laravel_session", "Laravel (PHP)"),
    (r"django",          "Django (Python)"),
    (r"flask",           "Flask (Python)"),
    (r"_rails",          "Ruby on Rails"),
    (r"wordpress_",      "WordPress"),
    (r"wp-settings",     "WordPress"),
    (r"Drupal\.visitor", "Drupal"),
]

# (regex_in_body, tech_label)
BODY_SIGNATURES = [
    (r"/wp-content/",            "WordPress"),
    (r"/wp-includes/",           "WordPress"),
    (r"wp-json",                 "WordPress REST API"),
    (r"Joomla!",                 "Joomla"),
    (r"/sites/default/files/",   "Drupal"),
    (r"Drupal\.settings",        "Drupal"),
    (r"content=\"Magento",       "Magento"),
    (r"Mage\.Cookies",           "Magento 1.x"),
    (r"shopify",                 "Shopify"),
    (r"cdn\.shopify\.com",       "Shopify"),
    (r"squarespace",             "Squarespace"),
    (r"wix\.com",                "Wix"),
    (r"webflow",                 "Webflow"),
    (r'"react"',                 "React"),
    (r"__NEXT_DATA__",           "Next.js"),
    (r"__nuxt",                  "Nuxt.js"),
    (r"ng-version=",             "Angular"),
    (r"vue\.js",                 "Vue.js"),
    (r"ember\.js",               "Ember.js"),
    (r"jQuery v",                "jQuery"),
    (r"jquery\.min\.js",         "jQuery"),
    (r"bootstrap\.min\.css",     "Bootstrap"),
    (r"tailwind",                "Tailwind CSS"),
    (r"laravel",                 "Laravel"),
    (r"django",                  "Django"),
    (r"flask",                   "Flask"),
    (r"rails",                   "Ruby on Rails"),
    (r"wp-login\.php",           "WordPress Login"),
]

# Known CVE-prone version patterns
VERSION_CHECKS = [
    (r"PHP/(\d+\.\d+)", "PHP"),
    (r"Apache/(\d+\.\d+\.\d+)", "Apache"),
    (r"nginx/(\d+\.\d+\.\d+)", "Nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)", "IIS"),
]


def run(target: str, progress_cb: Optional[Callable] = None) -> dict:
    log = progress_cb or (lambda m: None)
    log(f"[tech] Fingerprinting {target} ...")

    detected: dict[str, str] = {}   # label → evidence
    findings: list = []

    try:
        resp = requests.get(target, timeout=10, headers={
            "User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"
        })
    except Exception as e:
        log(f"[tech] Request failed: {e}")
        return {"technologies": [], "findings": []}

    headers = resp.headers
    body    = resp.text
    cookies = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())

    # Header signatures
    for hdr, pattern, label in HEADER_SIGNATURES:
        val = headers.get(hdr, "")
        if val:
            m = re.search(pattern, val, re.I)
            if m:
                evidence = f"{hdr}: {val}"
                detected[label] = evidence

    # Cookie signatures
    for pattern, label in COOKIE_SIGNATURES:
        if re.search(pattern, cookies, re.I):
            detected[label] = f"Cookie: {re.search(pattern, cookies, re.I).group()}"

    # Body signatures
    for pattern, label in BODY_SIGNATURES:
        if re.search(pattern, body, re.I):
            if label not in detected:
                detected[label] = f"Body pattern: {pattern}"

    # Version extraction → potential CVE hints
    server_header = headers.get("Server", "") + " " + headers.get("X-Powered-By", "")
    for pattern, tech in VERSION_CHECKS:
        m = re.search(pattern, server_header, re.I)
        if m:
            version = m.group(1)
            detected[f"{tech} {version}"] = f"Version disclosed: {m.group()}"
            # Flag outdated versions
            old = False
            if tech == "PHP" and version.startswith(("5.", "7.0", "7.1", "7.2", "7.3")):
                old = True
            elif tech == "Apache" and version.startswith("2.2"):
                old = True
            if old:
                findings.append({
                    "type":     f"Outdated {tech} Version Disclosed",
                    "severity": "Medium",
                    "url":      target,
                    "location": f"HTTP header",
                    "description": (
                        f"The server discloses it is running {tech} {version}, "
                        "which is outdated and may have known CVEs."
                    ),
                    "evidence":    m.group(),
                    "recommendation": f"Upgrade {tech} to the latest stable release and suppress version headers.",
                })

    # Flag WordPress admin exposure
    if "WordPress" in detected:
        try:
            wp_admin = requests.get(
                target.rstrip("/") + "/wp-login.php", timeout=5
            )
            if wp_admin.status_code == 200 and "wp-login" in wp_admin.text:
                findings.append({
                    "type":     "WordPress Login Page Exposed",
                    "severity": "Low",
                    "url":      target.rstrip("/") + "/wp-login.php",
                    "location": "/wp-login.php",
                    "description": "The WordPress admin login page is publicly accessible, facilitating brute-force attacks.",
                    "evidence":    "HTTP 200 at /wp-login.php",
                    "recommendation": "Restrict wp-login.php to authorised IPs or use two-factor authentication.",
                })
        except Exception:
            pass

    tech_list = [{"technology": k, "evidence": v} for k, v in detected.items()]
    log(f"[tech] Detected: {', '.join(detected.keys()) or 'nothing identified'}")

    return {"technologies": tech_list, "findings": findings}
