"""ssl_check.py - SSL/TLS certificate and configuration inspection."""
import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger("webvulnscanner.ssl")

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


def run(target: str, progress_cb: Optional[Callable] = None) -> dict:
    log = progress_cb or (lambda m: None)
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    results: dict = {
        "host":          host,
        "port":          port,
        "tls_available": False,
        "certificate":   {},
        "protocol":      None,
        "cipher":        None,
        "days_until_expiry": None,
        "findings":      [],
    }

    if parsed.scheme != "https":
        # Still try port 443 for HTTPS availability
        port = 443

    log(f"[ssl] Connecting to {host}:{port} ...")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                results["tls_available"] = True
                cert = ssl_sock.getpeercert()
                cipher_info = ssl_sock.cipher()
                proto = ssl_sock.version()

                results["protocol"] = proto
                results["cipher"]   = cipher_info[0] if cipher_info else None

                log(f"[ssl] Protocol: {proto} | Cipher: {results['cipher']}")

                # Parse certificate
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                not_after  = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                san = [v for _, v in cert.get("subjectAltName", [])]

                results["certificate"] = {
                    "subject":       subject,
                    "issuer":        issuer,
                    "not_before":    not_before,
                    "not_after":     not_after,
                    "san":           san,
                    "serial_number": cert.get("serialNumber", ""),
                }

                # Expiry check
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days = (exp - now).days
                        results["days_until_expiry"] = days
                        log(f"[ssl] Certificate expires in {days} day(s)")

                        if days < 0:
                            results["findings"].append({
                                "type":     "Expired SSL Certificate",
                                "severity": "Critical",
                                "url":      f"https://{host}",
                                "location": "TLS Certificate",
                                "description": f"The SSL certificate expired {abs(days)} day(s) ago.",
                                "evidence":    f"notAfter: {not_after}",
                                "recommendation": "Renew the SSL certificate immediately.",
                            })
                        elif days < 14:
                            results["findings"].append({
                                "type":     "SSL Certificate Expiring Soon",
                                "severity": "High",
                                "url":      f"https://{host}",
                                "location": "TLS Certificate",
                                "description": f"The SSL certificate expires in {days} day(s).",
                                "evidence":    f"notAfter: {not_after}",
                                "recommendation": "Renew the SSL certificate before it expires.",
                            })
                        elif days < 30:
                            results["findings"].append({
                                "type":     "SSL Certificate Expiring Soon",
                                "severity": "Medium",
                                "url":      f"https://{host}",
                                "location": "TLS Certificate",
                                "description": f"The SSL certificate expires in {days} day(s).",
                                "evidence":    f"notAfter: {not_after}",
                                "recommendation": "Plan to renew the SSL certificate.",
                            })
                    except Exception:
                        pass

                # Self-signed check
                s_cn = subject.get("commonName", "")
                i_cn = issuer.get("commonName", "")
                if s_cn and s_cn == i_cn:
                    results["findings"].append({
                        "type":     "Self-Signed SSL Certificate",
                        "severity": "High",
                        "url":      f"https://{host}",
                        "location": "TLS Certificate",
                        "description": "The certificate is self-signed and not trusted by browsers.",
                        "evidence":    f"Subject CN == Issuer CN: {s_cn}",
                        "recommendation": "Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
                    })

                # Weak protocol
                if proto in WEAK_PROTOCOLS:
                    results["findings"].append({
                        "type":     f"Weak TLS Protocol: {proto}",
                        "severity": "High",
                        "url":      f"https://{host}",
                        "location": "TLS Configuration",
                        "description": f"The server negotiated {proto}, which is deprecated and insecure.",
                        "evidence":    f"Negotiated: {proto}",
                        "recommendation": "Disable TLS 1.0 and 1.1; use TLS 1.2+ only.",
                    })

                # Hostname mismatch
                try:
                    ssl.match_hostname(cert, host)
                except ssl.CertificateError as e:
                    results["findings"].append({
                        "type":     "SSL Hostname Mismatch",
                        "severity": "High",
                        "url":      f"https://{host}",
                        "location": "TLS Certificate",
                        "description": "The certificate common name does not match the server hostname.",
                        "evidence":    str(e),
                        "recommendation": "Obtain a certificate that covers this hostname.",
                    })

    except ssl.SSLError as e:
        log(f"[ssl] SSL error: {e}")
        results["findings"].append({
            "type":     "SSL Configuration Error",
            "severity": "Medium",
            "url":      f"https://{host}",
            "location": "TLS",
            "description": "An SSL error occurred when connecting.",
            "evidence":    str(e),
            "recommendation": "Review TLS configuration and certificate chain.",
        })
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        log(f"[ssl] Could not connect to {host}:{port}: {e}")
        if parsed.scheme == "https":
            results["findings"].append({
                "type":     "HTTPS Unreachable",
                "severity": "Medium",
                "url":      f"https://{host}:{port}",
                "location": "TLS",
                "description": f"Unable to establish a TLS connection to {host}:{port}.",
                "evidence":    str(e),
                "recommendation": "Verify TLS is configured and the certificate is valid.",
            })

    # HTTP but no HTTPS redirect
    if parsed.scheme == "http":
        try:
            import requests
            r = requests.get(target, timeout=5, allow_redirects=True)
            if not r.url.startswith("https://"):
                results["findings"].append({
                    "type":     "Missing HTTPS Redirect",
                    "severity": "Medium",
                    "url":      target,
                    "location": "HTTP",
                    "description": "The site is served over plain HTTP without redirecting to HTTPS.",
                    "evidence":    f"Final URL: {r.url}",
                    "recommendation": "Configure HTTP → HTTPS redirect and enable HSTS.",
                })
        except Exception:
            pass

    log(f"[ssl] {len(results['findings'])} SSL finding(s)")
    return results
