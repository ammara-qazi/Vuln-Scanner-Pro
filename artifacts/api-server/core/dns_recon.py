"""dns_recon.py - DNS reconnaissance: records, subdomains, zone-transfer test."""
import socket
import logging
from typing import Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger("webvulnscanner.dns")

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "test", "portal", "admin", "beta", "cdn", "media", "static", "assets",
    "app", "help", "support", "docs", "git", "gitlab", "jenkins", "jira",
    "confluence", "login", "auth", "sso", "vpn2", "cloud", "s3",
]


def _hostname(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target
    return host.lower()


def _resolve(hostname: str):
    try:
        info = socket.getaddrinfo(hostname, None)
        return list({i[4][0] for i in info})
    except Exception:
        return []


def run(target: str, progress_cb: Optional[Callable] = None) -> dict:
    log = progress_cb or (lambda m: None)
    host = _hostname(target)
    results: dict = {
        "hostname": host,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "subdomains_found": [],
        "zone_transfer": [],
        "findings": [],
    }

    log(f"[dns] Resolving A records for {host} ...")
    results["a_records"] = _resolve(host)
    if results["a_records"]:
        log(f"[dns] A: {', '.join(results['a_records'])}")

    # DNS record lookups with dnspython
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        import dns.exception

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        for rtype in ("MX", "NS", "TXT", "CNAME"):
            try:
                answers = resolver.resolve(host, rtype)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                results[f"{rtype.lower()}_records"] = records
                log(f"[dns] {rtype}: {len(records)} record(s)")
            except Exception:
                pass

        # Zone transfer test (AXFR) - will usually fail (good)
        ns_list = results.get("ns_records", [])
        for ns in ns_list[:2]:
            ns_host = ns.rstrip(".")
            try:
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns_host, host, timeout=3, lifetime=5)
                )
                names = [str(n) for n in z.nodes.keys()][:20]
                results["zone_transfer"] = names
                results["findings"].append({
                    "type": "DNS Zone Transfer Enabled",
                    "severity": "High",
                    "url": f"dns://{host}",
                    "location": f"NS: {ns_host}",
                    "description": (
                        f"The nameserver '{ns_host}' allows zone transfers (AXFR), "
                        "exposing the full DNS zone including internal hostnames."
                    ),
                    "evidence": f"Zone contains {len(names)} name(s): {', '.join(names[:5])}",
                    "recommendation": "Restrict zone transfers to authorised secondary nameservers only.",
                })
                log(f"[dns] ZONE TRANSFER SUCCESS on {ns_host} — {len(names)} names")
            except Exception:
                pass

    except ImportError:
        log("[dns] dnspython not installed — skipping MX/NS/TXT/zone-transfer")

    # Subdomain enumeration
    log(f"[dns] Enumerating {len(COMMON_SUBDOMAINS)} common subdomains...")
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{host}"
        ips = _resolve(fqdn)
        if ips:
            found.append({"subdomain": fqdn, "ips": ips})
            log(f"[dns] Found: {fqdn} → {', '.join(ips)}")

    results["subdomains_found"] = found
    if found:
        log(f"[dns] {len(found)} subdomain(s) discovered")

    # Check for DNS rebinding / wildcard
    try:
        wildcard_ips = _resolve(f"nonexistent-wvs-{host}")
        if wildcard_ips:
            results["findings"].append({
                "type": "Wildcard DNS Record",
                "severity": "Low",
                "url": f"dns://{host}",
                "location": f"*.{host}",
                "description": "A wildcard DNS record resolves all subdomains, which can aid attackers in enumerating the domain.",
                "evidence": f"*.{host} resolves to {', '.join(wildcard_ips)}",
                "recommendation": "Remove wildcard DNS records unless intentionally required.",
            })
            log(f"[dns] Wildcard DNS detected: *.{host} → {wildcard_ips}")
    except Exception:
        pass

    return results
