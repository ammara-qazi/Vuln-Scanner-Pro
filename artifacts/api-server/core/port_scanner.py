"""port_scanner.py - lightweight TCP port scanner for common web ports."""
import socket
import logging
from typing import Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger("webvulnscanner.ports")

# Common ports with service labels
PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP Submission",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    3000:  "Dev Server",
    3306:  "MySQL",
    3389:  "RDP",
    4200:  "Angular Dev",
    4443:  "Alt HTTPS",
    5000:  "Dev Server",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8000:  "HTTP Alt",
    8080:  "HTTP Proxy/Dev",
    8443:  "HTTPS Alt",
    8888:  "Jupyter",
    9000:  "PHP-FPM/Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# Ports that indicate serious exposure if open
SENSITIVE_PORTS = {21, 23, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 1433, 445}


def run(target: str, progress_cb: Optional[Callable] = None) -> dict:
    log = progress_cb or (lambda m: None)
    parsed = urlparse(target)
    host = parsed.hostname or target

    open_ports = []
    log(f"[ports] Scanning {host} ({len(PORTS)} common ports)...")

    for port, service in PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                risk = "High" if port in SENSITIVE_PORTS else "Info"
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "risk":    risk,
                })
                log(f"[ports] OPEN {port}/{service}")
        except Exception as e:
            logger.debug("Port %d scan error: %s", port, e)

    findings = []
    for entry in open_ports:
        if entry["risk"] == "High":
            findings.append({
                "type":     f"Exposed Sensitive Service: {entry['service']}",
                "severity": "High",
                "url":      f"tcp://{host}:{entry['port']}",
                "location": f"Port {entry['port']}/{entry['service']}",
                "description": (
                    f"Port {entry['port']} ({entry['service']}) is publicly accessible. "
                    "Database, remote-access and internal services should not be exposed to the internet."
                ),
                "evidence":        f"TCP connect to {host}:{entry['port']} succeeded",
                "recommendation": (
                    "Restrict this service with a firewall. "
                    "Do not expose database or admin services to untrusted networks."
                ),
            })

    log(f"[ports] {len(open_ports)} open port(s) found")
    return {
        "host":       host,
        "open_ports": open_ports,
        "findings":   findings,
    }
