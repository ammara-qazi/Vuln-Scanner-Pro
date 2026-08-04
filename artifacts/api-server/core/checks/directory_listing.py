"""directory_listing.py - checks for enabled directory listing."""

DIR_LISTING_SIGS = [
    "<title>Index of /",
    "<h1>Index of /",
    "Parent Directory</a>",
    "Last modified</a>",
    "Directory listing for",
]

DIRS = [
    "/images/", "/uploads/", "/files/", "/css/", "/js/", "/static/",
    "/backup/", "/backups/", "/conf/", "/config/", "/data/", "/logs/",
    "/tmp/", "/temp/", "/assets/", "/media/", "/public/", "/private/",
    "/old/", "/archive/", "/bak/", "/test/", "/dev/", "/.git/",
]


def run(client, target: str) -> list:
    findings = []
    base = target.rstrip("/")
    for d in DIRS:
        url  = base + d
        resp = client.get(url)
        if not resp or resp.status_code != 200:
            continue
        body = resp.text
        for sig in DIR_LISTING_SIGS:
            if sig in body:
                findings.append({
                    "type":     "Directory Listing Enabled",
                    "severity": "Medium",
                    "url":      url,
                    "location": d,
                    "description": (
                        f"Directory listing is enabled at '{d}', exposing all files "
                        "in that directory to anyone."
                    ),
                    "evidence":    f"Signature: '{sig}'",
                    "recommendation": "Disable directory listing (e.g. 'Options -Indexes' in Apache or 'autoindex off' in Nginx).",
                })
                break
    return findings
