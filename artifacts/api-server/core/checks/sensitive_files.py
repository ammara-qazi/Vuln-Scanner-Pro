"""sensitive_files.py - checks for exposed sensitive files and admin panels."""

SENSITIVE_PATHS = [
    # Secrets and configs
    (".env",                        "Environment file (likely contains secrets)",   "Critical"),
    (".env.local",                  "Local environment file",                        "Critical"),
    (".env.production",             "Production environment file",                   "Critical"),
    (".env.backup",                 "Environment backup file",                       "Critical"),
    (".git/config",                 "Git configuration",                             "High"),
    (".git/HEAD",                   "Git HEAD pointer",                              "High"),
    (".git/COMMIT_EDITMSG",         "Git commit message",                            "Medium"),
    (".svn/entries",                "SVN entries file",                              "High"),
    (".htaccess",                   "Apache htaccess configuration",                 "Medium"),
    (".htpasswd",                   "Apache htpasswd (credential hashes)",           "Critical"),
    ("phpinfo.php",                 "PHP configuration info",                        "Medium"),
    ("config.php.bak",              "PHP config backup",                             "High"),
    ("config.php~",                 "PHP config backup (tilde)",                     "High"),
    ("wp-config.php.bak",           "WordPress config backup",                       "High"),
    ("wp-config.old",               "WordPress config old",                          "High"),
    (".ssh/id_rsa",                 "Private SSH key",                               "Critical"),
    (".ssh/id_dsa",                 "Private DSA key",                               "Critical"),
    ("id_rsa",                      "Private SSH key (root)",                         "Critical"),
    ("backup.sql",                  "Database backup",                               "High"),
    ("backup.tar.gz",               "Archive backup",                                "High"),
    ("dump.sql",                    "Database dump",                                 "High"),
    ("database.sql",                "Database file",                                 "High"),
    ("data.sql",                    "Database data",                                 "High"),
    ("server-status",               "Apache server status",                          "Low"),
    ("server-info",                 "Apache server info",                            "Low"),
    ("crossdomain.xml",             "Flash cross-domain policy",                     "Low"),
    ("clientaccesspolicy.xml",      "Silverlight access policy",                     "Low"),
    ("robots.txt",                  "Robots exclusion (may reveal hidden paths)",    "Info"),
    ("sitemap.xml",                 "Sitemap (reveals site structure)",              "Info"),
    # Admin panels
    ("admin/",                      "Admin panel",                                   "Medium"),
    ("admin.php",                   "Admin panel (PHP)",                             "Medium"),
    ("admin/login",                 "Admin login",                                   "Medium"),
    ("administrator/",              "Admin panel (Joomla-style)",                    "Medium"),
    ("wp-admin/",                   "WordPress admin",                               "Medium"),
    ("phpmyadmin/",                 "phpMyAdmin",                                    "High"),
    ("phpmyadmin",                  "phpMyAdmin (no trailing slash)",                "High"),
    ("pma/",                        "phpMyAdmin (alias)",                            "High"),
    ("cpanel",                      "cPanel hosting panel",                          "Medium"),
    ("webmail",                     "Webmail interface",                             "Low"),
]

FALSE_POSITIVE_SIGS = ["404", "not found", "page not found", "does not exist"]


def run(client, target: str) -> list:
    findings = []
    base = target.rstrip("/") + "/"
    for path, desc, severity in SENSITIVE_PATHS:
        url  = base + path
        resp = client.get(url)
        if not resp or resp.status_code not in (200, 403):
            continue
        if resp.status_code == 403:
            # 403 on admin paths is still interesting
            if "admin" in path or "phpmyadmin" in path or "cpanel" in path:
                findings.append({
                    "type":     "Admin Panel Detected (Access Restricted)",
                    "severity": "Low",
                    "url":      url,
                    "location": f"Path: /{path}",
                    "description": f"An admin interface was found at '{path}' (HTTP 403 — access restricted).",
                    "evidence":    f"HTTP 403 at {url}",
                    "recommendation": "Ensure admin interfaces are protected by IP allow-listing and MFA.",
                })
            continue
        body = resp.text
        if len(body) < 10:
            continue
        body_lower = body.lower()
        if any(sig in body_lower for sig in FALSE_POSITIVE_SIGS) and len(body) < 2000:
            continue
        label = "Sensitive File Disclosed" if "admin" not in path else "Admin Panel Exposed"
        findings.append({
            "type":     label,
            "severity": severity,
            "url":      url,
            "location": f"Path: /{path}",
            "description": f"'{path}' is publicly accessible. {desc}.",
            "evidence":    f"HTTP 200 OK — {len(body)} byte(s) returned",
            "recommendation": "Remove or restrict access to sensitive files from the web root.",
        })
    return findings
