#!/usr/bin/env python3
"""
app.py - Flask backend for WebVulnScanner.
All routes are under /api prefix (matched by the reverse proxy).
"""
import os
import time
import uuid
import threading
import logging
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS

from core.http_client import RateLimitedClient
from core.crawler import Crawler
from core.checks import headers as headers_check
from core.checks import server_info as server_info_check
from core.checks import xss as xss_check
from core.checks import sqli as sqli_check
from core.checks import open_redirect as open_redirect_check
from core.checks import directory_listing as directory_listing_check
from core.checks import sensitive_files as sensitive_files_check
from core.checks import lfi as lfi_check
from core.checks import cors as cors_check
from core.checks import ssrf as ssrf_check
from core.checks import cmdi as cmdi_check
from core.checks import clickjacking as clickjacking_check
from core import dns_recon
from core import port_scanner
from core import ssl_check
from core import tech_fingerprint
from core import report_writer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("webvulnscanner")

try:
    import docx  # noqa
except ImportError:
    logger.warning("python-docx not installed - DOCX reports disabled")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(APP_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app, origins="*")

JOBS: dict = {}
JOBS_LOCK = threading.Lock()

CHECK_RUNNERS = {
    "headers":           lambda c, t, p, l: headers_check.run(c, t),
    "server-info":       lambda c, t, p, l: server_info_check.run(c, t),
    "directory-listing": lambda c, t, p, l: directory_listing_check.run(c, t),
    "sensitive-files":   lambda c, t, p, l: sensitive_files_check.run(c, t),
    "open-redirect":     lambda c, t, p, l: open_redirect_check.run(c, p, progress_cb=l),
    "lfi":               lambda c, t, p, l: lfi_check.run(c, p, progress_cb=l),
    "xss":               lambda c, t, p, l: xss_check.run(c, p, progress_cb=l),
    "sqli":              lambda c, t, p, l: sqli_check.run(c, p, progress_cb=l),
    "cors":              lambda c, t, p, l: cors_check.run(c, t),
    "ssrf":              lambda c, t, p, l: ssrf_check.run(c, p, progress_cb=l),
    "cmdi":              lambda c, t, p, l: cmdi_check.run(c, p, progress_cb=l),
    "clickjacking":      lambda c, t, p, l: clickjacking_check.run(c, t),
}

CHECK_LABELS = {
    "headers":           "Security Headers",
    "server-info":       "Server Info Disclosure",
    "directory-listing": "Directory Listing",
    "sensitive-files":   "Sensitive Files",
    "open-redirect":     "Open Redirect",
    "lfi":               "Local File Inclusion (LFI)",
    "xss":               "Cross-Site Scripting (XSS)",
    "sqli":              "SQL Injection",
    "cors":              "CORS Misconfiguration",
    "ssrf":              "SSRF",
    "cmdi":              "Command Injection",
    "clickjacking":      "Clickjacking",
}

RECON_RUNNERS = {
    "dns":   lambda t, l: dns_recon.run(t, progress_cb=l),
    "ports": lambda t, l: port_scanner.run(t, progress_cb=l),
    "ssl":   lambda t, l: ssl_check.run(t, progress_cb=l),
    "tech":  lambda t, l: tech_fingerprint.run(t, progress_cb=l),
}


def _validate_target(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parsed.netloc:
        return "URL must include a hostname"
    return None


def _run_job(job_id, target, delay, max_depth, max_pages, checks, recon_modules, cookie, timeout):
    def log(msg):
        with JOBS_LOCK:
            JOBS[job_id]["log"].append(msg)
            JOBS[job_id]["stage"] = msg
        logger.info("[%s] %s", job_id, msg)

    try:
        log(f"[*] Target: {target}")
        client = RateLimitedClient(delay=delay, timeout=timeout, cookie=cookie)

        # Recon phase
        recon_results: dict = {}
        if recon_modules:
            log("[*] Starting reconnaissance phase...")
        for mod_id in recon_modules:
            if mod_id not in RECON_RUNNERS:
                continue
            log(f"[~] Recon/{mod_id.upper()} ...")
            try:
                recon_results[mod_id] = RECON_RUNNERS[mod_id](target, log)
                count = (
                    len(recon_results[mod_id])
                    if isinstance(recon_results[mod_id], list)
                    else len(recon_results[mod_id].get("findings", []))
                )
                log(f"[+] Recon/{mod_id.upper()} complete — {count} result(s)")
            except Exception as e:
                logger.error("Recon %s failed: %s", mod_id, e)
                log(f"[!] Recon/{mod_id.upper()} error: {e}")
                recon_results[mod_id] = {"error": str(e), "findings": []}

        # Crawl
        log("[*] Crawling target — discovering pages, forms and parameters...")
        crawler = Crawler(client, target, max_depth=max_depth, max_pages=max_pages, progress_cb=log)
        pages = crawler.crawl()
        log(f"[+] Crawl complete — {len(pages)} page(s) discovered")

        # Vulnerability checks
        all_findings: list = []
        for check_id in checks:
            if check_id not in CHECK_RUNNERS:
                continue
            label = CHECK_LABELS.get(check_id, check_id)
            log(f"[~] Testing: {label} ...")
            try:
                found = CHECK_RUNNERS[check_id](client, target, pages, log)
                all_findings.extend(found)
                status = f"VULNERABLE ({len(found)} finding(s))" if found else "clean"
                marker = "[!]" if found else "[+]"
                log(f"{marker} {label}: {status}")
            except Exception as e:
                logger.error("Check %s failed: %s", check_id, e)
                log(f"[!] {label}: error — {e}")

        sorted_findings = report_writer.sort_findings(all_findings)
        stats = {
            "pages_crawled": len(pages),
            "checks_run":    len(checks),
            "recon_modules": len(recon_modules),
            "total_findings": len(all_findings),
        }
        sev_summary = report_writer.severity_summary(all_findings)

        with JOBS_LOCK:
            JOBS[job_id].update({
                "status":           "done",
                "findings":         sorted_findings,
                "recon":            recon_results,
                "stats":            stats,
                "severity_summary": sev_summary,
                "stage":            "Scan complete",
            })
        log("[*] === SCAN COMPLETE ===")

    except Exception as e:
        logger.error("Job %s crashed: %s", job_id, e, exc_info=True)
        with JOBS_LOCK:
            JOBS[job_id].update({"status": "error", "stage": f"Fatal error: {e}"})


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True) or {}
    target = (data.get("target") or "").strip().rstrip("/")
    if not target:
        return jsonify({"error": "target is required"}), 400
    err = _validate_target(target)
    if err:
        return jsonify({"error": err}), 400
    if not data.get("authorized"):
        return jsonify({"error": "Authorization confirmation is required"}), 403

    job_id        = uuid.uuid4().hex[:12]
    delay         = float(data.get("delay", 0.3))
    max_depth     = int(data.get("max_depth", 2))
    max_pages     = int(data.get("max_pages", 30))
    cookie        = str(data.get("cookie", ""))
    timeout       = int(data.get("timeout", 10))
    checks        = data.get("checks",        list(CHECK_RUNNERS.keys()))
    recon_modules = data.get("recon_modules", list(RECON_RUNNERS.keys()))

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status":     "running",
            "target":     target,
            "log":        [],
            "stage":      "Initializing...",
            "findings":   [],
            "recon":      {},
            "stats":      {},
            "severity_summary": {},
            "started_at": time.time(),
        }

    threading.Thread(
        target=_run_job,
        args=(job_id, target, delay, max_depth, max_pages, checks, recon_modules, cookie, timeout),
        daemon=True,
    ).start()

    return jsonify({"job_id": job_id}), 202


@app.route("/api/status/<job_id>")
def job_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404
    return jsonify({
        "status": job["status"],
        "stage":  job["stage"],
        "log":    job["log"][-200:],
        "stats":  job.get("stats", {}),
    })


@app.route("/api/result/<job_id>")
def job_result(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404
    if job["status"] != "done":
        return jsonify({"error": "Job not finished", "status": job["status"]}), 409
    return jsonify({
        "target":           job["target"],
        "stats":            job["stats"],
        "severity_summary": job["severity_summary"],
        "findings":         job["findings"],
        "recon":            job["recon"],
    })


@app.route("/api/report/<job_id>/<fmt>")
def download_report(job_id, fmt):
    if fmt not in ("json", "txt", "html", "docx"):
        abort(400)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        abort(404)

    target   = job["target"]
    findings = job["findings"]
    stats    = job["stats"]
    recon    = job.get("recon", {})
    path     = os.path.join(REPORTS_DIR, f"{job_id}.{fmt}")

    if not os.path.exists(path):
        if fmt == "json":
            report_writer.write_json(path, target, findings, stats, recon)
        elif fmt == "txt":
            report_writer.write_txt(path, target, findings, stats)
        elif fmt == "html":
            report_writer.write_html(path, target, findings, stats, recon)
        elif fmt == "docx":
            try:
                report_writer.write_docx(path, target, findings, stats)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

    return send_file(path, as_attachment=True,
                     download_name=f"vulnscan_{job_id}.{fmt}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n  WebVulnScanner API  →  http://0.0.0.0:{port}/api\n")
    app.run(host="0.0.0.0", port=port, debug=False)
