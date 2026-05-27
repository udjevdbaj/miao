#!/usr/bin/env python3
"""Email notification for CI/CD security scan results.

Sends an HTML email via Outlook SMTP with scan results.
Only sends if new repos are found (or always if --always flag is set).

Usage:
    python notify.py --input scan_results.json [--always] [--summary scan_summary.txt]
"""

import argparse
import json
import os
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


SMTP_HOST = "smtp-mail.outlook.com"
SMTP_PORT = 587


def build_html_email(results: dict, summary_text: str = "") -> str:
    """Build HTML email body from scan results."""
    scan_time = results.get("scan_time", datetime.utcnow().isoformat())
    new_repos = results.get("new_repos", [])
    details = results.get("details", [])
    errors = results.get("errors", [])

    has_new = len(new_repos) > 0
    status_color = "#dc3545" if has_new else "#28a745"
    status_text = f"NEW REPOS DETECTED ({len(new_repos)})" if has_new else "No new repos"

    rows = ""
    for nr in new_repos:
        rows += f"""
        <tr>
            <td>{nr['vendor']}</td>
            <td><a href="https://github.com/{nr['repo']}">{nr['repo']}</a></td>
            <td><span style="color:#dc3545;font-weight:bold">{nr['query_type']}</span></td>
            <td>{'<br>'.join(nr['files'][:3])}</td>
        </tr>"""

    detail_rows = ""
    for d in details:
        new_badge = f' <span style="color:#dc3545">[NEW: {len(d.get("new_repos", []))}]</span>' if d.get("new_repos") else ""
        detail_rows += f"""
        <tr>
            <td>{d['vendor']}</td>
            <td>{d['org']}</td>
            <td>{d['query_type']}</td>
            <td>{d['total']}</td>
            <td>{new_badge}</td>
        </tr>"""

    error_rows = ""
    for e in errors:
        error_rows += f"""
        <tr>
            <td>{e['org']}</td>
            <td>{e['query_type']}</td>
            <td style="color:#ffc107">{e['error']}</td>
        </tr>"""

    new_repos_section = ""
    if new_repos:
        new_repos_section = f"""
        <h3 style="color:#dc3545">New Repositories Detected</h3>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:8px;text-align:left">Vendor</th>
                <th style="border:1px solid #ddd;padding:8px;text-align:left">Repository</th>
                <th style="border:1px solid #ddd;padding:8px;text-align:left">Query</th>
                <th style="border:1px solid #ddd;padding:8px;text-align:left">Files</th>
            </tr>
            {rows}
        </table>"""

    details_section = ""
    if details:
        details_section = f"""
        <h3>Scan Details</h3>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Vendor</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Org</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Type</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Count</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">New</th>
            </tr>
            {detail_rows}
        </table>"""

    errors_section = ""
    if errors:
        errors_section = f"""
        <h3 style="color:#ffc107">Errors ({len(errors)})</h3>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Org</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Query</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Error</th>
            </tr>
            {error_rows}
        </table>"""

    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:900px;margin:0 auto">
        <div style="background:{status_color};color:white;padding:15px;border-radius:5px 5px 0 0">
            <h2 style="margin:0">CI/CD Security Monitor</h2>
            <p style="margin:5px 0 0 0">{status_text} — {scan_time}</p>
        </div>
        <div style="padding:15px;border:1px solid #ddd;border-top:none">
            <p>
                <strong>Queries:</strong> {results.get('total_queries', 0)} |
                <strong>Results:</strong> {results.get('total_results', 0)} |
                <strong>New:</strong> <span style="color:{status_color};font-weight:bold">{len(new_repos)}</span> |
                <strong>Errors:</strong> {len(errors)}
            </p>
            {new_repos_section}
            {details_section}
            {errors_section}
        </div>
        <div style="font-size:11px;color:#999;margin-top:10px;text-align:center">
            CI/CD Security Monitor — Automated scan
        </div>
    </body>
    </html>"""

    return html


def send_email(smtp_user: str, smtp_pass: str, to_addr: str, subject: str, html_body: str):
    """Send HTML email via Outlook SMTP."""
    msg = MIMEMultipart("alternative")
    msg["From"] = smtp_user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [to_addr], msg.as_string())

    print(f"Email sent to {to_addr}")


def main():
    parser = argparse.ArgumentParser(description="CI/CD Security Scan Email Notification")
    parser.add_argument("--input", required=True, help="Path to scan_results.json")
    parser.add_argument("--summary", default="", help="Path to scan_summary.txt")
    parser.add_argument("--always", action="store_true", help="Send email even if no new repos")
    args = parser.parse_args()

    # Load env
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")
    notify_email = os.environ.get("NOTIFY_EMAIL", "")

    if not all([smtp_user, smtp_pass, notify_email]):
        print("ERROR: SMTP_USER, SMTP_PASSWORD, and NOTIFY_EMAIL env vars required")
        sys.exit(1)

    # Load results
    results_path = Path(args.input)
    if not results_path.exists():
        print(f"ERROR: Results file not found: {args.input}")
        sys.exit(1)

    results = json.loads(results_path.read_text())
    new_count = len(results.get("new_repos", []))

    # Skip if no new repos and not --always
    if new_count == 0 and not args.always:
        print("No new repos found. Skipping email (use --always to always send).")
        return

    # Build email
    summary_text = ""
    if args.summary and Path(args.summary).exists():
        summary_text = Path(args.summary).read_text()

    html = build_html_email(results, summary_text)
    status = "NEW REPOS DETECTED" if new_count > 0 else "No new repos"
    subject = f"[CI/CD Monitor] {status} — {new_count} new — {results.get('scan_time', '')[:10]}"

    send_email(smtp_user, smtp_pass, notify_email, subject, html)


if __name__ == "__main__":
    main()
