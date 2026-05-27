#!/usr/bin/env python3
"""Email notification for CI/CD security scan results.

Sends an HTML email via QQ SMTP with ALL scan results.
New repos are highlighted in red.

Usage:
    python notify.py --input scan_results.json [--always] [--summary scan_summary.txt]
"""

import argparse
import json
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from pathlib import Path


SMTP_HOST = "smtp.qq.com"
SMTP_PORT = 465


def build_html_email(results: dict) -> str:
    """Build HTML email body from scan results."""
    scan_time = results.get("scan_time", datetime.now(timezone.utc).isoformat())
    all_repos = results.get("all_repos", [])
    new_repos = results.get("new_repos", [])
    errors = results.get("errors", [])
    total_repos = results.get("total_repos", 0)

    has_new = len(new_repos) > 0
    status_color = "#dc3545" if has_new else "#28a745"
    status_text = f"{len(new_repos)} NEW REPOS" if has_new else "No new repos"

    # Group all repos by vendor
    by_vendor = {}
    for r in all_repos:
        by_vendor.setdefault(r["vendor"], []).append(r)

    vendor_sections = ""
    for vendor in sorted(by_vendor.keys()):
        repos = by_vendor[vendor]
        # Deduplicate by repo name, merge query types
        repo_map = {}
        for r in repos:
            if r["repo"] not in repo_map:
                repo_map[r["repo"]] = {"is_new": r["is_new"], "types": set(), "files": r["files"]}
            repo_map[r["repo"]]["types"].add(r["query_type"])

        rows = ""
        for repo_name in sorted(repo_map.keys()):
            info = repo_map[repo_name]
            new_badge = ' <span style="background:#dc3545;color:white;padding:2px 6px;border-radius:3px;font-size:11px">NEW</span>' if info["is_new"] else ""
            types_str = ", ".join(sorted(info["types"]))
            # Show ALL files as clickable links
            file_links = []
            for f in info["files"]:
                file_links.append(
                    f'<a href="https://github.com/{repo_name}/blob/main/{f}" '
                    f'style="color:#0366d6;text-decoration:none">{f}</a>'
                )
            files_str = "<br>".join(file_links)
            bg = "#fff3f3" if info["is_new"] else ""
            rows += f"""
            <tr style="background:{bg}">
                <td style="border:1px solid #ddd;padding:6px">
                    <a href="https://github.com/{repo_name}">{repo_name}</a>{new_badge}
                </td>
                <td style="border:1px solid #ddd;padding:6px">{types_str}</td>
                <td style="border:1px solid #ddd;padding:6px;font-size:12px">{files_str}</td>
            </tr>"""

        vendor_sections += f"""
        <h4 style="margin:15px 0 5px 0">{vendor} ({len(repo_map)} repos)</h4>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Repository</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Trigger Types</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left">Workflow Files</th>
            </tr>
            {rows}
        </table>"""

    errors_section = ""
    if errors:
        error_rows = ""
        for e in errors:
            error_rows += f"""
            <tr>
                <td style="border:1px solid #ddd;padding:4px">{e['org']}</td>
                <td style="border:1px solid #ddd;padding:4px">{e['query_type']}</td>
                <td style="border:1px solid #ddd;padding:4px;color:#e67e22">{e['error'][:60]}</td>
            </tr>"""
        errors_section = f"""
        <h4 style="color:#e67e22">Errors ({len(errors)})</h4>
        <table style="border-collapse:collapse;width:100%;font-size:12px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:4px;text-align:left">Org</th>
                <th style="border:1px solid #ddd;padding:4px;text-align:left">Query</th>
                <th style="border:1px solid #ddd;padding:4px;text-align:left">Error</th>
            </tr>
            {error_rows}
        </table>"""

    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:950px;margin:0 auto">
        <div style="background:{status_color};color:white;padding:15px;border-radius:5px 5px 0 0">
            <h2 style="margin:0">CI/CD Security Monitor</h2>
            <p style="margin:5px 0 0 0">{status_text} — {scan_time[:19]}</p>
        </div>
        <div style="padding:15px;border:1px solid #ddd;border-top:none">
            <p style="font-size:14px">
                <strong>Orgs:</strong> {results.get('total_orgs', 0)} |
                <strong>Queries:</strong> {results.get('total_queries', 0)} |
                <strong>Matches:</strong> {results.get('total_results', 0)} |
                <strong>Repos:</strong> {total_repos} |
                <strong style="color:{status_color}">New:</strong> {len(new_repos)} |
                <strong>Errors:</strong> {len(errors)}
            </p>
            {vendor_sections}
            {errors_section}
            <p style="font-size:11px;color:#999;margin-top:15px">
                CI/CD Security Monitor — {results.get('total_orgs', 0)} orgs x {len(set(r.get('query_type','') for r in all_repos)) or 3} queries = {results.get('total_queries', 0)} API calls
            </p>
        </div>
    </body>
    </html>"""

    return html


def send_email(smtp_user: str, smtp_pass: str, to_addr: str, subject: str, html_body: str, attachments: list[str] = None):
    """Send HTML email via QQ SMTP (SSL) with optional file attachments."""
    msg = MIMEMultipart("mixed")
    msg["From"] = smtp_user
    msg["To"] = to_addr
    msg["Subject"] = subject

    # HTML body as alternative part
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html"))
    msg.attach(alt)

    # Attach files
    if attachments:
        for filepath in attachments:
            p = Path(filepath)
            if not p.exists():
                print(f"  [WARN] Attachment not found: {filepath}")
                continue
            part = MIMEBase("application", "octet-stream")
            part.set_payload(p.read_bytes())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{p.name}"')
            msg.attach(part)
            print(f"  Attached: {p.name} ({p.stat().st_size} bytes)")

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [to_addr], msg.as_string())

    print(f"Email sent to {to_addr}")


def main():
    parser = argparse.ArgumentParser(description="CI/CD Security Scan Email Notification")
    parser.add_argument("--input", required=True, help="Path to scan_results.json")
    parser.add_argument("--summary", default=None, help="Path to scan_summary.txt (attached to email)")
    parser.add_argument("--always", action="store_true", help="Send email even if no results")
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
    total_repos = results.get("total_repos", 0)

    # Skip if no repos found at all and not --always
    if total_repos == 0 and not args.always:
        print("No repos found. Skipping email.")
        return

    # Build and send email
    html = build_html_email(results)
    new_tag = f"[{new_count} NEW] " if new_count > 0 else ""
    subject = f"[CI/CD Monitor] {new_tag}{total_repos} repos — {results.get('scan_time', '')[:10]}"

    # Collect attachments
    attachments = [str(results_path)]
    if args.summary:
        attachments.append(args.summary)

    send_email(smtp_user, smtp_pass, notify_email, subject, html, attachments)


if __name__ == "__main__":
    main()
