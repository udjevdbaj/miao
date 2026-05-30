#!/usr/bin/env python3
"""Email notification template for GitHub App audit results.

Reads app_audit_report.json and sends an email showing which repos
have high-risk GitHub App installations.

Usage:
    python app_audit_notify.py --input app_audit_report.json [--summary app_audit_summary.txt] [--always]
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

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#e67e22",
    "MEDIUM": "#f0ad4e",
    "LOW": "#28a745",
}


def build_app_audit_email(report: dict) -> str:
    """Build HTML email from app_audit_report.json."""
    audit_time = report.get("audit_time", datetime.now(timezone.utc).isoformat())
    summary = report.get("summary", {})
    total_repos = report.get("total_repos", 0)

    n_critical = len(summary.get("critical", []))
    n_high = len(summary.get("high", []))
    n_medium = len(summary.get("medium", []))
    n_low = len(summary.get("low", []))

    # Header
    if n_critical > 0:
        header_color = SEVERITY_COLORS["CRITICAL"]
        status_text = f"{n_critical} CRITICAL"
    elif n_high > 0:
        header_color = SEVERITY_COLORS["HIGH"]
        status_text = f"{n_high} HIGH"
    elif n_medium > 0:
        header_color = SEVERITY_COLORS["MEDIUM"]
        status_text = f"{n_medium} MEDIUM"
    else:
        header_color = SEVERITY_COLORS["LOW"]
        status_text = "All Low / None"

    # Stats bar
    stats_html = f"""
    <div style="display:flex;gap:15px;flex-wrap:wrap;margin:10px 0">
        <span style="background:#dc3545;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            CRITICAL: {n_critical}
        </span>
        <span style="background:#e67e22;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            HIGH: {n_high}
        </span>
        <span style="background:#f0ad4e;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            MEDIUM: {n_medium}
        </span>
        <span style="background:#28a745;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            LOW: {n_low}
        </span>
    </div>
    <p style="font-size:13px;color:#666">
        Total repos audited: <strong>{total_repos}</strong> | {audit_time[:19]}
    </p>"""

    # Category sections
    sections_html = ""
    for cat_key, cat_label, cat_color in [
        ("critical", "CRITICAL — Supply Chain Risk", "#dc3545"),
        ("high", "HIGH — Dangerous Permissions", "#e67e22"),
        ("medium", "MEDIUM — Elevated Permissions", "#f0ad4e"),
    ]:
        items = summary.get(cat_key, [])
        if not items:
            continue

        rows_html = ""
        for item in items:
            repo = item["repo"]
            score = item.get("score", 0)
            apps_html = ""
            for app in item.get("apps", []):
                risk_badges = " ".join(
                    f'<span style="background:#fff3cd;color:#856404;padding:1px 4px;border-radius:2px;font-size:10px">{r}</span>'
                    for r in app.get("risks", [])[:3]
                )
                det = app.get("detection_method", "")
                det_tag = f'<span style="font-size:10px;color:#999">({det})</span>' if det else ""
                apps_html += f"""
                <div style="margin:3px 0;padding:3px 6px;background:#f8f9fa;border-radius:3px">
                    <span style="font-weight:bold;font-size:12px">{app["name"]}</span>
                    <span style="background:{SEVERITY_COLORS.get(app["severity"], "#999")};color:white;padding:1px 5px;border-radius:2px;font-size:10px;margin-left:5px">{app["severity"]}</span>
                    <span style="font-size:10px;color:#666;margin-left:5px">score={app.get("risk_score", 0)}</span>
                    {det_tag}
                    <div style="margin-top:2px">{risk_badges}</div>
                </div>"""

            rows_html += f"""
            <tr>
                <td style="border:1px solid #ddd;padding:6px;vertical-align:top">
                    <a href="https://github.com/{repo}" style="color:#0366d6;text-decoration:none;font-weight:bold">{repo}</a>
                    <span style="font-size:11px;color:#666;margin-left:5px">score={score}</span>
                </td>
                <td style="border:1px solid #ddd;padding:6px;vertical-align:top">
                    {apps_html if apps_html else '<span style="color:#999">—</span>'}
                </td>
            </tr>"""

        sections_html += f"""
        <h4 style="margin:15px 0 5px 0;color:{cat_color}">{cat_label} ({len(items)})</h4>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:6px;text-align:left;width:35%">Repository</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left;width:65%">Installed Apps</th>
            </tr>
            {rows_html}
        </table>"""

    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:950px;margin:0 auto">
        <div style="background:{header_color};color:white;padding:15px;border-radius:5px 5px 0 0">
            <h2 style="margin:0">GitHub App Audit</h2>
            <p style="margin:5px 0 0 0">{status_text} — {audit_time[:19]}</p>
        </div>
        <div style="padding:15px;border:1px solid #ddd;border-top:none">
            {stats_html}
            {sections_html}
            <p style="font-size:11px;color:#999;margin-top:15px">
                GitHub App Installation Audit — {total_repos} repos audited | Automated detection
            </p>
        </div>
    </body>
    </html>"""

    return html


def send_email(smtp_user: str, smtp_pass: str, to_addr: str, subject: str, html_body: str, attachments: list[str] = None):
    """Send HTML email via QQ SMTP (SSL)."""
    msg = MIMEMultipart("mixed")
    msg["From"] = smtp_user
    msg["To"] = to_addr
    msg["Subject"] = subject

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html"))
    msg.attach(alt)

    if attachments:
        for filepath in attachments:
            p = Path(filepath)
            if not p.exists():
                continue
            part = MIMEBase("application", "octet-stream")
            part.set_payload(p.read_bytes())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{p.name}"')
            msg.attach(part)

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [to_addr], msg.as_string())

    print(f"App audit email sent to {to_addr}")


def main():
    parser = argparse.ArgumentParser(description="GitHub App Audit Email Notification")
    parser.add_argument("--input", required=True, help="Path to app_audit_report.json")
    parser.add_argument("--summary", default=None, help="Path to app_audit_summary.txt (attached)")
    parser.add_argument("--always", action="store_true", help="Send email even if no findings")
    args = parser.parse_args()

    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")
    notify_email = os.environ.get("NOTIFY_EMAIL", "")

    if not all([smtp_user, smtp_pass, notify_email]):
        print("ERROR: SMTP_USER, SMTP_PASSWORD, and NOTIFY_EMAIL env vars required")
        sys.exit(1)

    report_path = Path(args.input)
    if not report_path.exists():
        print(f"Report not found: {args.input}")
        return

    report = json.loads(report_path.read_text())
    summary = report.get("summary", {})

    n_actionable = (
        len(summary.get("critical", []))
        + len(summary.get("high", []))
        + len(summary.get("medium", []))
    )

    if n_actionable == 0 and not args.always:
        print("No actionable app audit findings. Skipping email.")
        return

    html = build_app_audit_email(report)

    parts = []
    if len(summary.get("critical", [])):
        parts.append(f"{len(summary['critical'])} CRITICAL")
    if len(summary.get("high", [])):
        parts.append(f"{len(summary['high'])} HIGH")
    if not parts:
        parts.append(f"{n_actionable} findings")
    subject_tag = " | ".join(parts)
    subject = f"[App Audit] {subject_tag} — {report.get('audit_time', '')[:10]}"

    attachments = [str(report_path)]
    if args.summary:
        attachments.append(args.summary)

    send_email(smtp_user, smtp_pass, notify_email, subject, html, attachments)


if __name__ == "__main__":
    main()
