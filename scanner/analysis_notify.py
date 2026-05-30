#!/usr/bin/env python3
"""Dedicated email template for CI/CD workflow security analysis results.

Reads analysis_report.json and sends a clear, actionable email showing
which repos have what security problems, grouped by severity.

Usage:
    python analysis_notify.py --input analysis_report.json [--summary analysis_summary.txt] [--always]
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
    "POTENTIAL": "#f0ad4e",
    "NOT_EXPLOITABLE": "#6c757d",
    "MANUAL_REVIEW": "#6f42c1",
    "SAFE": "#28a745",
}


def _severity_level(verdict: str) -> str:
    v = verdict.upper()
    if "CRITICAL" in v:
        return "CRITICAL"
    if "HIGH" in v:
        return "HIGH"
    if "POTENTIAL" in v or "MEDIUM" in v:
        return "POTENTIAL"
    if "MANUAL_REVIEW" in v:
        return "MANUAL_REVIEW"
    if "NOT EXPLOITABLE" in v:
        return "NOT EXPLOITABLE"
    return "SAFE"


def build_analysis_email(analysis: dict) -> str:
    """Build HTML email from analysis_report.json."""
    analysis_time = analysis.get("analysis_time", datetime.now(timezone.utc).isoformat())
    summary = analysis.get("summary", {})
    total_repos = analysis.get("total_repos", 0)

    # Count by category
    n_critical = len(summary.get("critical", []))
    n_high = len(summary.get("high", []))
    n_potential = len(summary.get("potential", []))
    n_manual_review = len(summary.get("manual_review", []))
    n_not_exploitable = len(summary.get("not_exploitable", []))
    n_safe = len(summary.get("github_hosted", [])) + len(summary.get("safe", []))

    # Header status
    if n_critical > 0:
        header_color = SEVERITY_COLORS["CRITICAL"]
        status_text = f"{n_critical} CRITICAL"
    elif n_high > 0:
        header_color = SEVERITY_COLORS["HIGH"]
        status_text = f"{n_high} HIGH"
    elif n_potential > 0:
        header_color = SEVERITY_COLORS["POTENTIAL"]
        status_text = f"{n_potential} POTENTIAL"
    else:
        header_color = SEVERITY_COLORS["SAFE"]
        status_text = "All Clear"

    # ── Stats bar ──
    stats_html = f"""
    <div style="display:flex;gap:15px;flex-wrap:wrap;margin:10px 0">
        <span style="background:#dc3545;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            CRITICAL: {n_critical}
        </span>
        <span style="background:#e67e22;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            HIGH: {n_high}
        </span>
        <span style="background:#f0ad4e;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            POTENTIAL: {n_potential}
        </span>
        <span style="background:#6c757d;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            NOT EXPLOITABLE: {n_not_exploitable}
        </span>
        <span style="background:#6f42c1;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            MANUAL_REVIEW: {n_manual_review}
        </span>
        <span style="background:#28a745;color:white;padding:4px 10px;border-radius:3px;font-size:13px">
            SAFE: {n_safe}
        </span>
    </div>
    <p style="font-size:13px;color:#666">
        Total repos analyzed: <strong>{total_repos}</strong> | {analysis_time[:19]}
    </p>"""

    # ── Category sections ──
    sections_html = ""

    categories = [
        ("critical", "CRITICAL — 0-Click RCE Possible", "#dc3545"),
        ("high", "HIGH — 0-Click Script Injection", "#e67e22"),
        ("potential", "POTENTIAL — Security Gate Required", "#f0ad4e"),
        ("manual_review", "MANUAL_REVIEW — Runner Group (verify if self-hosted)", "#6f42c1"),
        ("not_exploitable", "NOT EXPLOITABLE — Needs Approval/No Precedent", "#6c757d"),
    ]

    for cat_key, cat_label, cat_color in categories:
        items = summary.get(cat_key, [])
        if not items:
            continue

        rows_html = ""
        for item in items:
            repo = item["repo"]
            vendor = item.get("vendor", "")
            triggers = ", ".join(item.get("triggers", []))
            secrets = item.get("secrets", [])
            risk = item.get("risk_score", 0)
            verdict = item.get("verdict", "")

            secrets_str = ""
            if secrets:
                secret_badges = " ".join(
                    f'<span style="background:#fff3cd;color:#856404;padding:1px 5px;border-radius:2px;font-size:11px">{s}</span>'
                    for s in secrets
                )
                secrets_str = f'<div style="margin-top:3px">Secrets: {secret_badges}</div>'

            rows_html += f"""
            <tr>
                <td style="border:1px solid #ddd;padding:6px;vertical-align:top">
                    <a href="https://github.com/{repo}" style="color:#0366d6;text-decoration:none;font-weight:bold">{repo}</a>
                    <span style="color:#999;font-size:11px">({vendor})</span>
                </td>
                <td style="border:1px solid #ddd;padding:6px;vertical-align:top;font-size:12px">
                    {triggers}
                </td>
                <td style="border:1px solid #ddd;padding:6px;vertical-align:top">
                    <span style="background:{cat_color};color:white;padding:2px 6px;border-radius:3px;font-size:11px">
                        {verdict}
                    </span>
                    <span style="font-size:11px;color:#666;margin-left:5px">risk={risk}</span>
                    {secrets_str}
                </td>
            </tr>"""

        sections_html += f"""
        <h4 style="margin:15px 0 5px 0;color:{cat_color}">{cat_label} ({len(items)})</h4>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
            <tr style="background:#f8f9fa">
                <th style="border:1px solid #ddd;padding:6px;text-align:left;width:40%">Repository</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left;width:20%">Triggers</th>
                <th style="border:1px solid #ddd;padding:6px;text-align:left;width:40%">Verdict & Details</th>
            </tr>
            {rows_html}
        </table>"""

    # ── Workflow details for actionable items ──
    actionable_items = summary.get("critical", []) + summary.get("high", []) + summary.get("potential", []) + summary.get("manual_review", [])
    details_html = ""
    if actionable_items:
        details_html = """
        <hr style="border:none;border-top:1px solid #ddd;margin:20px 0 10px 0">
        <h4 style="color:#333">Actionable Target Details</h4>"""

        for item in actionable_items[:10]:  # Top 10
            repo = item["repo"]
            verdict = item.get("verdict", "")
            risk = item.get("risk_score", 0)
            details_html += f"""
            <div style="margin:8px 0;padding:8px;border:1px solid #eee;border-radius:4px;background:#fafafa">
                <strong><a href="https://github.com/{repo}" style="color:#0366d6;text-decoration:none">{repo}</a></strong>
                <span style="float:right;color:#666;font-size:12px">risk={risk}</span><br>
                <span style="font-size:12px;color:#555">Triggers: {', '.join(item.get('triggers', []))} | Verdict: {verdict}</span>
            </div>"""

        if len(actionable_items) > 10:
            details_html += f"""
            <p style="font-size:12px;color:#999">
                ... and {len(actionable_items) - 10} more. See attached analysis_report.json for full details.
            </p>"""

    # ── Assemble full HTML ──
    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:950px;margin:0 auto">
        <div style="background:{header_color};color:white;padding:15px;border-radius:5px 5px 0 0">
            <h2 style="margin:0">CI/CD Security Analysis</h2>
            <p style="margin:5px 0 0 0">{status_text} — {analysis_time[:19]}</p>
        </div>
        <div style="padding:15px;border:1px solid #ddd;border-top:none">
            {stats_html}
            {sections_html}
            {details_html}
            <p style="font-size:11px;color:#999;margin-top:15px">
                CI/CD Security Monitor — {total_repos} repos analyzed | Automated workflow analysis
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

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html"))
    msg.attach(alt)

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

    print(f"Analysis email sent to {to_addr}")


def main():
    parser = argparse.ArgumentParser(description="CI/CD Analysis Email Notification")
    parser.add_argument("--input", required=True, help="Path to analysis_report.json")
    parser.add_argument("--summary", default=None, help="Path to analysis_summary.txt (attached)")
    parser.add_argument("--always", action="store_true", help="Send email even if no actionable findings")
    args = parser.parse_args()

    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")
    notify_email = os.environ.get("NOTIFY_EMAIL", "")

    if not all([smtp_user, smtp_pass, notify_email]):
        print("ERROR: SMTP_USER, SMTP_PASSWORD, and NOTIFY_EMAIL env vars required")
        sys.exit(1)

    report_path = Path(args.input)
    if not report_path.exists():
        print(f"ERROR: Report file not found: {args.input}")
        sys.exit(1)

    analysis = json.loads(report_path.read_text())
    summary = analysis.get("summary", {})

    n_actionable = (
        len(summary.get("critical", []))
        + len(summary.get("high", []))
        + len(summary.get("potential", []))
    )

    if n_actionable == 0 and not args.always:
        print("No actionable findings. Skipping email.")
        return

    html = build_analysis_email(analysis)

    # Subject line
    n_crit = len(summary.get("critical", []))
    n_high = len(summary.get("high", []))
    parts = []
    if n_crit:
        parts.append(f"{n_crit} CRITICAL")
    if n_high:
        parts.append(f"{n_high} HIGH")
    if not parts:
        parts.append(f"{n_actionable} findings")
    subject_tag = " | ".join(parts)

    subject = f"[CI/CD Analysis] {subject_tag} — {analysis.get('analysis_time', '')[:10]}"

    attachments = [str(report_path)]
    if args.summary:
        attachments.append(args.summary)

    send_email(smtp_user, smtp_pass, notify_email, subject, html, attachments)


if __name__ == "__main__":
    main()
