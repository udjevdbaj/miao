#!/usr/bin/env python3
"""GitHub App Installation Security Auditor.

Scans repositories and organizations for GitHub App installations
that have high-risk permissions (contents:write, pull_requests:write, etc.).
A compromised SaaS AI tool (Qodo, CodeRabbit, etc.) with these permissions
could push malicious code to all installed repos.

Uses GitHub REST API to enumerate:
  - Org-level app installations (requires org admin or specific token scope)
  - Repo-level app installations (requires repo admin or specific token scope)

Usage:
    python app_audit.py --config config/orgs.json --output app_audit_report.json [--summary app_audit_summary.txt]
    python app_audit.py --repos owner/repo1,owner/repo2 --output app_audit_report.json
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

API = "https://api.github.com"

# Permissions that grant write access — supply chain risk if leaked
HIGH_RISK_PERMISSIONS = {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
    "deployments": "write",
    "packages": "write",
    "administration": "write",
}

# Specific permissions that are dangerous for supply chain
DANGEROUS_COMBOS = [
    # Can read and write repo contents → push malicious commits
    (["contents"], "Can push code to repo"),
    # Can create/approve PRs → bypass branch protection
    (["pull_requests"], "Can create/merge pull requests"),
    # Can read secrets if combined with contents:write
    (["secrets"], "Can read repository secrets"),
    # Can manage Actions → modify workflows
    (["actions"], "Can modify GitHub Actions workflows"),
    # Can manage environments → access deployment secrets
    (["environments"], "Can access deployment environments"),
]


class TokenRotator:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.idx = 0

    def next(self) -> str:
        token = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return token


def api_get(token: str, url: str, retries: int = 3) -> dict | list | None:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(3)
            continue

        # Transient server errors / secondary rate limit → retry with backoff
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 30))
                continue
            return None

        # Rate limit: only sleep on an explicit signal; a permission-denied 403
        # must NOT trigger a long sleep. Wait capped at 300s (6h job ceiling).
        if resp.status_code == 403:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            body_msg = ""
            try:
                body_msg = resp.json().get("message", "")
            except ValueError:
                pass
            if remaining == "0" or "rate limit" in body_msg.lower():
                if attempt >= retries - 1:
                    return None  # last attempt — don't sleep 300s just to exit the loop
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = min(max(reset - int(time.time()), 10), 300)
                print(f"    [RATE LIMIT] waiting {wait}s...")
                time.sleep(wait)
                continue
            return None  # genuine 403 forbidden (e.g. not admin on target repo)

        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            print(f"    [AUTH] Token lacks required scope for {url}")
            return None
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None
    return None


def assess_app_permissions(app_name: str, permissions: dict) -> dict:
    """Evaluate the risk level of a GitHub App's permissions."""
    risks = []
    risk_score = 0

    for perm, access in permissions.items():
        if access not in ("write", "admin"):
            continue
        risk_score += 10
        risk_desc = f"{perm}:{access}"
        if perm in HIGH_RISK_PERMISSIONS:
            risk_score += 15
            risk_desc += " (HIGH RISK)"
        risks.append(risk_desc)

    # Check dangerous combinations
    write_perms = {p for p, a in permissions.items() if a in ("write", "admin")}
    for combo_perms, desc in DANGEROUS_COMBOS:
        if any(p in write_perms for p in combo_perms):
            risk_score += 20
            risks.append(f"COMBO: {desc}")

    severity = "LOW"
    if risk_score >= 60:
        severity = "CRITICAL"
    elif risk_score >= 40:
        severity = "HIGH"
    elif risk_score >= 20:
        severity = "MEDIUM"

    return {
        "app_name": app_name,
        "permissions": permissions,
        "write_permissions": sorted(write_perms),
        "risks": risks,
        "risk_score": risk_score,
        "severity": severity,
    }


def audit_repo_apps(token: str, repo: str) -> dict:
    """Check GitHub Apps installed on a specific repository."""
    result = {
        "repo": repo,
        "apps": [],
        "highest_severity": "NONE",
        "highest_score": 0,
        "error": None,
    }

    # List app installations on the repo
    # Note: This requires the token to have admin:repo_hook scope or
    # the user to be a repo admin. Most tokens won't have this.
    # Alternative: Check for visible integration events in recent commits/PRs
    data = api_get(token, f"{API}/repos/{repo}/installation")
    if data is None:
        # Fallback: check for bot accounts in recent commits/PRs
        # Note: /repos/{repo}/installation requires target repo admin,
        # not just admin:repo_hook scope. Fallback is the normal path
        # for third-party repos.
        result["error"] = "Token not admin on target repo; using bot-detection fallback"
        result["apps"] = _fallback_detect_bots(token, repo)
        _update_highest_severity(result)
        return result

    # If we have installation data, assess it
    if isinstance(data, dict):
        app_name = data.get("app_slug", data.get("app_id", "unknown"))
        permissions = data.get("permissions", {})
        assessment = assess_app_permissions(app_name, permissions)
        result["apps"].append(assessment)
        _update_highest_severity(result)

    return result


def _update_highest_severity(result: dict):
    """Recalculate highest_severity and highest_score from apps list."""
    for app in result["apps"]:
        if app["risk_score"] > result["highest_score"]:
            result["highest_score"] = app["risk_score"]
            result["highest_severity"] = app["severity"]


def _fallback_detect_bots(token: str, repo: str) -> list[dict]:
    """Fallback: detect bot/app activity from recent commits and comments.

    If we can't enumerate app installations directly, we can look for
    bot accounts (username[bot]) in recent PR comments and commits.
    """
    apps_found = []
    seen_bots = set()

    # Check recent PR comments for bot activity
    prs_data = api_get(token, f"{API}/repos/{repo}/pulls?state=all&per_page=20")
    if prs_data and isinstance(prs_data, list):
        for pr in prs_data[:10]:
            pr_number = pr.get("number")
            comments = api_get(token, f"{API}/repos/{repo}/issues/{pr_number}/comments?per_page=30")
            if not comments or not isinstance(comments, list):
                continue
            for comment in comments:
                user = comment.get("user", {})
                login = user.get("login", "")
                if login.endswith("[bot]") and login not in seen_bots:
                    seen_bots.add(login)
                    bot_name = login.replace("[bot]", "")
                    # Known dangerous apps
                    known_risk = _assess_known_bot(bot_name)
                    apps_found.append({
                        "app_name": bot_name,
                        "permissions": known_risk.get("permissions", {}),
                        "write_permissions": known_risk.get("write_permissions", []),
                        "risks": known_risk.get("risks", [f"Bot detected: {login}"]),
                        "risk_score": known_risk.get("risk_score", 10),
                        "severity": known_risk.get("severity", "MEDIUM"),
                        "detection_method": "bot_comment_fallback",
                    })
            time.sleep(0.3)

    # Check recent commits for bot authors
    commits_data = api_get(token, f"{API}/repos/{repo}/commits?per_page=20")
    if commits_data and isinstance(commits_data, list):
        for commit in commits_data:
            author = commit.get("author", {})
            login = author.get("login", "") if author else ""
            committer = commit.get("committer", {})
            clogin = committer.get("login", "") if committer else ""
            for bot_login in (login, clogin):
                if bot_login.endswith("[bot]") and bot_login not in seen_bots:
                    seen_bots.add(bot_login)
                    bot_name = bot_login.replace("[bot]", "")
                    known_risk = _assess_known_bot(bot_name)
                    apps_found.append({
                        "app_name": bot_name,
                        "permissions": known_risk.get("permissions", {}),
                        "write_permissions": known_risk.get("write_permissions", []),
                        "risks": known_risk.get("risks", [f"Bot detected: {bot_login}"]),
                        "risk_score": known_risk.get("risk_score", 10),
                        "severity": known_risk.get("severity", "MEDIUM"),
                        "detection_method": "bot_commit_fallback",
                    })

    return apps_found


def _assess_known_bot(bot_name: str) -> dict:
    """Assess risk of known GitHub Apps/bots."""
    KNOWN_APPS = {
        "dependabot": {"risk_score": 5, "severity": "LOW", "permissions": {"pull_requests": "write"}, "write_permissions": ["pull_requests"], "risks": ["Can create PRs (dependabot — low risk, trusted)"]},
        "github-actions": {"risk_score": 5, "severity": "LOW", "permissions": {}, "write_permissions": [], "risks": ["Internal GitHub Actions bot"]},
        "renovate": {"risk_score": 10, "severity": "LOW", "permissions": {"contents": "write", "pull_requests": "write"}, "write_permissions": ["contents", "pull_requests"], "risks": ["Can create PRs and push commits"]},
        "mergify": {"risk_score": 20, "severity": "MEDIUM", "permissions": {"contents": "write", "pull_requests": "write"}, "write_permissions": ["contents", "pull_requests"], "risks": ["Can merge PRs (supply chain risk if compromised)"]},
        "codecov": {"risk_score": 15, "severity": "MEDIUM", "permissions": {"statuses": "write"}, "write_permissions": ["statuses"], "risks": ["Can set commit statuses — bypass required checks"]},
        "qodo-merge-pro": {"risk_score": 60, "severity": "CRITICAL", "permissions": {"contents": "write", "pull_requests": "write", "issues": "write"}, "write_permissions": ["contents", "pull_requests", "issues"], "risks": ["Qodo Merge Pro — AWS key leak via Dynaconf (2025), contents:write = push code"]},
        "coderabbitai": {"risk_score": 40, "severity": "HIGH", "permissions": {"contents": "write", "pull_requests": "write"}, "write_permissions": ["contents", "pull_requests"], "risks": ["CodeRabbit — AI code review with contents:write (15K+ repos)"]},
        "semantic-release": {"risk_score": 30, "severity": "MEDIUM", "permissions": {"contents": "write"}, "write_permissions": ["contents"], "risks": ["Can push commits and create releases"]},
        "stale": {"risk_score": 5, "severity": "LOW", "permissions": {"issues": "write", "pull_requests": "write"}, "write_permissions": ["issues", "pull_requests"], "risks": ["Can close issues/PRs (low supply chain risk)"]},
    }

    lower = bot_name.lower().replace("-", "").replace("_", "")
    for key, info in KNOWN_APPS.items():
        if key.replace("-", "").replace("_", "") in lower:
            return info

    # Unknown bot — assume medium risk
    return {
        "risk_score": 15,
        "severity": "MEDIUM",
        "permissions": {},
        "write_permissions": [],
        "risks": [f"Unknown bot/app: {bot_name} — verify permissions manually"],
    }


def run_app_audit(repos: list[str], rotator: TokenRotator) -> dict:
    """Audit GitHub App installations across repos."""
    results = []

    for repo in repos:
        token = rotator.next()
        print(f"  Auditing apps for {repo}...", end=" ", flush=True)
        audit = audit_repo_apps(token, repo)
        results.append(audit)
        n_apps = len(audit["apps"])
        severity = audit["highest_severity"]
        print(f"{n_apps} apps, highest={severity}")
        time.sleep(0.5)

    results.sort(key=lambda x: x["highest_score"], reverse=True)

    return {
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(results),
        "results": results,
        "summary": _generate_summary(results),
    }


def _generate_summary(results: list[dict]) -> dict:
    """Generate summary by severity."""
    summary = {"critical": [], "high": [], "medium": [], "low": [], "none": []}

    for r in results:
        entry = {
            "repo": r["repo"],
            "severity": r["highest_severity"],
            "score": r["highest_score"],
            "apps": [
                {"name": a["app_name"], "severity": a["severity"], "risks": a["risks"]}
                for a in r["apps"]
            ],
        }
        sev = r["highest_severity"]
        if sev == "CRITICAL":
            summary["critical"].append(entry)
        elif sev == "HIGH":
            summary["high"].append(entry)
        elif sev == "MEDIUM":
            summary["medium"].append(entry)
        elif sev == "LOW":
            summary["low"].append(entry)
        else:
            summary["none"].append(entry)

    return summary


def write_audit_report(report: dict, output_path: str):
    """Write JSON report."""
    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def write_audit_summary(report: dict, output_path: str):
    """Write human-readable summary."""
    summary = report["summary"]
    lines = [
        f"GitHub App Installation Audit — {report['audit_time']}",
        f"{'=' * 70}",
        f"Total repos audited: {report['total_repos']}",
        f"CRITICAL: {len(summary['critical'])}",
        f"HIGH: {len(summary['high'])}",
        f"MEDIUM: {len(summary['medium'])}",
        f"LOW: {len(summary['low'])}",
        f"NONE: {len(summary['none'])}",
        "",
    ]

    for category in ("critical", "high", "medium"):
        items = summary.get(category, [])
        if not items:
            continue
        lines.append(f"{'=' * 70}")
        lines.append(f"{category.upper()} RISK ({len(items)})")
        lines.append(f"{'=' * 70}")
        for item in items:
            lines.append(f"  {item['repo']} (score={item['score']})")
            for app in item["apps"]:
                lines.append(f"    [{app['severity']}] {app['name']}")
                for risk in app["risks"]:
                    lines.append(f"      → {risk}")
            lines.append("")

    Path(output_path).write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="GitHub App Installation Security Auditor")
    parser.add_argument("--config", help="Path to orgs.json for repo discovery")
    parser.add_argument("--repos", help="Comma-separated repo list (owner/repo)")
    parser.add_argument("--input", help="Path to scan_results.json for repo list")
    parser.add_argument("--output", default="app_audit_report.json")
    parser.add_argument("--summary", default="app_audit_summary.txt")
    args = parser.parse_args()

    tokens_str = os.environ.get("SCAN_TOKENS", "")
    if not tokens_str:
        print("ERROR: SCAN_TOKENS environment variable not set")
        sys.exit(1)
    tokens = [t.strip() for t in tokens_str.split(",") if t.strip()]
    rotator = TokenRotator(tokens)

    # Collect repo list
    repos = []
    if args.repos:
        repos = [r.strip() for r in args.repos.split(",") if r.strip()]
    elif args.input:
        scan_data = json.loads(Path(args.input).read_text())
        seen = set()
        for r in scan_data.get("all_repos", []):
            repo = r["repo"]
            if repo not in seen:
                seen.add(repo)
                repos.append(repo)
    elif args.config:
        config = json.loads(Path(args.config).read_text())
        # Supports two formats:
        # 1. {"repos": ["owner/repo", ...]}  — explicit repo list
        # 2. {"vendors": [...]} with "orgs"   — orgs.json format (enumerate repos via API)
        if "repos" in config:
            repos = [r.strip() for r in config["repos"] if r.strip()]
            print(f"Loaded {len(repos)} repos from config")
        elif "vendors" in config:
            print("Discovering repos from org list...")
            for vendor in config["vendors"]:
                for org in vendor.get("orgs", []):
                    token = rotator.next()
                    data = api_get(token, f"{API}/orgs/{org}/repos?per_page=100&type=public")
                    if data and isinstance(data, list):
                        for r in data:
                            full_name = r.get("full_name", "")
                            if full_name:
                                repos.append(full_name)
                        print(f"  {org}: {len(data)} repos")
                    else:
                        print(f"  {org}: no repos or error")
                    time.sleep(0.5)
            print(f"Total repos discovered: {len(repos)}")
    else:
        print("ERROR: Provide --repos, --input, or --config")
        sys.exit(1)

    if not repos:
        print("No repos to audit")
        sys.exit(0)

    print(f"Auditing {len(repos)} repos for GitHub App installations...\n")
    report = run_app_audit(repos, rotator)

    write_audit_report(report, args.output)
    write_audit_summary(report, args.summary)

    print(f"\n{'=' * 70}")
    print(f"App audit complete: {report['total_repos']} repos")
    s = report["summary"]
    print(f"  CRITICAL: {len(s['critical'])} | HIGH: {len(s['high'])} | MEDIUM: {len(s['medium'])} | LOW: {len(s['low'])}")
    print(f"  Report: {args.output}")
    print(f"  Summary: {args.summary}")


if __name__ == "__main__":
    main()
