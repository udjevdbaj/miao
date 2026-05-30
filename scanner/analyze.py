#!/usr/bin/env python3
"""Automated CI/CD Workflow Security Analyzer.

Reads scan_results.json, downloads and analyzes every workflow file
from each matched repo, and produces a detailed security assessment.

Usage:
    python analyze.py --input scan_results.json --output analysis_report.json [--summary analysis_summary.txt]
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

API = "https://api.github.com"


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
            if resp.status_code == 403:
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(time.time()), 10)
                print(f"    [RATE LIMIT] waiting {wait}s...")
                time.sleep(wait)
                continue
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                return None
            return resp.json()
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(3)
    return None


def get_workflow_files(token: str, repo: str) -> dict[str, str]:
    """Download all workflow files from a repo. Returns {filename: content}."""
    files = {}
    data = api_get(token, f"{API}/repos/{repo}/contents/.github/workflows")
    if not data or not isinstance(data, list):
        return files

    for item in data:
        if not isinstance(item, dict) or not item.get("name", "").endswith((".yml", ".yaml")):
            continue
        name = item["name"]
        content_data = api_get(token, f"{API}/repos/{repo}/contents/.github/workflows/{name}")
        if content_data and isinstance(content_data, dict) and content_data.get("content"):
            try:
                content = base64.b64decode(content_data["content"]).decode("utf-8", errors="replace")
                files[name] = content
            except Exception:
                pass
        time.sleep(0.3)
    return files


def check_none_approval(token: str, repo: str, max_pages: int = 3) -> dict:
    """Check if NONE users ever had PR workflow runs approved/completed.

    Strategy:
    1. Collect PR numbers from NONE-authors via pulls API
    2. Page through workflow runs (event=pull_request), match by PR number
       via the run's pull_requests[].number field
    3. If any NONE-author's PR has a completed/successful run → precedent confirmed
    """
    result = {"has_none_precedent": False, "none_users": [], "total_pr_runs": 0}

    # Step 1: Find all NONE-author PR numbers
    none_pr_numbers: dict[int, str] = {}  # {pr_number: username}
    pulls_data = api_get(token, f"{API}/repos/{repo}/pulls?state=all&per_page=100")
    if pulls_data and isinstance(pulls_data, list):
        for pr in pulls_data:
            if pr.get("author_association") == "NONE":
                num = pr.get("number")
                login = pr.get("user", {}).get("login", "unknown")
                if num:
                    none_pr_numbers[num] = login
    if not none_pr_numbers:
        return result

    # Step 2: Match workflow runs to NONE-author PRs via pull_requests field
    for page in range(1, max_pages + 1):
        data = api_get(
            token,
            f"{API}/repos/{repo}/actions/runs?per_page=100&event=pull_request&page={page}",
        )
        if not data or not isinstance(data, dict):
            break
        runs = data.get("workflow_runs", [])
        result["total_pr_runs"] += len(runs)
        if not runs:
            break

        for run in runs:
            if run.get("conclusion") not in ("success", "completed"):
                continue
            # Each run has a pull_requests list; check if any matches a NONE PR
            for pr_ref in run.get("pull_requests", []):
                pr_number = pr_ref.get("number")
                if pr_number in none_pr_numbers:
                    username = none_pr_numbers[pr_number]
                    result["has_none_precedent"] = True
                    if username not in result["none_users"]:
                        result["none_users"].append(username)
                    return result  # One precedent is enough
        time.sleep(0.5)

    return result


def analyze_workflow(filename: str, content: str) -> dict:
    """Parse a single workflow file and extract security-relevant info."""
    result = {
        "file": filename,
        "triggers": [],
        "trigger_types": [],
        "label_gate": None,
        "user_gate": None,
        "jobs": [],
        "secrets_used": set(),
        "runner_types": set(),
        "checkout_pr_code": False,
        "expression_injection": [],
        "permissions": None,
        "mutable_actions": [],       # Actions using mutable tags (not SHA-pinned)
        "has_oidc": False,           # id-token: write permission present
        "has_cache_write": False,    # actions/cache without fork PR guard
        "risk_score": 0,
        "verdict": "UNKNOWN",
        "details": [],
    }

    try:
        wf = yaml.safe_load(content)
    except Exception:
        result["details"].append("Failed to parse YAML")
        return result

    if not isinstance(wf, dict):
        return result

    # ── Triggers ──
    on_section = wf.get("on", wf.get(True, {}))
    if isinstance(on_section, str):
        result["triggers"].append(on_section)
        result["trigger_types"].append(on_section)
    elif isinstance(on_section, list):
        for t in on_section:
            result["triggers"].append(str(t))
            result["trigger_types"].append(str(t))
    elif isinstance(on_section, dict):
        for trigger, config in on_section.items():
            trigger_info = {"name": trigger}
            if isinstance(config, dict):
                if trigger == "pull_request_target":
                    types_list = config.get("types", [])
                    trigger_info["types"] = types_list
                    if "labeled" in types_list:
                        result["label_gate"] = True
                        result["details"].append(f"PRT trigger with 'labeled' type — label gate active")
                branches = config.get("branches", [])
                if branches:
                    trigger_info["branches"] = branches
            result["triggers"].append(trigger_info)
            result["trigger_types"].append(trigger)

    has_prt = "pull_request_target" in result["trigger_types"]
    has_pr = "pull_request" in result["trigger_types"]
    has_ic = "issue_comment" in result["trigger_types"]
    has_wfr = "workflow_run" in result["trigger_types"]

    # ── Permissions ──
    perms = wf.get("permissions", None)
    if perms:
        result["permissions"] = perms
        # OIDC detection: id-token: write enables cloud credential minting
        if isinstance(perms, dict) and perms.get("id-token") == "write":
            result["has_oidc"] = True
        elif perms == "write-all":
            result["has_oidc"] = True

    # Also check job-level permissions for OIDC
    if not result["has_oidc"]:
        jobs_dict = wf.get("jobs", {})
        if isinstance(jobs_dict, dict):
            for _jn, job_data in jobs_dict.items():
                if not isinstance(job_data, dict):
                    continue
                job_perms = job_data.get("permissions", None)
                if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
                    result["has_oidc"] = True
                    break
                elif job_perms == "write-all":
                    result["has_oidc"] = True
                    break

    # ── Raw content analysis (more reliable than YAML for GHA expressions) ──
    raw = content

    # Secrets usage
    secrets_found = re.findall(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", raw)
    result["secrets_used"] = set(secrets_found)

    # Expression injection patterns
    injections = re.findall(r"\$\{\{\s*github\.event\.([^\}]+)\}\}", raw)
    result["expression_injection"] = injections

    # Dangerous expressions that should NEVER appear in run: blocks
    # (0-click injectable: attacker controls these fields via PR body/title/comments)
    DANGEROUS_RUN_EXPRS = [
        "comment.body", "issue.body", "issue.title",
        "pull_request.body", "pull_request.title",
        "review.body", "review_comment.body",
    ]

    # Check for dangerous expressions in run: blocks
    # Handles both inline `run: echo ${{ expr }}` and multi-line `run: |` blocks
    lines = raw.split("\n")
    for danger_expr in DANGEROUS_RUN_EXPRS:
        if danger_expr not in raw:
            continue
        in_run_block = False
        run_block_indent = 0
        for line in lines:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # Detect run: block start
            if stripped.startswith("run:"):
                in_run_block = True
                run_block_indent = indent
                # Inline value on same line
                if danger_expr in stripped:
                    result["details"].append(f"⚠️ {danger_expr} in run: block — SCRIPT INJECTION RISK")
                    result["risk_score"] += 30
                    in_run_block = False
                    break
                # Multi-line block indicator (| or >)
                if "|" in stripped or ">" in stripped:
                    continue
                # Single-line value without block indicator
                in_run_block = False
                continue

            # Inside a multi-line run block
            if in_run_block:
                # If indentation drops back to or below run: level, block ended
                if indent <= run_block_indent and stripped:
                    in_run_block = False
                    continue
                if danger_expr in stripped:
                    result["details"].append(f"⚠️ {danger_expr} in run: block — SCRIPT INJECTION RISK")
                    result["risk_score"] += 30
                    break

    # ── Jobs ──
    jobs = wf.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            job_info = {"name": job_name}

            # Runner type
            runs_on = job.get("runs-on", "")
            if isinstance(runs_on, str):
                job_info["runs_on"] = runs_on
                if "self-hosted" in runs_on.lower():
                    result["runner_types"].add("self-hosted")
                else:
                    result["runner_types"].add(f"github-hosted({runs_on})")
            elif isinstance(runs_on, list):
                runners = [str(r) for r in runs_on]
                job_info["runs_on"] = runners
                if any("self-hosted" in str(r).lower() for r in runs_on):
                    result["runner_types"].add("self-hosted")
                else:
                    result["runner_types"].add("github-hosted")
            elif isinstance(runs_on, dict):
                # group: xxx format
                group = runs_on.get("group", "")
                job_info["runs_on"] = f"group:{group}"
                result["runner_types"].add(f"group:{group}")

            # If condition (gates)
            if_condition = job.get("if", "")
            if if_condition:
                job_info["if"] = str(if_condition)
                # Check for label gates
                if "label" in str(if_condition).lower():
                    result["label_gate"] = True
                    result["details"].append(f"Job '{job_name}' has label gate: {str(if_condition)[:80]}")
                # Check for user gates
                if "actor" in str(if_condition).lower() or "user.login" in str(if_condition):
                    result["user_gate"] = True
                    result["details"].append(f"Job '{job_name}' has user gate: {str(if_condition)[:80]}")
                # Check for comment.user gates
                if "comment.user" in str(if_condition) or "comment.user.login" in str(if_condition):
                    result["user_gate"] = True

            # Steps analysis
            steps = job.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue

                # Checkout analysis
                uses = step.get("uses", "")
                if "actions/checkout" in uses:
                    with_config = step.get("with", {})
                    ref = with_config.get("ref", "")
                    if any(x in ref for x in ["pull_request", "head.sha", "pull/", "merge"]):
                        result["checkout_pr_code"] = True
                        job_info["checkout_pr_code"] = True
                        result["details"].append(f"Checkout PR code: ref={ref}")

                    # Check if persist-credentials is explicitly false
                    persist_creds = with_config.get("persist-credentials", True)
                    if persist_creds is not False:
                        result["details"].append(
                            f"Checkout retains credentials (persist-credentials not false)"
                        )

                # Mutable action tag detection (#4 Tag Poisoning)
                # A mutable tag like @v4 can be repointed to a malicious commit
                # SHA pins like @b4ffde65... are immutable
                if uses and "@" in uses:
                    ref_part = uses.split("@", 1)[1]
                    # Short refs (<=40 chars) that are NOT full 40-char hex = mutable tag
                    if len(ref_part) < 40 or not re.fullmatch(r"[0-9a-f]{40}", ref_part):
                        result["mutable_actions"].append(uses)
                        result["details"].append(f"Mutable action ref: {uses}")

                # Cache usage detection (#5 Cache Poisoning)
                # actions/cache in PRT/PR context without fork guard = cache poisoning risk
                if "actions/cache" in uses or "actions/cache" in str(step.get("uses", "")):
                    step_if = str(step.get("if", ""))
                    # Check if there's a guard that prevents cache write on fork PRs
                    has_cache_guard = (
                        "github.event_name" in step_if
                        or "pull_request" in step_if
                        or "fork" in step_if.lower()
                    )
                    if not has_cache_guard and (has_prt or has_pr):
                        result["has_cache_write"] = True
                        result["details"].append(
                            f"actions/cache without fork guard in step '{step.get('name', uses)}'"
                        )

            result["jobs"].append(job_info)

    # ── Risk Scoring ──
    has_self_hosted = "self-hosted" in result["runner_types"]
    is_github_hosted = any("github-hosted" in r for r in result["runner_types"])
    is_runner_group = any("group:" in r for r in result["runner_types"])

    if has_prt and has_self_hosted:
        if result["label_gate"]:
            result["risk_score"] += 40
            result["verdict"] = "POTENTIAL (label gate required)"
        else:
            result["risk_score"] += 80
            result["verdict"] = "CRITICAL (0-click RCE possible)"

    if has_ic and has_self_hosted:
        if result["user_gate"]:
            result["risk_score"] += 30
            result["verdict"] = "POTENTIAL (user gate)"
        else:
            result["risk_score"] += 70
            result["verdict"] = "HIGH (0-click script injection)"

    if has_wfr and has_self_hosted:
        # workflow_run is triggered after another workflow completes on the same repo
        # No approval needed, runs with repo secrets, can checkout any code
        result["risk_score"] += 35
        result["details"].append("workflow_run trigger on self-hosted runner — no approval needed")
        if result["verdict"] == "UNKNOWN":
            result["verdict"] = "POTENTIAL (workflow_run, no approval)"

    if has_pr and has_self_hosted:
        result["risk_score"] += 20
        if result["verdict"] == "UNKNOWN":
            result["verdict"] = "MEDIUM (needs approval)"

    if result["checkout_pr_code"]:
        result["risk_score"] += 15

    # TOCTOU pattern: issue_comment approval + pull_request checkout
    # issue_comment webhook doesn't carry SHA → second API call creates race window
    if has_ic and (has_pr or has_prt) and result["checkout_pr_code"]:
        result["risk_score"] += 25
        result["details"].append(
            "TOCTOU risk: issue_comment trigger + checkout PR code — SHA race window"
        )
        if result["verdict"] not in ("CRITICAL (0-click RCE possible)", "HIGH (0-click script injection)"):
            result["verdict"] = "HIGH (TOCTOU race condition)"

    # OIDC token risk: id-token:write + cloud provider credentials
    # If OIDC is present and workflow runs on PR/PRT, attacker can steal cloud credentials
    if result["has_oidc"] and (has_prt or has_pr or has_ic):
        result["risk_score"] += 20
        result["details"].append(
            "OIDC (id-token:write) with PR trigger — cloud credential theft possible"
        )

    # Cache poisoning risk: fork PR can write cache → privileged workflow executes it
    if result["has_cache_write"] and (has_prt or has_pr):
        result["risk_score"] += 15
        result["details"].append(
            "Cache poisoning risk: actions/cache without fork guard"
        )

    # Mutable action tags: @v1/@v2 can be repointed to malicious commits
    if result["mutable_actions"]:
        result["risk_score"] += 5
        result["details"].append(
            f"Tag poisoning risk: {len(result['mutable_actions'])} mutable action ref(s)"
        )

    if result["secrets_used"]:
        result["risk_score"] += 10 * min(len(result["secrets_used"]), 5)
        result["details"].append(f"Secrets exposed: {', '.join(sorted(result['secrets_used']))}")

    if is_github_hosted and not has_self_hosted and not is_runner_group:
        result["risk_score"] = 0
        result["verdict"] = "SAFE (GitHub-hosted)"

    if is_runner_group and not has_self_hosted:
        # Runner groups could be GitHub-hosted larger runners or self-hosted groups
        # group: "Default" (capital D) typically = self-hosted in enterprise
        # group: "ubuntu-latest" or lowercase = GitHub-hosted larger runner
        result["verdict"] = "MANUAL_REVIEW (runner group — verify if self-hosted)"
        result["risk_score"] = max(result["risk_score"], 5)
        result["details"].append("Note: runner group may be GitHub-hosted larger runner — verify manually")

    if not has_self_hosted and not is_runner_group and not is_github_hosted:
        result["verdict"] = "SAFE"

    return result


def analyze_repo(rotator: TokenRotator, repo: str, trigger_types: list[str]) -> dict:
    """Full analysis of a single repo."""
    token = rotator.next()
    result = {
        "repo": repo,
        "trigger_types": trigger_types,
        "workflows": [],
        "has_self_hosted": False,
        "has_prt": False,
        "has_ic": False,
        "has_wfr": False,
        "secrets_total": set(),
        "mutable_actions_total": [],
        "has_oidc": False,
        "has_cache_risk": False,
        "highest_risk": 0,
        "verdict": "UNKNOWN",
        "none_approval": None,
    }

    print(f"  Analyzing {repo}...", end=" ", flush=True)

    # Download workflow files
    wf_files = get_workflow_files(token, repo)
    if not wf_files:
        print("no workflow files found")
        result["verdict"] = "NO_WORKFLOWS"
        return result

    # Analyze each file
    for filename, content in wf_files.items():
        analysis = analyze_workflow(filename, content)
        result["workflows"].append(analysis)

        if "self-hosted" in analysis["runner_types"]:
            result["has_self_hosted"] = True
        if "pull_request_target" in analysis["trigger_types"]:
            result["has_prt"] = True
        if "issue_comment" in analysis["trigger_types"]:
            result["has_ic"] = True
        if "workflow_run" in analysis["trigger_types"]:
            result["has_wfr"] = True
        result["secrets_total"].update(analysis["secrets_used"])
        result["mutable_actions_total"].extend(analysis["mutable_actions"])
        if analysis["has_oidc"]:
            result["has_oidc"] = True
        if analysis["has_cache_write"]:
            result["has_cache_risk"] = True
        if analysis["risk_score"] > result["highest_risk"]:
            result["highest_risk"] = analysis["risk_score"]
            result["verdict"] = analysis["verdict"]

    # For PR-only repos with self-hosted (no PRT/IC/WFR), check NONE user approval history
    if result["has_self_hosted"] and not result["has_prt"] and not result["has_ic"] and not result["has_wfr"]:
        token = rotator.next()
        result["none_approval"] = check_none_approval(token, repo)
        if not result["none_approval"]["has_none_precedent"]:
            if result["verdict"] == "MEDIUM (needs approval)":
                result["verdict"] = "NOT EXPLOITABLE (no NONE approval precedent)"
                result["highest_risk"] = max(0, result["highest_risk"] - 15)

    verdict_short = result["verdict"][:40]
    print(f"{len(wf_files)} files → {verdict_short}")

    return result


def run_analysis(scan_results: dict, rotator: TokenRotator) -> dict:
    """Analyze all repos from scan results."""
    all_repos = scan_results.get("all_repos", [])

    # Deduplicate repos
    repo_map = {}
    for r in all_repos:
        repo = r["repo"]
        if repo not in repo_map:
            repo_map[repo] = {"trigger_types": set(), "vendor": r.get("vendor", "")}
        repo_map[repo]["trigger_types"].add(r.get("query_type", ""))

    print(f"Analyzing {len(repo_map)} repos...\n")

    results = []
    for repo, info in sorted(repo_map.items()):
        result = analyze_repo(rotator, repo, sorted(info["trigger_types"]))
        result["vendor"] = info["vendor"]
        results.append(result)
        time.sleep(1)

    # Sort by risk score
    results.sort(key=lambda x: x["highest_risk"], reverse=True)

    return {
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(results),
        "results": results,
        "summary": generate_summary(results),
    }


def generate_summary(results: list[dict]) -> dict:
    """Generate summary statistics."""
    summary = {
        "critical": [],
        "high": [],
        "potential": [],
        "manual_review": [],
        "not_exploitable": [],
        "safe": [],
        "github_hosted": [],
    }

    for r in results:
        verdict = r["verdict"]
        entry = {
            "repo": r["repo"],
            "vendor": r.get("vendor", ""),
            "risk_score": r["highest_risk"],
            "verdict": verdict,
            "triggers": r["trigger_types"],
            "has_self_hosted": r["has_self_hosted"],
            "has_oidc": r.get("has_oidc", False),
            "has_cache_risk": r.get("has_cache_risk", False),
            "mutable_actions_count": len(r.get("mutable_actions_total", [])),
            "secrets": sorted(r["secrets_total"]) if r["secrets_total"] else [],
        }

        if "CRITICAL" in verdict:
            summary["critical"].append(entry)
        elif "HIGH" in verdict:
            summary["high"].append(entry)
        elif "POTENTIAL" in verdict or "MEDIUM" in verdict:
            summary["potential"].append(entry)
        elif "MANUAL_REVIEW" in verdict:
            summary["manual_review"].append(entry)
        elif "NOT EXPLOITABLE" in verdict:
            summary["not_exploitable"].append(entry)
        elif "SAFE" in verdict or "GITHUB" in verdict.upper():
            summary["github_hosted"].append(entry)
        else:
            summary["safe"].append(entry)

    return summary


def write_report(analysis: dict, output_path: str):
    """Write detailed analysis report."""
    # Clean sets/lists for JSON serialization
    for r in analysis["results"]:
        r["secrets_total"] = sorted(r["secrets_total"]) if r["secrets_total"] else []
        r["mutable_actions_total"] = list(set(r.get("mutable_actions_total", [])))
        for wf in r["workflows"]:
            wf["secrets_used"] = sorted(wf["secrets_used"]) if wf["secrets_used"] else []
            wf["runner_types"] = sorted(wf["runner_types"]) if wf["runner_types"] else []
            wf["mutable_actions"] = list(set(wf.get("mutable_actions", [])))

    Path(output_path).write_text(json.dumps(analysis, indent=2, ensure_ascii=False) + "\n")


def write_summary_txt(analysis: dict, output_path: str):
    """Write human-readable summary."""
    summary = analysis["summary"]
    lines = [
        f"CI/CD Workflow Security Analysis Report — {analysis['analysis_time']}",
        f"{'=' * 70}",
        f"Total repos analyzed: {analysis['total_repos']}",
        f"CRITICAL (0-click RCE): {len(summary['critical'])}",
        f"HIGH (0-click injection): {len(summary['high'])}",
        f"POTENTIAL (gate required): {len(summary['potential'])}",
        f"MANUAL_REVIEW (runner group): {len(summary['manual_review'])}",
        f"NOT EXPLOITABLE: {len(summary['not_exploitable'])}",
        f"SAFE/GitHub-hosted: {len(summary['github_hosted']) + len(summary['safe'])}",
        "",
    ]

    for category, label in [
        ("critical", "CRITICAL — 0-Click RCE"),
        ("high", "HIGH — 0-Click Script Injection"),
        ("potential", "POTENTIAL — Gate Required"),
        ("manual_review", "MANUAL_REVIEW — Runner Group (verify if self-hosted)"),
        ("not_exploitable", "NOT EXPLOITABLE"),
    ]:
        items = summary.get(category, [])
        if not items:
            continue
        lines.append(f"{'=' * 70}")
        lines.append(f"{label} ({len(items)})")
        lines.append(f"{'=' * 70}")
        for item in items:
            extras = []
            if item["secrets"]:
                extras.append(f"secrets: {', '.join(item['secrets'])}")
            if item.get("has_oidc"):
                extras.append("OIDC: yes")
            if item.get("has_cache_risk"):
                extras.append("cache-risk: yes")
            if item.get("mutable_actions_count", 0) > 0:
                extras.append(f"mutable-refs: {item['mutable_actions_count']}")
            extras_str = f" | {' | '.join(extras)}" if extras else ""
            lines.append(f"  {item['repo']} ({item['vendor']})")
            lines.append(f"    triggers: {', '.join(item['triggers'])} | risk={item['risk_score']}{extras_str}")
            lines.append(f"    verdict: {item['verdict']}")
            lines.append("")

    Path(output_path).write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="CI/CD Workflow Security Analyzer")
    parser.add_argument("--input", required=True, help="Path to scan_results.json")
    parser.add_argument("--output", default="analysis_report.json", help="Output analysis JSON")
    parser.add_argument("--summary", default="analysis_summary.txt", help="Output summary text")
    args = parser.parse_args()

    tokens_str = os.environ.get("SCAN_TOKENS", "")
    if not tokens_str:
        print("ERROR: SCAN_TOKENS environment variable not set")
        sys.exit(1)
    tokens = [t.strip() for t in tokens_str.split(",") if t.strip()]
    rotator = TokenRotator(tokens)

    scan_results = json.loads(Path(args.input).read_text())
    analysis = run_analysis(scan_results, rotator)

    write_report(analysis, args.output)
    write_summary_txt(analysis, args.summary)

    print(f"\n{'=' * 70}")
    print(f"Analysis complete: {analysis['total_repos']} repos")
    s = analysis["summary"]
    print(f"  CRITICAL: {len(s['critical'])} | HIGH: {len(s['high'])} | POTENTIAL: {len(s['potential'])} | NOT EXPLOITABLE: {len(s['not_exploitable'])}")
    print(f"  Report: {args.output}")
    print(f"  Summary: {args.summary}")


if __name__ == "__main__":
    main()
