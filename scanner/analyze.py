#!/usr/bin/env python3
"""CI/CD Workflow Security Analyzer.

Analyzes GitHub Actions workflow files from scan results to assess
security risks including RCE, credential theft, and supply chain attacks.

Usage:
    python analyze.py --input scan_results.json --output analysis_report.json
"""

import argparse
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


# Known AI code review tools that can be prompted via PR body/diff
AI_REVIEW_ACTIONS = {
    "coderabbitai/ai-pr-reviewer": "CodeRabbit AI PR Reviewer",
    "sourcery-ai/sourcery": "Sourcery AI Review",
    "qodo-ai/qodo-merge-pro": "Qodo Merge Pro (ex: CodiumAI)",
    "codedog-ai/codedog": "CodeDog AI Review",
    "moonlight-ai/moonlight": "Moonlight AI Review",
    "bugfree-ai/bugfree": "BugFree AI Review",
    "reviewpad/action": "Reviewpad (AI-assisted)",
    "deepseek-ai/deepseek-reviewer": "DeepSeek AI Reviewer",
    "amai-ai/automatic-code-review": "AMAI Code Review",
    "microsoft/code-review-action": "Microsoft Code Review",
}

# Known AI review bot names (for app_audit fallback cross-reference)
AI_REVIEW_BOTS = {
    "coderabbitai", "coderabbit", "sourcery-ai", "sourcery",
    "qodo-ai", "qodo", "codiumai", "deepseek-reviewer",
    "chatgpt-codex", "gemini-code-assist",
}

# Publish commands that indicate package publishing capability
PUBLISH_PATTERNS = [
    (r"\bnpm\s+publish\b", "npm publish"),
    (r"\bnpm\s+run\s+.*publish", "npm run publish"),
    (r"\btwine\s+upload\b", "twine upload (PyPI)"),
    (r"\bpython\s+.*setup\.py\s+.*upload\b", "setup.py upload (PyPI)"),
    (r"\bcargo\s+publish\b", "cargo publish (crates.io)"),
    (r"\bgem\s+push\b", "gem push (RubyGems)"),
    (r"\bgradle\s+.*publish", "gradle publish (Maven)"),
    (r"\bmvn\s+deploy\b", "mvn deploy (Maven)"),
    (r"\bdotnet\s+nuget\s+push\b", "dotnet nuget push (NuGet)"),
    (r"\bpod\s+trunk\s+push\b", "pod trunk push (CocoaPods)"),
]


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
            if resp.status_code in (404, 401):
                return None
            if resp.status_code != 200:
                return None
            return resp.json()
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(3)
    return None


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
        "config_abuse_risks": [],    # Dynaconf dynamic variable abuse patterns
        "has_ai_review": False,      # AI code review tools present
        "ai_review_tools": [],       # Names of detected AI tools
        "has_publish_capability": False,  # Package publish commands present
        "publish_tools": [],         # Names of detected publish tools
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
                elif trigger == "issue_comment":
                    types_list = config.get("types", ["created", "edited"])
                    trigger_info["types"] = types_list
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
    DANGEROUS_RUN_EXPRS = [
        "comment.body", "issue.body", "issue.title",
        "pull_request.body", "pull_request.title",
        "review.body", "review_comment.body",
    ]

    # Check for dangerous expressions in run: blocks
    lines = raw.split("\n")
    for danger_expr in DANGEROUS_RUN_EXPRS:
        if danger_expr not in raw:
            continue
        in_run_block = False
        run_block_indent = 0
        for line in lines:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if stripped.startswith("run:"):
                in_run_block = True
                run_block_indent = indent
                if danger_expr in stripped:
                    result["details"].append(f"\u26a0\ufe0f {danger_expr} in run: block — SCRIPT INJECTION RISK")
                    result["risk_score"] += 30
                    in_run_block = False
                    break
                if "|" in stripped or ">" in stripped:
                    continue
                in_run_block = False
                continue

            if in_run_block:
                if indent <= run_block_indent and stripped:
                    in_run_block = False
                    continue
                if danger_expr in stripped:
                    result["details"].append(f"\u26a0\ufe0f {danger_expr} in run: block — SCRIPT INJECTION RISK")
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
                group = runs_on.get("group", "")
                job_info["runs_on"] = f"group:{group}"
                result["runner_types"].add(f"group:{group}")

            # If condition (gates)
            if_condition = job.get("if", "")
            if if_condition:
                job_info["if"] = str(if_condition)
                if "label" in str(if_condition).lower():
                    result["label_gate"] = True
                    result["details"].append(f"Job '{job_name}' has label gate: {str(if_condition)[:80]}")
                if "actor" in str(if_condition).lower() or "user.login" in str(if_condition):
                    result["user_gate"] = True
                    result["details"].append(f"Job '{job_name}' has user gate: {str(if_condition)[:80]}")
                if "comment.user" in str(if_condition) or "comment.user.login" in str(if_condition):
                    result["user_gate"] = True

            # Steps analysis
            steps = job.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")

                # Checkout analysis
                if "actions/checkout" in uses:
                    with_config = step.get("with", {})
                    ref = with_config.get("ref", "")
                    if any(x in ref for x in ["pull_request", "head.sha", "pull/", "merge"]):
                        result["checkout_pr_code"] = True
                        job_info["checkout_pr_code"] = True
                        result["details"].append(f"Checkout PR code: ref={ref}")

                    persist_creds = with_config.get("persist-credentials", True)
                    if persist_creds is not False:
                        result["details"].append(
                            f"Checkout retains credentials (persist-credentials not false)"
                        )

                # Mutable action tag detection (#4 Tag Poisoning)
                if uses and "@" in uses:
                    ref_part = uses.split("@", 1)[1]
                    if len(ref_part) < 40 or not re.fullmatch(r"[0-9a-f]{40}", ref_part):
                        result["mutable_actions"].append(uses)
                        result["details"].append(f"Mutable action ref: {uses}")

                # Cache usage detection (#5 Cache Poisoning)
                if "actions/cache" in uses or "actions/cache" in str(step.get("uses", "")):
                    step_if = str(step.get("if", ""))
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

                # AI code review tool detection (#6)
                uses_lower = uses.lower()
                for action_ref, tool_name in AI_REVIEW_ACTIONS.items():
                    if action_ref.lower() in uses_lower:
                        result["has_ai_review"] = True
                        result["ai_review_tools"].append(tool_name)
                        result["details"].append(f"AI review tool: {tool_name} ({uses})")

                # Also check run: steps for AI review CLI tools
                run_content = step.get("run", "")
                if run_content:
                    for ai_cli in ["coderabbit", "sourcery", "qodo", "deepseek-reviewer"]:
                        if ai_cli in str(run_content).lower():
                            if ai_cli not in [t.lower() for t in result["ai_review_tools"]]:
                                result["has_ai_review"] = True
                                result["ai_review_tools"].append(ai_cli)

            # ── Publish capability detection (#8) ──
            # Scan all run: blocks in this job for publish commands
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run_content = str(step.get("run", ""))
                if not run_content:
                    continue
                for pattern, pub_name in PUBLISH_PATTERNS:
                    if re.search(pattern, run_content, re.IGNORECASE):
                        result["has_publish_capability"] = True
                        if pub_name not in result["publish_tools"]:
                            result["publish_tools"].append(pub_name)
                            result["details"].append(f"Publish capability: {pub_name}")

            result["jobs"].append(job_info)

    # ── Config Library Abuse Detection (#11) ──
    DYNACONF_PATTERNS = [
        (r"@format\s*\{[^}]*env[^}]*\}", "HIGH", "@format with env \u2192 environment variable leak"),
        (r"@jinja\s*\{", "HIGH", "@jinja \u2192 Jinja2 template injection (attribute access/RCE)"),
        (r"@json\s*\{", "MEDIUM", "@json \u2192 dynamic object construction"),
        (r"dynaconf_include", "HIGH", "dynaconf_include \u2192 file inclusion (arbitrary .py execution)"),
        (r"AUTO_CAST_FOR_DYNACONF", "MEDIUM", "AUTO_CAST_FOR_DYNACONF \u2192 dynamic variable engine active"),
    ]
    for pattern, severity, description in DYNACONF_PATTERNS:
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            result["config_abuse_risks"].append({
                "pattern": pattern,
                "severity": severity,
                "description": description,
                "count": len(matches),
            })
            result["details"].append(f"Config abuse ({severity}): {description} (\u00d7{len(matches)})")

    # ── Risk Scoring ──
    has_self_hosted = "self-hosted" in result["runner_types"]
    is_github_hosted = any("github-hosted" in r for r in result["runner_types"])
    is_runner_group = any("group:" in r for r in result["runner_types"])

    # ── Trigger + Runner combos (core RCE paths) ──
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
        result["risk_score"] += 35
        result["details"].append("workflow_run trigger on self-hosted runner — no approval needed")
        if result["verdict"] == "UNKNOWN":
            result["verdict"] = "POTENTIAL (workflow_run, no approval)"

    if has_pr and has_self_hosted:
        result["risk_score"] += 20
        if result["verdict"] == "UNKNOWN":
            result["verdict"] = "MEDIUM (needs approval)"

    # ── GitHub-hosted trigger combos ──
    # GitHub-hosted runners can't be persisted, but secrets/OIDC/cache are still at risk
    if is_github_hosted and not has_self_hosted and not is_runner_group:
        if has_prt:
            result["risk_score"] += 50
            result["verdict"] = "HIGH (PRT on GitHub-hosted — secrets injectable)"
            result["details"].append("pull_request_target on GitHub-hosted — secrets still injectable")
        if has_ic and not result["user_gate"]:
            result["risk_score"] += 40
            if result["verdict"] == "UNKNOWN":
                result["verdict"] = "MEDIUM (IC on GitHub-hosted — script injection)"
            result["details"].append("issue_comment on GitHub-hosted — script injection possible")
        if has_pr:
            result["risk_score"] += 10
            if result["verdict"] == "UNKNOWN":
                result["verdict"] = "LOW (PR on GitHub-hosted — secrets not injectable)"

    # ── Cross-cutting risk factors (apply to both self-hosted and GitHub-hosted) ──

    if result["checkout_pr_code"]:
        result["risk_score"] += 15

    # TOCTOU pattern: issue_comment approval + pull_request checkout
    if has_ic and (has_pr or has_prt) and result["checkout_pr_code"]:
        result["risk_score"] += 25
        result["details"].append(
            "TOCTOU risk: issue_comment trigger + checkout PR code — SHA race window"
        )
        if result["verdict"] not in ("CRITICAL (0-click RCE possible)", "HIGH (0-click script injection)"):
            result["verdict"] = "HIGH (TOCTOU race condition)"

    # OIDC token risk
    if result["has_oidc"] and (has_prt or has_pr or has_ic):
        result["risk_score"] += 20
        result["details"].append(
            "OIDC (id-token:write) with PR trigger — cloud credential theft possible"
        )

    # Cache poisoning risk
    if result["has_cache_write"] and (has_prt or has_pr):
        result["risk_score"] += 15
        result["details"].append(
            "Cache poisoning risk: actions/cache without fork guard"
        )

    # Mutable action tags
    if result["mutable_actions"]:
        result["risk_score"] += 5
        result["details"].append(
            f"Tag poisoning risk: {len(result['mutable_actions'])} mutable action ref(s)"
        )

    # Config library abuse scoring (#11)
    for abuse in result["config_abuse_risks"]:
        if abuse["severity"] == "HIGH":
            result["risk_score"] += 25
        elif abuse["severity"] == "MEDIUM":
            result["risk_score"] += 10
    if result["config_abuse_risks"] and result["secrets_used"] and (has_prt or has_pr or has_ic):
        result["risk_score"] += 30
        result["details"].append(
            "CRITICAL combo: config library dynamic vars + secrets + PR trigger \u2192 credential leak"
        )
        if "CRITICAL" not in result["verdict"] and "HIGH" not in result["verdict"]:
            result["verdict"] = "HIGH (config library abuse \u2192 credential leak)"

    if result["secrets_used"]:
        result["risk_score"] += 10 * min(len(result["secrets_used"]), 5)
        result["details"].append(f"Secrets exposed: {', '.join(sorted(result['secrets_used']))}")

    # AI review tool detection — additional attack vector (#6)
    # AI tools can be prompted via PR body/diff to approve malicious code
    if result["has_ai_review"] and (has_prt or has_pr or has_ic):
        result["risk_score"] += 15
        result["details"].append(
            f"AI review bypass risk: {', '.join(result['ai_review_tools'])} — prompt injection via PR body/diff"
        )

    # Publish capability — high-value target marker (#8)
    # Not an independent attack path, but RCE on these repos enables supply chain poisoning
    if result["has_publish_capability"]:
        result["risk_score"] += 5
        result["details"].append(
            f"HIGH-VALUE TARGET: publish capability ({', '.join(result['publish_tools'])}) — RCE \u2192 supply chain poisoning"
        )

    # ── Final verdict adjustments ──

    # If still UNKNOWN after all checks, and no dangerous triggers → SAFE
    if result["verdict"] == "UNKNOWN" and result["risk_score"] == 0:
        result["verdict"] = "SAFE"

    # Runner group needs manual verification
    if is_runner_group and not has_self_hosted:
        result["verdict"] = "MANUAL_REVIEW (runner group — verify if self-hosted)"
        result["risk_score"] = max(result["risk_score"], 5)
        result["details"].append("Note: runner group may be GitHub-hosted larger runner — verify manually")

    return result


def check_none_approval(token: str, repo: str) -> dict:
    """Check if NONE-user PRs have been approved and triggered CI before.

    This determines if a first-time contributor can get automatic CI runs.
    For pull_request trigger, GitHub requires maintainer approval for first-time
    contributors. If there's a precedent of NONE-user approval, returning
    contributors get auto-approved.
    """
    result = {"has_none_precedent": False, "none_prs": [], "approved_prs": []}

    # Get PRs by NONE user (first-time contributors)
    prs_data = api_get(token, f"{API}/repos/{repo}/pulls?state=all&per_page=50")
    if not prs_data or not isinstance(prs_data, list):
        return result

    none_prs = []
    for pr in prs_data:
        author_assoc = pr.get("author_association", "")
        if author_assoc == "NONE":
            none_prs.append(pr["number"])

    if not none_prs:
        return result

    result["none_prs"] = none_prs

    # Get workflow runs and check if any NONE-user PR was completed
    runs_data = api_get(token, f"{API}/repos/{repo}/actions/runs?per_page=100&status=completed")
    if not runs_data or not isinstance(runs_data, dict):
        return result

    runs = runs_data.get("workflow_runs", [])
    for run in runs:
        pr_refs = run.get("pull_requests", [])
        for pr_ref in pr_refs:
            pr_num = pr_ref.get("number")
            if pr_num in none_prs:
                result["has_none_precedent"] = True
                result["approved_prs"].append(pr_num)
                break

    return result


def analyze_repo(rotator: TokenRotator, repo: str, trigger_types: list[str], query_labels: list[str] | None = None) -> dict:
    """Full analysis of a single repo."""
    token = rotator.next()
    result = {
        "repo": repo,
        "trigger_types": trigger_types,
        "query_labels": query_labels or [],
        "workflows": [],
        "secrets_total": set(),
        "mutable_actions_total": [],
        "has_self_hosted": False,
        "has_prt": "pull_request_target" in trigger_types,
        "has_ic": "issue_comment" in trigger_types,
        "has_pr": "pull_request" in trigger_types,
        "has_wfr": "workflow_run" in trigger_types,
        "has_oidc": False,
        "has_cache_risk": False,
        "has_ai_review": False,
        "ai_review_tools": [],
        "has_publish_capability": False,
        "publish_tools": [],
        "highest_risk": 0,
        "verdict": "UNKNOWN",
        "none_approval": None,
    }

    # Get all workflow files
    wf_data = api_get(token, f"{API}/repos/{repo}/contents/.github/workflows")
    if not wf_data or not isinstance(wf_data, list):
        print(f"  {repo}: no workflows found or API error")
        result["verdict"] = "NO_WORKFLOWS"
        return result

    wf_files = [f["name"] for f in wf_data if f["name"].endswith((".yml", ".yaml"))]
    print(f"  {repo}: {len(wf_files)} workflow files", end="", flush=True)

    for wf_file in wf_files:
        token = rotator.next()
        content_data = api_get(token, f"{API}/repos/{repo}/contents/.github/workflows/{wf_file}")
        if not content_data or not isinstance(content_data, dict):
            continue

        import base64
        content = base64.b64decode(content_data.get("content", "")).decode("utf-8", errors="replace")

        analysis = analyze_workflow(wf_file, content)
        result["workflows"].append(analysis)

        # Aggregate
        result["secrets_total"].update(analysis["secrets_used"])
        result["mutable_actions_total"].extend(analysis["mutable_actions"])
        if "self-hosted" in analysis["runner_types"]:
            result["has_self_hosted"] = True
        if analysis["has_oidc"]:
            result["has_oidc"] = True
        if analysis["has_cache_write"]:
            result["has_cache_risk"] = True
        if analysis["has_ai_review"]:
            result["has_ai_review"] = True
            result["ai_review_tools"].extend(analysis["ai_review_tools"])
        if analysis["has_publish_capability"]:
            result["has_publish_capability"] = True
            result["publish_tools"].extend(analysis["publish_tools"])
        if analysis["risk_score"] > result["highest_risk"]:
            result["highest_risk"] = analysis["risk_score"]
            result["verdict"] = analysis["verdict"]

    # Deduplicate
    result["ai_review_tools"] = list(dict.fromkeys(result["ai_review_tools"]))
    result["publish_tools"] = list(dict.fromkeys(result["publish_tools"]))

    # For PR-only repos with self-hosted (no PRT/IC/WFR), check NONE user approval history
    if result["has_self_hosted"] and not result["has_prt"] and not result["has_ic"] and not result["has_wfr"]:
        token = rotator.next()
        result["none_approval"] = check_none_approval(token, repo)
        if not result["none_approval"]["has_none_precedent"]:
            if result["verdict"] == "MEDIUM (needs approval)":
                result["verdict"] = "NOT EXPLOITABLE (no NONE approval precedent)"
                result["highest_risk"] = max(0, result["highest_risk"] - 15)

    verdict_short = result["verdict"][:40]
    print(f" \u2192 {verdict_short}")

    return result


def run_analysis(scan_results: dict, rotator: TokenRotator) -> dict:
    """Analyze all repos from scan results."""
    all_repos = scan_results.get("all_repos", [])

    # Map query labels to canonical trigger types
    # PRT/PRTGH → pull_request_target, IC/ICGH → issue_comment, etc.
    QUERY_TRIGGER_MAP = {
        "PRT": "pull_request_target", "PRTGH": "pull_request_target",
        "PR": "pull_request", "PRGH": "pull_request",
        "IC": "issue_comment", "ICGH": "issue_comment",
        "ICE": "issue_comment",
        "WFR": "workflow_run",
        "OIDC": "pull_request_target",
        "CACHE": "pull_request_target", "CACHGH": "pull_request_target",
        "AIREV": "pull_request_target",
        "PUBPRT": "pull_request_target",
        "DYNF": "pull_request_target", "DYNJ": "pull_request_target", "DYNL": "pull_request_target",
    }

    # Deduplicate repos
    repo_map = {}
    for r in all_repos:
        repo = r["repo"]
        if repo not in repo_map:
            repo_map[repo] = {"trigger_types": set(), "vendor": r.get("vendor", ""), "query_labels": set()}
        qt = r.get("query_type", "")
        canonical = QUERY_TRIGGER_MAP.get(qt, qt)
        repo_map[repo]["trigger_types"].add(canonical)
        repo_map[repo]["query_labels"].add(qt)

    print(f"Analyzing {len(repo_map)} repos...\n")

    results = []
    for repo, info in sorted(repo_map.items()):
        result = analyze_repo(rotator, repo, sorted(info["trigger_types"]), sorted(info["query_labels"]))
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
            "has_ai_review": r.get("has_ai_review", False),
            "has_publish_capability": r.get("has_publish_capability", False),
            "mutable_actions_count": len(r.get("mutable_actions_total", [])),
            "config_abuse_count": sum(len(wf.get("config_abuse_risks", [])) for wf in r.get("workflows", [])),
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
        elif "SAFE" in verdict or "GITHUB" in verdict.upper() or "LOW" in verdict.upper():
            summary["github_hosted"].append(entry)
        else:
            summary["safe"].append(entry)

    return summary


def write_report(analysis: dict, output_path: str):
    """Write detailed analysis report."""
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
        f"CI/CD Workflow Security Analysis Report \u2014 {analysis['analysis_time']}",
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
        ("critical", "CRITICAL \u2014 0-Click RCE"),
        ("high", "HIGH \u2014 0-Click Script Injection"),
        ("potential", "POTENTIAL \u2014 Gate Required"),
        ("manual_review", "MANUAL_REVIEW \u2014 Runner Group (verify if self-hosted)"),
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
            if item.get("has_ai_review"):
                extras.append("AI-review: yes")
            if item.get("has_publish_capability"):
                extras.append("PUBLISH: yes")
            if item.get("mutable_actions_count", 0) > 0:
                extras.append(f"mutable-refs: {item['mutable_actions_count']}")
            if item.get("config_abuse_count", 0) > 0:
                extras.append(f"config-abuse: {item['config_abuse_count']}")
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
