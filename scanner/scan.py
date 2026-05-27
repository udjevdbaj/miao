#!/usr/bin/env python3
"""CI/CD Self-Hosted Runner Security Scanner.

Scans GitHub organizations for repos with self-hosted runners
exposed via pull_request_target / pull_request / issue_comment triggers.
Compares against a baseline file to detect new repos.

Usage:
    python scan.py --config config/orgs.json --baseline baselines/baseline.json [--output results.json] [--init] [--summary summary.txt]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

API_URL = "https://api.github.com/search/code"
PER_PAGE = 100


class TokenRotator:
    """Round-robin token rotation with rate limit awareness."""

    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.idx = 0

    def next(self) -> str:
        token = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return token


def search_code(token: str, query: str, org: str) -> dict:
    """Execute a single GitHub Code Search API query."""
    full_query = f"{query}+org:{org}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    resp = requests.get(
        API_URL, params={"q": full_query, "per_page": PER_PAGE}, headers=headers, timeout=30
    )
    data = resp.json()

    if resp.status_code == 403 or "rate limit" in data.get("message", "").lower():
        return {"error": "rate_limited"}

    if "total_count" not in data:
        return {"error": data.get("message", "unknown")[:80]}

    repos = {}
    for item in data.get("items", []):
        repo = item["repository"]["full_name"]
        repos.setdefault(repo, []).append(item["path"])

    return {"total": data["total_count"], "repos": repos}


def search_with_retry(
    rotator: TokenRotator, org: str, query: str, max_retries: int = 5, wait: int = 45
) -> dict:
    """Search with automatic token rotation and rate limit retry.

    Strategy:
    - Round-robin through all available tokens
    - On rate limit: wait + switch to next token
    - Exponential backoff: 45s, 60s, 75s, 90s, 105s
    - Up to max_retries attempts (default 5)
    """
    for attempt in range(1, max_retries + 1):
        token = rotator.next()
        result = search_code(token, query, org)

        if result.get("error") == "rate_limited":
            backoff = wait + (attempt - 1) * 15  # 45, 60, 75, 90, 105
            print(f"  [RATE LIMIT] attempt {attempt}/{max_retries}, token rotated, waiting {backoff}s...")
            time.sleep(backoff)
            continue

        if "error" in result:
            print(f"  [ERROR] {result['error']} — {org}")
            return result

        return result

    return {"error": "max_retries_exceeded"}


def load_baseline(path: str) -> dict:
    """Load baseline JSON file."""
    p = Path(path)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_baseline(path: str, data: dict):
    """Save baseline JSON file."""
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def run_scan(config: dict, rotator: TokenRotator, baseline: dict, settings: dict) -> dict:
    """Execute full scan across all configured orgs and queries."""
    sleep_time = settings.get("sleep_between_requests", 8)
    max_retries = settings.get("max_retries", 3)
    rate_limit_wait = settings.get("rate_limit_wait", 30)

    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "new_repos": [],
        "all_repos": [],       # ALL repos found (new + known)
        "total_queries": 0,
        "total_results": 0,
        "total_orgs": 0,
        "total_repos": 0,
        "errors": [],
        "details": [],
    }

    for vendor in config["vendors"]:
        vendor_name = vendor["name"]
        print(f"\n>> {vendor_name}")

        for org in vendor["orgs"]:
            results["total_orgs"] += 1
            for q in config["queries"]:
                results["total_queries"] += 1
                label = q["name"]

                result = search_with_retry(
                    rotator, org, q["query"], max_retries, rate_limit_wait
                )

                if "error" in result:
                    results["errors"].append({"org": org, "query": label, "error": result["error"]})
                    time.sleep(sleep_time)
                    continue

                total = result.get("total", 0)
                results["total_results"] += total

                # Always record details, even with 0 results
                repos_found = result.get("repos", {})
                new_in_query = []
                for repo in repos_found:
                    is_new = repo not in baseline
                    if is_new:
                        new_in_query.append(repo)
                        results["new_repos"].append(
                            {
                                "vendor": vendor_name,
                                "org": org,
                                "query_type": label,
                                "repo": repo,
                                "files": repos_found[repo],
                            }
                        )
                    results["all_repos"].append(
                        {
                            "vendor": vendor_name,
                            "org": org,
                            "query_type": label,
                            "repo": repo,
                            "is_new": is_new,
                            "files": repos_found[repo],
                        }
                    )

                if total > 0:
                    print(f"  {org} | {label} | {total} results")
                    if new_in_query:
                        print(f"    [NEW] {', '.join(new_in_query)}")

                # Always add detail entry (even 0 results for visibility)
                results["details"].append(
                    {
                        "vendor": vendor_name,
                        "org": org,
                        "query_type": label,
                        "total": total,
                        "repos": list(repos_found.keys()),
                        "new_repos": new_in_query,
                    }
                )

                time.sleep(sleep_time)

    # Deduplicate repos count
    unique_repos = set(r["repo"] for r in results["all_repos"])
    results["total_repos"] = len(unique_repos)

    return results


def update_baseline(baseline: dict, results: dict) -> dict:
    """Add all discovered repos to baseline."""
    for repo_info in results.get("all_repos", []):
        baseline[repo_info["repo"]] = True
    baseline["_last_scan"] = results["scan_time"]
    baseline["_scan_count"] = baseline.get("_scan_count", 0) + 1
    return baseline


def write_summary(results: dict, output_path: str):
    """Write human-readable summary to file."""
    lines = [
        f"CI/CD Security Scan Report — {results['scan_time']}",
        f"{'=' * 60}",
        f"Orgs scanned: {results['total_orgs']}",
        f"Total queries: {results['total_queries']}",
        f"Total results: {results['total_results']}",
        f"Unique repos: {results['total_repos']}",
        f"New repos: {len(results['new_repos'])}",
        f"Errors: {len(results['errors'])}",
        "",
    ]

    if results["new_repos"]:
        lines.append("=" * 60)
        lines.append(f"NEW REPOS ({len(results['new_repos'])})")
        lines.append("=" * 60)
        for nr in results["new_repos"]:
            lines.append(
                f"  [{nr['vendor']}] {nr['repo']} ({nr['query_type']}) — {nr['files']}"
            )
        lines.append("")

    if results["all_repos"]:
        lines.append("=" * 60)
        lines.append(f"ALL MATCHING REPOS ({results['total_repos']})")
        lines.append("=" * 60)
        # Group by vendor
        by_vendor = {}
        for r in results["all_repos"]:
            by_vendor.setdefault(r["vendor"], []).append(r)
        for vendor, repos in sorted(by_vendor.items()):
            unique = {r["repo"] for r in repos}
            lines.append(f"\n  [{vendor}] ({len(unique)} repos)")
            for repo in sorted(unique):
                repo_info = next(r for r in repos if r["repo"] == repo)
                new_flag = " [NEW]" if repo_info["is_new"] else ""
                types = sorted(set(r["query_type"] for r in repos if r["repo"] == repo))
                lines.append(f"    {repo}{new_flag} — triggers: {', '.join(types)}")

    if results["errors"]:
        lines.append("")
        lines.append(f"ERRORS ({len(results['errors'])})")
        lines.append("-" * 40)
        for e in results["errors"]:
            lines.append(f"  {e['org']}/{e['query_type']}: {e['error']}")

    Path(output_path).write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="CI/CD Self-Hosted Runner Security Scanner")
    parser.add_argument("--config", required=True, help="Path to orgs.json config file")
    parser.add_argument("--baseline", required=True, help="Path to baseline JSON file")
    parser.add_argument("--output", default="scan_results.json", help="Output results JSON")
    parser.add_argument("--summary", default="scan_summary.txt", help="Output summary text")
    parser.add_argument("--init", action="store_true", help="Initialize baseline (no new-repo detection)")
    args = parser.parse_args()

    # Load config
    config = json.loads(Path(args.config).read_text())
    settings = config.get("settings", {})

    # Load tokens from env
    tokens_str = os.environ.get("SCAN_TOKENS", "")
    if not tokens_str:
        print("ERROR: SCAN_TOKENS environment variable not set")
        sys.exit(1)
    tokens = [t.strip() for t in tokens_str.split(",") if t.strip()]
    if not tokens:
        print("ERROR: No valid tokens found in SCAN_TOKENS")
        sys.exit(1)

    print(f"Loaded {len(tokens)} tokens")
    print(f"Scanning {sum(len(v['orgs']) for v in config['vendors'])} orgs across {len(config['vendors'])} vendors")
    print(f"Queries per org: {len(config['queries'])}")

    rotator = TokenRotator(tokens)
    baseline = load_baseline(args.baseline)

    # Run scan
    results = run_scan(config, rotator, baseline, settings)

    # Update baseline with all discovered repos
    baseline = update_baseline(baseline, results)
    save_baseline(args.baseline, baseline)

    # Save results
    Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")

    # Write summary
    write_summary(results, args.summary)

    print(f"\n{'=' * 60}")
    print(f"Scan complete: {results['total_repos']} repos, {len(results['new_repos'])} new")
    print(f"Baseline updated: {args.baseline}")
    print(f"Results saved: {args.output}")


if __name__ == "__main__":
    main()
