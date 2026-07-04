#!/usr/bin/env python3
"""Union-merge this run's discovered repos into a baseline.json.

Used by CI when a baseline push hits a rebase conflict (another concurrent
run pushed its own baseline update first). Instead of aborting and losing
this run's findings, the workflow resets to origin/main and calls this
script to re-apply all repos from scan_results.json on top of the remote
baseline — so concurrent runs don't clobber each other's entries.

Usage:
    python3 scanner/merge_baseline.py baselines/baseline.json scan_results.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if len(sys.argv) != 3:
    print("usage: merge_baseline.py <baseline.json> <scan_results.json>", file=sys.stderr)
    sys.exit(2)

baseline_path, scan_path = sys.argv[1], sys.argv[2]

if not Path(scan_path).exists():
    print(f"no {scan_path} — nothing to merge", file=sys.stderr)
    sys.exit(0)

baseline = json.loads(Path(baseline_path).read_text())
scan = json.loads(Path(scan_path).read_text())

added = 0
for r in scan.get("all_repos", []):
    repo = r.get("repo")
    if repo and not baseline.get(repo):
        baseline[repo] = True
        added += 1

baseline["_last_scan"] = datetime.now(timezone.utc).isoformat()
baseline["_scan_count"] = baseline.get("_scan_count", 0) + 1

Path(baseline_path).write_text(
    json.dumps(baseline, indent=2, ensure_ascii=False) + "\n"
)
print(f"merged {added} new repo(s) into {baseline_path} (total now {sum(1 for k in baseline if k not in ('_last_scan','_scan_count','_created'))})")
