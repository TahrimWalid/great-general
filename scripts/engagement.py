#!/usr/bin/env python3
"""Check the rules of engagement and open a run.

Usage:
  engagement.py check [--engagement .great-general/engagement.yaml] [--lock PATH]
  engagement.py init  [--engagement ...] [--lock PATH] [--runs-root ~/.great-general/runs]

init creates RUN = <runs-root>/<repo-name>/<run-id>/ OUTSIDE the target repo, with
run.json (target commit + dirty flag, campaign, every general's pinned version
and approval, the engagement's hash), raw.jsonl, generals/, pocs/, logs/.
It refuses when the engagement is invalid, a general it would deploy is not
approved in generals.lock.json, or a never-touch host is also in scope.
Exit codes: 0 ok, 1 refused (errors listed), 2 usage error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGNS = {
    # campaign -> generals deployed by default (ids from generals.lock.json)
    "pr": ["anthropic-security-review", "tob-differential-review"],
    "full-audit": ["tob-audit-context-building", "cloudflare-security-audit", "tob-static-analysis",
                   "tob-insecure-defaults", "tob-supply-chain-risk-auditor", "tob-agentic-actions-auditor"],
    "release": ["cloudflare-security-audit", "tob-static-analysis", "tob-insecure-defaults",
                "tob-supply-chain-risk-auditor", "tob-agentic-actions-auditor"],
    "follow-up": ["tob-fp-check", "tob-variant-analysis"],
    "re-check": ["cloudflare-security-audit", "tob-fp-check"],
}
ALWAYS_AVAILABLE = ["tob-fp-check", "tob-variant-analysis"]  # used to adjudicate in every campaign


def git(repo: Path, *args: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.exit("engagement.py: PyYAML is required: pip install pyyaml")
    if not path.exists():
        sys.exit(f"engagement.py: {path} not found. Copy the template from references/engagement.md")
    return yaml.safe_load(path.read_text()) or {}


def validate(e: dict, lock: dict) -> tuple[list[str], list[str], list[str]]:
    errors, warnings = [], []
    if not str(e.get("authorization", "")).strip():
        errors.append("authorization is missing: state that you own (or are authorised to test) the code and lab in scope")
    t = e.get("target") or {}
    repo = Path(os.path.expanduser(str(t.get("repo", "")))) if t.get("repo") else None
    if not repo or not repo.exists():
        errors.append("target.repo must be an existing path to the repository under review")
    wt = t.get("worktree")
    if not wt:
        warnings.append("target.worktree not set: review a detached worktree outside the main checkout "
                        "(git worktree add --detach <path> <ref>) so other sessions' work is never touched")
    campaign = e.get("campaign", "full-audit")
    if campaign not in CAMPAIGNS:
        errors.append(f"campaign must be one of {sorted(CAMPAIGNS)}")
    if e.get("profile", "standard") not in ("quick", "standard", "deep"):
        errors.append("profile must be quick, standard or deep")
    hosts = {str(h).lower() for h in ((e.get("in_scope") or {}).get("hosts") or [])}
    lab = e.get("lab") or {}
    never = {str(h).lower() for h in (lab.get("never_touch") or [])}
    for h in sorted(hosts & never):
        errors.append(f"'{h}' is both in in_scope.hosts and lab.never_touch")
    for m, addr in (lab.get("machines") or {}).items():
        if str(addr).lower() not in hosts:
            errors.append(f"lab.machines.{m}: {addr} must be in in_scope.hosts")
        if m.lower() in never or str(addr).lower() in never:
            errors.append(f"lab.machines.{m} is in lab.never_touch")
    poc = e.get("poc_policy") or {"allowed": False}
    if poc.get("allowed"):
        if not (lab.get("snapshot") or {}).get("create"):
            errors.append("poc_policy.allowed needs lab.snapshot.create/restore: lab machines are snapshotted before any proof")
        if not e.get("scratch_home"):
            errors.append("poc_policy.allowed needs scratch_home: proofs run against a scratch copy of the app's data, never the real one")
    if e.get("report_only", True) is not True:
        warnings.append("report_only is not true: the commander still never commits or pushes; fixes are a separate session's job")
    skip = set((e.get("generals") or {}).get("skip") or [])
    deploy = [g for g in CAMPAIGNS.get(campaign, []) + ALWAYS_AVAILABLE if g not in skip]
    deploy = list(dict.fromkeys(deploy))
    by_id = {g["id"]: g for g in lock.get("generals", [])}
    for gid in deploy:
        g = by_id.get(gid)
        if not g:
            errors.append(f"general '{gid}' is not in generals.lock.json")
        elif g.get("repo") and not g.get("approved"):
            errors.append(f"general '{gid}' is not approved yet: generals.py vet --id {gid}, review, then approve")
    return errors, warnings, deploy


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["check", "init"])
    ap.add_argument("--engagement", default=".great-general/engagement.yaml")
    ap.add_argument("--lock", default=str(HERE.parent / "generals.lock.json"))
    ap.add_argument("--runs-root", default="~/.great-general/runs")
    a = ap.parse_args()
    epath = Path(a.engagement)
    e = load_yaml(epath)
    lock = json.loads(Path(a.lock).read_text())
    errors, warnings, deploy = validate(e, lock)
    if errors or a.cmd == "check":
        print(json.dumps({"ok": not errors, "errors": errors, "warnings": warnings, "would_deploy": deploy}, indent=2))
        return 1 if errors else 0
    t = e["target"]
    repo = Path(os.path.expanduser(str(t["repo"])))
    review_dir = Path(os.path.expanduser(str(t.get("worktree") or t["repo"])))
    now = dt.datetime.now().astimezone()
    run_id = now.strftime("%Y%m%d-%H%M") + "-" + secrets.token_hex(2)
    run = Path(os.path.expanduser(a.runs_root)) / repo.name / run_id
    try:
        run.relative_to(repo.resolve())
        print("engagement.py: refused: the run directory would be inside the target repo")
        return 1
    except ValueError:
        pass
    for sub in ("generals", "pocs", "logs"):
        (run / sub).mkdir(parents=True, exist_ok=True)
    (run / "raw.jsonl").touch()
    (run / "logs" / "actions.jsonl").touch()
    by_id = {g["id"]: g for g in lock["generals"]}
    info = {
        "run_id": run_id, "started": now.isoformat(timespec="seconds"),
        "engagement_sha256": hashlib.sha256(epath.read_bytes()).hexdigest()[:16],
        "owner": e.get("owner"), "authorization": e.get("authorization"),
        "target": {"repo": str(repo), "reviewed_path": str(review_dir), "ref": t.get("ref"),
                   "commit": git(review_dir, "rev-parse", "HEAD"), "dirty": bool(git(review_dir, "status", "--porcelain"))},
        "campaign": e.get("campaign", "full-audit"), "profile": e.get("profile", "standard"),
        "generals": [{"id": gid, "commit": by_id[gid].get("commit"), "approved_by": (by_id[gid].get("approved") or {}).get("by")}
                     for gid in deploy],
        "claude_code_builtin_security_review": "built into Claude Code: record `claude --version` here when used",
        "environment": "production" if e.get("treat_as_production") else "local",
        "in_scope": e.get("in_scope"), "lab": e.get("lab"), "poc_policy": e.get("poc_policy") or {"allowed": False},
        "previous_reviews": e.get("previous_reviews") or [],
    }
    (run / "run.json").write_text(json.dumps(info, indent=2))
    print(json.dumps({"ok": True, "run_dir": str(run), "deploy": deploy, "warnings": warnings,
                      "target_commit": info["target"]["commit"], "dirty": info["target"]["dirty"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
