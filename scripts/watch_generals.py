#!/usr/bin/env python3
"""Watch the generals' upstreams and open one GitHub issue per real update.

Usage:
  watch_generals.py [--lock generals.lock.json] [--cache DIR] [--open-issues] [--repo OWNER/NAME]

For every pinned general whose upstream branch has moved, it fetches the new
commit, diffs only that general's files against the pinned snapshot and runs
the risk scan on what changed (generals.py diff). Repository-level commits
that don't touch the general are ignored.

With --open-issues (used by the scheduled workflow), it opens a GitHub issue
"Upstream update: <id> -> <sha12>" with the changed files, risk flags and the
patch, unless an issue for that exact update already exists. It closes an
open update issue once the lock pins that commit (you approved and synced).
Without --open-issues it only prints the reports.

Safety: nothing from upstream is executed; it is fetched with git and read as
text. Upstream excerpts are put inside code fences so that their Markdown
(links, images, @mentions) is not rendered in the issue.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generals  # noqa: E402
import risk_scan  # noqa: E402

LABEL = "general-update"
MAX_PATCH_CHARS = 50_000  # GitHub issue bodies are capped at 65,536 characters
TITLE_RE = re.compile(r"^Upstream update: (\S+) -> ([0-9a-f]{12})$")


def fence(text: str, lang: str = "") -> str:
    """A code fence longer than any backtick run inside the text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"


def gh(*args: str) -> str:
    p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed: {p.stderr.strip()[:300]}")
    return p.stdout


def issue_body(g: dict, new: str, d: dict, flags: list, patch: str) -> str:
    s = risk_scan.summarize(flags)
    lines = [
        f"Upstream **{g['repo']}** has a new commit that changes the general **{g['id']}** ({g['provider']}, {g['license']}).",
        "",
        f"- Pinned: `{g['commit']}`",
        f"- Upstream: `{new}`",
        f"- Files: {len(d['added'])} added, {len(d['modified'])} modified, {len(d['removed'])} removed",
        f"- Risk flags on changed files: {s['total']} ({s['high']} high)",
        "",
        "Nothing has been approved or installed. To vet and sync:",
        "",
        fence(f"python3 scripts/generals.py diff --id {g['id']} --to {new}\n"
              f"# have a fresh reviewer agent read the patch as data (references/vetting.md), then if you accept it:\n"
              f"python3 scripts/generals.py approve --id {g['id']} --commit {new} --by \"<your name>\" --note \"<what you checked>\"\n"
              f"git switch -c pin-{g['id']}-{new[:12]}\n"
              f"git commit -am \"Pin {g['id']} to {new[:12]}\"\n"
              f"git push -u origin pin-{g['id']}-{new[:12]}   # main is protected: merge through a pull request", "bash"),
        "",
        "### Changed files",
        fence("\n".join([f"A {f}" for f in d["added"]] + [f"M {f}" for f in d["modified"]] + [f"D {f}" for f in d["removed"]]) or "(none)"),
    ]
    if flags:
        rows = "\n".join(f"{x['severity'].upper():<6} {x['category']:<15} {x['file']}:{x['line']}  {x['excerpt']}" for x in flags[:80])
        lines += ["", "### Risk flags (the scan flags what a person must read; it does not judge intent)", fence(rows)]
    if patch:
        cut = patch if len(patch) <= MAX_PATCH_CHARS else patch[:MAX_PATCH_CHARS] + "\n... (truncated; run the diff command above for the full patch)"
        lines += ["", "<details><summary>Patch</summary>", "", fence(cut, "diff"), "", "</details>"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lock", default=str(generals.DEFAULT_LOCK))
    ap.add_argument("--cache", default=str(generals.DEFAULT_CACHE))
    ap.add_argument("--open-issues", action="store_true")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    a = ap.parse_args()
    lock = generals.load_lock(Path(a.lock))
    cache = Path(a.cache).expanduser()
    heads: dict[tuple[str, str], str] = {}
    updates = []
    for g in lock["generals"]:
        if not g.get("repo"):
            continue
        key = (g["repo"], g.get("branch", "main"))
        if key not in heads:
            heads[key] = generals.upstream_head(*key)
        new = heads[key]
        if not new or new == g["commit"]:
            continue
        old_snap = generals.snapshot(cache, g, g["commit"])
        new_snap = generals.snapshot(cache, g, new)
        d = generals.diff_hashes(generals.hashes(old_snap), generals.hashes(new_snap))
        if not any(d.values()):
            print(json.dumps({"id": g["id"], "upstream": new[:12], "state": "repo moved, this general unchanged"}))
            continue
        flags = risk_scan.scan(new_snap, d["added"] + d["modified"])
        p = subprocess.run(["git", "diff", "--no-index", "--patch", str(old_snap), str(new_snap)], capture_output=True, text=True)
        patch = p.stdout.replace(str(old_snap), "a").replace(str(new_snap), "b")
        updates.append((g, new, d, flags, patch))
        print(json.dumps({"id": g["id"], "upstream": new[:12], "changed": sum(len(v) for v in d.values()),
                          **risk_scan.summarize(flags)}))
    if not a.open_issues:
        return 0
    if not a.repo:
        print("watch_generals.py: --repo (or GITHUB_REPOSITORY) is required with --open-issues")
        return 2
    try:
        gh("label", "create", LABEL, "--repo", a.repo, "--color", "B60205",
           "--description", "A pinned general changed upstream; vet before syncing")
    except RuntimeError:
        pass  # label already exists
    existing = json.loads(gh("issue", "list", "--repo", a.repo, "--label", LABEL, "--state", "open",
                             "--json", "number,title", "--limit", "200"))
    open_titles = {i["title"]: i["number"] for i in existing}
    for g, new, d, flags, patch in updates:
        title = f"Upstream update: {g['id']} -> {new[:12]}"
        if title in open_titles:
            continue
        gh("issue", "create", "--repo", a.repo, "--title", title, "--label", LABEL,
           "--body", issue_body(g, new, d, flags, patch))
        print(f"opened: {title}")
    pinned = {g["id"]: g["commit"][:12] for g in lock["generals"] if g.get("repo")}
    for title, number in open_titles.items():
        m = TITLE_RE.match(title)
        if m and pinned.get(m.group(1)) == m.group(2):
            gh("issue", "close", str(number), "--repo", a.repo, "--comment", "The lock now pins this commit. Closing.")
            print(f"closed: {title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
