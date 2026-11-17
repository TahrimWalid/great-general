#!/usr/bin/env python3
"""Pin, fetch, verify, vet and install the generals (outside security skills).

Every general is pinned in generals.lock.json to an exact git commit, with a
SHA-256 for every file. Nothing changes without a human approving a vetted diff.

Usage:
  generals.py list                                   roster and pinned versions
  generals.py fetch   [--id ID] [--commit SHA]       download pinned (or a candidate) commit into the cache
  generals.py verify  [--id ID] [--installed DIR]    re-hash cached (or installed) files against the lock
  generals.py vet     --id ID [--commit SHA]         risk-scan a snapshot; writes a vetting report
  generals.py check-updates                          compare pinned commits with upstream HEAD
  generals.py diff    --id ID --to SHA               what changed between the pinned and candidate commit,
                                                     with risk flags on changed files only
  generals.py approve --id ID --commit SHA --by NAME --note TEXT
                                                     pin a vetted commit (needs its vet/diff report)
  generals.py install --id ID|--all --dest DIR [--marketplace DIR]
                                                     copy pinned skills to DIR (e.g. ~/.claude/skills);
                                                     plugins go to a local, pinned plugin marketplace

Options for all: --lock PATH (default: ../generals.lock.json next to this script)
                 --cache DIR (default: ~/.great-general/cache)
Needs: git, network access to github.com for fetch/check-updates/diff.
Exit codes: 0 ok, 1 check failed (hash mismatch, high-risk flags, refused), 2 usage error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import risk_scan  # noqa: E402

DEFAULT_LOCK = HERE.parent / "generals.lock.json"
DEFAULT_CACHE = Path(os.path.expanduser("~/.great-general/cache"))
GIT_TIMEOUT_S = 300


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def git(*args: str, cwd: Path | None = None) -> str:
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=GIT_TIMEOUT_S)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])} failed: {p.stderr.strip()[:300]}")
    return p.stdout.strip()


def load_lock(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        sys.exit(f"generals.py: lock file not found: {path}")


def save_lock(path: Path, lock: dict) -> None:
    path.write_text(json.dumps(lock, indent=2) + "\n")


def general(lock: dict, gid: str) -> dict:
    for g in lock["generals"]:
        if g["id"] == gid:
            return g
    sys.exit(f"generals.py: no general '{gid}'. Known: {', '.join(x['id'] for x in lock['generals'])}")


def repo_cache(cache: Path, repo: str, commit: str) -> Path:
    """Shallow-fetch exactly one commit of a repo (shared by generals from the same repo)."""
    d = cache / "repos" / (repo.rstrip("/").split("github.com/")[-1].replace("/", "__") + "@" + commit[:12])
    if (d / ".git").exists() and git("rev-parse", "HEAD", cwd=d) == commit:
        return d
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    git("init", "-q", cwd=d)
    git("remote", "add", "origin", repo, cwd=d)
    git("fetch", "-q", "--depth", "1", "origin", commit, cwd=d)
    git("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD", cwd=d)
    got = git("rev-parse", "HEAD", cwd=d)
    if got != commit:
        raise RuntimeError(f"fetched {got}, expected {commit}")
    return d


def snapshot(cache: Path, g: dict, commit: str) -> Path:
    """Copy only the general's declared paths at `commit` into cache/generals/<id>/<commit>."""
    out = cache / "generals" / g["id"] / commit
    if out.exists():
        return out
    src = repo_cache(cache, g["repo"], commit)
    tmp = out.with_suffix(".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    for p in g["paths"]:
        s = src / p
        if s.is_dir():
            shutil.copytree(s, tmp / p, symlinks=True)
        elif s.exists() or s.is_symlink():
            (tmp / p).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, tmp / p, follow_symlinks=False)
        else:
            print(f"warning: {g['id']}: path '{p}' does not exist at {commit[:12]}", file=sys.stderr)
    tmp.rename(out)
    return out


def hashes(root: Path) -> dict[str, str]:
    out = {}
    for f in sorted(root.rglob("*")):
        if f.is_symlink():
            out[f.relative_to(root).as_posix()] = "symlink:" + os.readlink(f)
        elif f.is_file():
            out[f.relative_to(root).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def vet_dir(cache: Path, gid: str, commit: str) -> Path:
    d = cache / "vetting" / gid / commit
    d.mkdir(parents=True, exist_ok=True)
    return d


# --- commands ----------------------------------------------------------------------
def cmd_list(a, lock, cache):
    for g in lock["generals"]:
        pin = g.get("commit", "")[:12] or "-"
        print(f"{g['id']:<32} {g['provider']:<14} {g['kind']:<8} {g['license']:<14} pinned {pin}  {g['role']}")
    return 0


def cmd_fetch(a, lock, cache):
    targets = [general(lock, a.id)] if a.id else [g for g in lock["generals"] if g.get("repo")]
    rc = 0
    for g in targets:
        if not g.get("repo"):
            print(f"{g['id']}: product, nothing to fetch")
            continue
        commit = a.commit or g["commit"]
        snap = snapshot(cache, g, commit)
        line = {"id": g["id"], "commit": commit, "snapshot": str(snap), "files": len(hashes(snap))}
        if commit == g.get("commit") and g.get("files"):
            mismatch = diff_hashes(g["files"], hashes(snap))
            line["matches_lock"] = not any(mismatch.values())
            rc |= 0 if line["matches_lock"] else 1
        print(json.dumps(line))
    return rc


def diff_hashes(old: dict, new: dict) -> dict:
    return {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
            "modified": sorted(k for k in set(old) & set(new) if old[k] != new[k])}


def cmd_verify(a, lock, cache):
    targets = [general(lock, a.id)] if a.id else [g for g in lock["generals"] if g.get("repo")]
    rc = 0
    for g in targets:
        if a.installed:
            root = Path(a.installed).expanduser() / g["install"]["name"]
            expected = {k[len(g["install"]["from"]) + 1:]: v for k, v in g["files"].items()
                        if k.startswith(g["install"]["from"] + "/")}
        else:
            root = cache / "generals" / g["id"] / g["commit"]
            expected = g["files"]
        if not root.exists():
            print(json.dumps({"id": g["id"], "status": "missing", "path": str(root)}))
            rc = 1
            continue
        d = diff_hashes(expected, hashes(root))
        ok = not any(d.values())
        rc |= 0 if ok else 1
        print(json.dumps({"id": g["id"], "status": "ok" if ok else "CHANGED", "path": str(root), **({} if ok else d)}))
    return rc


def cmd_vet(a, lock, cache):
    g = general(lock, a.id)
    commit = a.commit or g["commit"]
    snap = snapshot(cache, g, commit)
    flags = risk_scan.scan(snap)
    report = {"id": g["id"], "commit": commit, "kind": "full", "time": now(), "files": len(hashes(snap)),
              "summary": risk_scan.summarize(flags), "flags": flags}
    out = vet_dir(cache, g["id"], commit) / "vet.json"
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps({"id": g["id"], "commit": commit[:12], "report": str(out), **report["summary"]}))
    return 1 if report["summary"]["high"] else 0


def upstream_head(repo: str, branch: str) -> str:
    out = git("ls-remote", repo, f"refs/heads/{branch}")
    return out.split()[0] if out else ""


def cmd_check_updates(a, lock, cache):
    seen: dict[tuple[str, str], str] = {}
    for g in lock["generals"]:
        if not g.get("repo"):
            continue
        key = (g["repo"], g.get("branch", "main"))
        if key not in seen:
            try:
                seen[key] = upstream_head(*key)
            except RuntimeError as e:
                seen[key] = f"error: {e}"
        head = seen[key]
        state = "up to date" if head == g["commit"] else ("upstream has newer commits" if not head.startswith("error") else head)
        print(json.dumps({"id": g["id"], "pinned": g["commit"][:12], "upstream": head[:12], "state": state}))
    print("For any general with newer commits: generals.py diff --id ID --to <upstream sha>, review, then approve.")
    return 0


def cmd_diff(a, lock, cache):
    g = general(lock, a.id)
    to = a.to
    if to.upper() == "HEAD":
        to = upstream_head(g["repo"], g.get("branch", "main"))
    old = snapshot(cache, g, g["commit"])
    new = snapshot(cache, g, to)
    d = diff_hashes(hashes(old), hashes(new))
    changed = d["added"] + d["modified"]
    flags = risk_scan.scan(new, changed) if changed else []
    patch_path = vet_dir(cache, g["id"], to) / "changes.diff"
    p = subprocess.run(["git", "diff", "--no-index", "--stat", "--patch", str(old), str(new)], capture_output=True, text=True)
    patch_path.write_text(p.stdout)
    report = {"id": g["id"], "from": g["commit"], "to": to, "kind": "diff", "time": now(), **d,
              "summary": risk_scan.summarize(flags), "flags": flags, "patch": str(patch_path)}
    out = vet_dir(cache, g["id"], to) / "diff.json"
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps({"id": g["id"], "from": g["commit"][:12], "to": to[:12], "added": len(d["added"]),
                      "removed": len(d["removed"]), "modified": len(d["modified"]),
                      **report["summary"], "report": str(out), "patch": str(patch_path)}))
    print("Next: a reviewer agent with no credentials reads the patch as data (references/vetting.md), "
          "then a human runs approve.")
    return 1 if report["summary"]["high"] else 0


def cmd_approve(a, lock, cache, lock_path):
    g = general(lock, a.id)
    vd = cache / "vetting" / g["id"] / a.commit
    if not ((vd / "diff.json").exists() or (vd / "vet.json").exists()):
        print(f"generals.py: refused: no vetting report for {g['id']} @ {a.commit[:12]}. "
              f"Run 'vet' (first pin) or 'diff' (update) and review it first.")
        return 1
    snap = cache / "generals" / g["id"] / a.commit
    if not snap.exists():
        print("generals.py: refused: snapshot missing; run fetch/diff again")
        return 1
    prev = g.get("commit")
    g["commit"] = a.commit
    g["files"] = hashes(snap)
    g["approved"] = {"by": a.by, "time": now(), "note": a.note, "previous": prev}
    save_lock(lock_path, lock)
    log = lock_path.with_name("vetting-log.jsonl")
    with log.open("a") as fh:
        fh.write(json.dumps({"time": now(), "id": g["id"], "from": prev, "to": a.commit, "by": a.by, "note": a.note}) + "\n")
    print(json.dumps({"id": g["id"], "pinned": a.commit[:12], "files": len(g["files"]), "log": str(log)}))
    return 0


def cmd_install(a, lock, cache):
    if not a.dest and not a.marketplace:
        print("generals.py install: give --dest (for skills) and/or --marketplace (for plugins)")
        return 2
    targets = [g for g in lock["generals"] if g.get("repo")] if a.all else [general(lock, a.id)]
    plugins = []
    for g in targets:
        if not g.get("approved") or not g.get("files"):
            print(json.dumps({"id": g["id"], "status": "refused: not approved yet. Run vet, review the report, "
                              "then approve --id ... --commit ... --by <your name>"}))
            return 1
        snap = snapshot(cache, g, g["commit"])
        d = diff_hashes(g["files"], hashes(snap))
        if any(d.values()):
            print(json.dumps({"id": g["id"], "status": "refused: cached files don't match the lock", **d}))
            return 1
        inst = g.get("install") or {}
        if inst.get("type") == "skill" and a.dest:
            dest = Path(a.dest).expanduser() / inst["name"]
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(snap / inst["from"], dest, symlinks=True)
            print(json.dumps({"id": g["id"], "installed": str(dest)}))
        elif inst.get("type") == "command" and a.dest:
            dest = Path(a.dest).expanduser() / inst["name"]
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snap / inst["from"], dest / Path(inst["from"]).name)
            print(json.dumps({"id": g["id"], "installed": str(dest / Path(inst['from']).name),
                              "note": "a customisable copy; Claude Code also ships /security-review built in"}))
        elif inst.get("type") == "plugin":
            plugins.append((g, snap))
    if plugins and a.marketplace:
        mk = Path(a.marketplace).expanduser()
        (mk / ".claude-plugin").mkdir(parents=True, exist_ok=True)
        entries = []
        for g, snap in plugins:
            dest = mk / "plugins" / g["install"]["name"]
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(snap / g["install"]["from"], dest, symlinks=True)
            lic = snap / "LICENSE"
            if lic.exists():
                shutil.copy2(lic, dest / "LICENSE.upstream")
            entries.append({"name": g["install"]["name"], "source": f"./plugins/{g['install']['name']}",
                            "description": g["role"], "version": g["commit"][:12],
                            "author": {"name": g["provider"]}})
        (mk / ".claude-plugin" / "marketplace.json").write_text(json.dumps(
            {"name": "great-general-pinned", "owner": {"name": "great-general"},
             "metadata": {"description": "Pinned, vetted copies of the generals", "version": "1"},
             "plugins": entries}, indent=2))
        print(json.dumps({"marketplace": str(mk), "plugins": [e["name"] for e in entries],
                          "next": f"in Claude Code: /plugin marketplace add {mk}  then /plugin install <name>@great-general-pinned"}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["list", "fetch", "verify", "vet", "check-updates", "diff", "approve", "install"])
    ap.add_argument("--lock", default=str(DEFAULT_LOCK))
    ap.add_argument("--cache", default=str(DEFAULT_CACHE))
    ap.add_argument("--id")
    ap.add_argument("--commit")
    ap.add_argument("--to")
    ap.add_argument("--by")
    ap.add_argument("--note", default="")
    ap.add_argument("--installed")
    ap.add_argument("--dest")
    ap.add_argument("--marketplace")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    lock_path, cache = Path(a.lock), Path(a.cache).expanduser()
    lock = load_lock(lock_path)
    try:
        if a.cmd == "vet" and not a.id:
            print("vet needs --id"); return 2
        if a.cmd == "diff" and not (a.id and a.to):
            print("diff needs --id and --to"); return 2
        if a.cmd == "approve":
            if not (a.id and a.commit and a.by):
                print("approve needs --id, --commit and --by (the human approving)"); return 2
            return cmd_approve(a, lock, cache, lock_path)
        return {"list": cmd_list, "fetch": cmd_fetch, "verify": cmd_verify, "vet": cmd_vet,
                "check-updates": cmd_check_updates, "diff": cmd_diff, "install": cmd_install}[a.cmd](a, lock, cache)
    except RuntimeError as e:
        print(f"generals.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
