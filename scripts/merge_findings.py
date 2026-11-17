#!/usr/bin/env python3
"""Bring every general's findings into one list, merge duplicates, surface
disagreements, compare with a previous review, and track each general's record.

Usage:
  merge_findings.py import cloudflare RUN FILE --commit SHA     Cloudflare security-audit findings.json
  merge_findings.py import anthropic  RUN FILE --commit SHA     claude-code-security-review JSON ({"findings": [...]})
  merge_findings.py import sarif      RUN FILE --general ID --commit SHA   SARIF (CodeQL, Semgrep...): imported as candidates
  merge_findings.py import manual     RUN FILE                  JSONL already in the unified format (prose generals)
  merge_findings.py merge    RUN                                 -> RUN/findings.json + RUN/summary.md
  merge_findings.py validate RUN                                 every candidate adjudicated, no open conflicts
  merge_findings.py compare  RUN --previous FILE                 regression table vs an earlier findings.json / prior.jsonl
  merge_findings.py trust    --runs DIR                          per-general record across runs (needs human dispositions)

Unified record (one JSON object per line in RUN/raw.jsonl; see references/reporting.md):
  fingerprint, title, verdict (confirmed | needs_validation | rejected | candidate), severity (confirmed only),
  confidence (high|medium|low), category, locations [{file, line}], description, evidence, remediation,
  open_question (needs_validation), reason (rejected), source {general, commit, ref}
Exit codes: 0 ok, 1 validation problems, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEV = ["critical", "high", "medium", "low", "informational"]
VERDICTS = {"confirmed", "needs_validation", "rejected", "candidate"}
LINE_SLACK = 3  # findings on the same file within this many lines and the same category are treated as one


# Different generals name the same class differently; merge on the family.
FAMILIES = [
    ("access_control", r"authz|authori[sz]|access_control|idor|missing_auth|unauthenticated|auth_bypass|privilege|permission|cross_tenant|broken_access"),
    ("authentication", r"authn|authentication|login|password|credential_stuffing|brute"),
    ("session", r"session|cookie|jwt|token_handling|csrf"),
    ("injection_sql", r"sql|sqli|nosql"),
    ("injection_command", r"command_injection|cmd_injection|os_command|shell_injection|rce|code_exec|eval_injection"),
    ("xss", r"xss|cross_site_scripting|html_injection"),
    ("ssrf", r"ssrf|server_side_request"),
    ("path_traversal", r"path_traversal|directory_traversal|zip_slip|symlink"),
    ("secrets", r"secret|hardcoded|api_key|credential_leak|private_key"),
    ("crypto", r"crypto|cipher|hash|random|tls|certificate"),
    ("deserialization", r"deserial|pickle|yaml_load|unmarshal"),
    ("data_exposure", r"exposure|disclosure|leak|pii|sensitive_data|logging"),
    ("supply_chain", r"dependency|supply_chain|typosquat|lockfile|workflow|github_action|ci_"),
    ("misconfiguration", r"config|default|debug|cors|header"),
]


def norm_cat(c: str | None) -> str:
    raw = re.sub(r"[^a-z0-9]+", "_", (c or "uncategorised").lower()).strip("_")
    for family, pat in FAMILIES:
        if re.search(pat, raw):
            return family
    return raw


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def append_raw(run: Path, recs: list[dict]) -> None:
    run.mkdir(parents=True, exist_ok=True)
    with (run / "raw.jsonl").open("a") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    print(json.dumps({"imported": len(recs), "into": str(run / "raw.jsonl"),
                      "verdicts": dict(Counter(r["verdict"] for r in recs))}))


# --- importers ---------------------------------------------------------------------
def imp_cloudflare(path: Path, commit: str) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    for f in data:
        trace = f.get("trace") or []
        locs = [{"file": t["file"], "line": t.get("line")} for t in trace if t.get("kind") == "sink"] or \
               [{"file": t["file"], "line": t.get("line")} for t in trace[:1]]
        overall = (f.get("severity") or {}).get("overall_severity")
        # Cloudflare's schema makes overall_severity a plain string; tolerate an object too
        sev = (overall.get("score") if isinstance(overall, dict) else overall) if f.get("verdict") == "confirmed" else None
        conf = (f.get("confidence") or {}).get("score")
        out.append({"fingerprint": f["fingerprint"], "title": f["title"], "verdict": f["verdict"], "severity": sev,
                    "confidence": conf or ("medium" if f["verdict"] == "needs_validation" else None),
                    "category": norm_cat(f["fingerprint"].split(":")[0] if ":" in f["fingerprint"] else f.get("title")),
                    "locations": locs, "description": f.get("description"),
                    "evidence": f.get("evidence"), "remediation": (f.get("remediation") or {}).get("strategy"),
                    "open_question": "; ".join(str(b) for b in f.get("blockers") or []) or None,
                    "validation_plan": f.get("validation_plan"),
                    "reason": f.get("reason"),
                    "source": {"general": "cloudflare-security-audit", "commit": commit, "ref": f["fingerprint"]}})
    return out


def imp_anthropic(path: Path, commit: str) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    for i, f in enumerate(data.get("findings", [])):
        c = float(f.get("confidence", 0.8))
        cat = norm_cat(f.get("category"))
        out.append({"fingerprint": f"{cat}:{f.get('file')}:{f.get('line')}", "title": f"{f.get('category', 'issue')} in {f.get('file')}",
                    "verdict": "candidate",  # its own filter already ran, but the commander still adjudicates
                    "severity": None, "proposed_severity": str(f.get("severity", "")).lower() or None,
                    "confidence": "high" if c >= 0.9 else "medium" if c >= 0.8 else "low", "category": cat,
                    "locations": [{"file": f.get("file"), "line": f.get("line")}], "description": f.get("description"),
                    "impact": f.get("exploit_scenario"), "remediation": f.get("recommendation"),
                    "source": {"general": "anthropic-security-review", "commit": commit, "ref": str(i)}})
    return out


def imp_sarif(path: Path, general: str, commit: str) -> list[dict]:
    data = json.loads(path.read_text())
    level_sev = {"error": "high", "warning": "medium", "note": "low", "none": "informational"}
    out = []
    for run in data.get("runs", []):
        for i, r in enumerate(run.get("results", [])):
            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
            file = (loc.get("artifactLocation") or {}).get("uri")
            line = (loc.get("region") or {}).get("startLine")
            cat = norm_cat(r.get("ruleId"))
            out.append({"fingerprint": f"{cat}:{file}:{line}", "title": (r.get("message") or {}).get("text", cat)[:120],
                        "verdict": "candidate", "severity": None,
                        "proposed_severity": level_sev.get(r.get("level", "warning"), "medium"), "confidence": "low",
                        "category": cat, "locations": [{"file": file, "line": line}],
                        "description": (r.get("message") or {}).get("text"),
                        "source": {"general": general, "commit": commit, "ref": r.get("ruleId", str(i))}})
    return out


def imp_manual(path: Path) -> list[dict]:
    recs = load_jsonl(path)
    for r in recs:
        r["category"] = norm_cat(r.get("category"))
        if "source" not in r or "general" not in r["source"]:
            sys.exit("merge_findings.py: manual records need source.general (and source.commit)")
    return recs


# --- merge -------------------------------------------------------------------------
def same(a: dict, b: dict) -> bool:
    if a.get("fingerprint") and a.get("fingerprint") == b.get("fingerprint"):
        return True
    if a["category"] != b["category"]:
        return False
    for la in a.get("locations") or []:
        for lb in b.get("locations") or []:
            if la.get("file") and la.get("file") == lb.get("file") and \
               abs(int(la.get("line") or 0) - int(lb.get("line") or 0)) <= LINE_SLACK:
                return True
    return False


def merge(raw: list[dict]) -> list[dict]:
    groups: list[list[dict]] = []
    for r in raw:
        for g in groups:
            if any(same(r, x) for x in g):
                g.append(r)
                break
        else:
            groups.append([r])
    merged = []
    for g in groups:
        # An adjudicated verdict (from a verifier or fp-check) supersedes raw scanner candidates.
        verdicts = {x["verdict"] for x in g} - {"candidate"} or {"candidate"}
        if "confirmed" in verdicts and "rejected" in verdicts:
            verdict = "conflict"
        elif "confirmed" in verdicts:
            verdict = "confirmed"
        elif "needs_validation" in verdicts:
            verdict = "needs_validation"
        elif verdicts == {"rejected"}:
            verdict = "rejected"
        else:
            verdict = "candidate"
        sevs = [x["severity"] for x in g if x.get("severity")]
        best = max(g, key=lambda x: (x["verdict"] == verdict, x["verdict"] != "candidate", len(x.get("description") or "")))
        merged.append({
            "fingerprint": best.get("fingerprint"), "title": best["title"], "verdict": verdict,
            "severity": min(sevs, key=SEV.index) if sevs and verdict == "confirmed" else None,
            "proposed_severity": next((x.get("proposed_severity") for x in g if x.get("proposed_severity")), None),
            "confidence": best.get("confidence"), "category": best["category"],
            "locations": [dict(t) for t in {tuple(sorted(l.items())) for x in g for l in x.get("locations") or []}],
            "description": best.get("description"), "impact": best.get("impact"), "remediation": best.get("remediation"),
            "evidence": best.get("evidence"), "open_question": best.get("open_question"), "reason": best.get("reason"),
            "sources": [x["source"] | {"verdict": x["verdict"], "severity": x.get("severity")} for x in g],
            "generals_agreeing": len({x["source"]["general"] for x in g if x["verdict"] in ("confirmed", "candidate", "needs_validation")}),
            "introduced": best.get("introduced", "unknown"), "lab_validation": best.get("lab_validation"),
            "disposition": best.get("disposition"),
        })
    order = {"conflict": 0, "confirmed": 1, "needs_validation": 2, "candidate": 3, "rejected": 4}
    merged.sort(key=lambda m: (order[m["verdict"]], SEV.index(m["severity"]) if m["severity"] else 9, m["fingerprint"] or ""))
    for i, m in enumerate(merged, 1):
        m["id"] = f"GG-{i:03d}"
    return merged


def problems(findings: list[dict]) -> list[str]:
    out = []
    for f in findings:
        fid = f.get("id", f.get("fingerprint"))
        if f["verdict"] == "candidate":
            out.append(f"{fid}: still a candidate. Adjudicate it (fresh verifier or tob-fp-check) and record confirmed / needs_validation / rejected")
        if f["verdict"] == "conflict":
            out.append(f"{fid}: generals disagree (confirmed vs rejected). A fresh verifier must settle it; record the outcome as a manual record")
        if f["verdict"] == "confirmed" and not f.get("severity"):
            out.append(f"{fid}: confirmed without severity")
        if f["verdict"] == "confirmed" and not (f.get("evidence") or f.get("locations")):
            out.append(f"{fid}: confirmed without evidence or a location")
        if f["verdict"] == "needs_validation" and not f.get("open_question"):
            out.append(f"{fid}: needs_validation without the exact open question")
        if f["verdict"] == "needs_validation" and f.get("severity"):
            out.append(f"{fid}: needs_validation must not carry a severity")
        if f["verdict"] == "rejected" and not f.get("reason"):
            out.append(f"{fid}: rejected without a reason")
    return out


def summary_md(findings: list[dict], raw: list[dict]) -> str:
    v = Counter(f["verdict"] for f in findings)
    sev = Counter(f["severity"] for f in findings if f["verdict"] == "confirmed")
    by_gen = defaultdict(Counter)
    for r in raw:
        by_gen[(r["source"]["general"], r["source"].get("commit", "")[:12])][r["verdict"]] += 1
    lines = ["## Summary (generated by merge_findings.py)", "",
             f"Confirmed {v.get('confirmed', 0)} · needs validation {v.get('needs_validation', 0)} · "
             f"rejected {v.get('rejected', 0)} · unresolved candidates {v.get('candidate', 0)} · conflicts {v.get('conflict', 0)}", "",
             "| Severity | Confirmed |", "|---|---|"] + [f"| {s} | {sev.get(s, 0)} |" for s in SEV]
    lines += ["", "### Generals deployed (version) and what each reported", "",
              "| General | Commit | Confirmed | Needs validation | Rejected | Candidates |", "|---|---|---|---|---|---|"]
    lines += [f"| {g} | {c} | {n.get('confirmed', 0)} | {n.get('needs_validation', 0)} | {n.get('rejected', 0)} | {n.get('candidate', 0)} |"
              for (g, c), n in sorted(by_gen.items())]
    multi = [f for f in findings if f["verdict"] == "confirmed" and f["generals_agreeing"] > 1]
    lines += ["", f"**Independently found by more than one general:** {len(multi)} of {v.get('confirmed', 0)} confirmed"
              + (": " + ", ".join(f["id"] for f in multi) if multi else "")]
    return "\n".join(lines) + "\n"


def words(t: str | None) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", (t or "").lower()) if len(w) > 2}


def match_across_versions(p: dict, cur: list[dict]) -> dict | None:
    """Code moves between reviews, so line numbers can't be trusted. Match by fingerprint,
    then by same file + same bug family (nearest line wins), then by same family + similar title."""
    for c in cur:
        if p.get("fingerprint") and p.get("fingerprint") == c.get("fingerprint"):
            return c
    pf = {l.get("file") for l in p.get("locations") or [] if l.get("file")}
    best, dist = None, None
    for c in cur:
        if norm_cat(c.get("category")) != norm_cat(p.get("category")):
            continue
        for lc in c.get("locations") or []:
            if lc.get("file") in pf:
                d = min(abs(int(lc.get("line") or 0) - int(lp.get("line") or 0)) for lp in p["locations"] if lp.get("file") == lc.get("file"))
                if dist is None or d < dist:
                    best, dist = c, d
    if best:
        return best
    for c in cur:
        a, b = words(p.get("title")), words(c.get("title"))
        if norm_cat(c.get("category")) == norm_cat(p.get("category")) and a and b and len(a & b) / len(a | b) >= 0.5:
            return c
    return None


def compare(cur: list[dict], prev: list[dict]) -> str:
    rows = ["| Previous finding | Previous status | Now | Current id |", "|---|---|---|---|"]
    matched_ids = set()
    for p in prev:
        match = match_across_versions(p, cur)
        if match:
            matched_ids.add(match["id"])
        was = p.get("disposition") or p.get("verdict")
        if match and match["verdict"] in ("confirmed", "needs_validation", "conflict", "candidate"):
            now = "REGRESSED (was fixed, found again)" if was == "fixed" else "still open"
        elif match:
            now = f"now {match['verdict']}"
        else:
            now = "still fixed (not found again; check the area was covered)" if was == "fixed" else "not found this run (check coverage before calling it fixed)"
        rows.append(f"| {p.get('id', '')} {p.get('title', p.get('fingerprint', ''))[:60]} | {was} | {now} | {match['id'] if match else '-'} |")
    new = [c for c in cur if c["verdict"] == "confirmed" and c["id"] not in matched_ids]
    rows += ["", f"New confirmed findings since the previous review: {', '.join(c['id'] for c in new) or 'none'}"]
    return "\n".join(rows) + "\n"


def trust(runs_dir: Path) -> str:
    stats: dict[str, Counter] = defaultdict(Counter)
    for fj in sorted(runs_dir.rglob("findings.json")):
        for f in json.loads(fj.read_text()):
            gens = {s["general"] for s in f.get("sources", [])}
            for g in gens:
                stats[g]["reported"] += 1
                if f["verdict"] == "confirmed" and len(gens) == 1:
                    stats[g]["only_this_general"] += 1
                if f.get("disposition"):
                    stats[g]["disp_" + f["disposition"]] += 1
                rej = [s for s in f.get("sources", []) if s["general"] == g and s.get("verdict") in ("confirmed", "candidate")]
                if rej and f["verdict"] == "rejected":
                    stats[g]["overruled"] += 1
    lines = ["| General | Reported | Found alone | Overruled | Fixed | Wrong | Intentional | Didn't matter | Precision |",
             "|---|---|---|---|---|---|---|---|---|"]
    for g, c in sorted(stats.items()):
        reviewed = sum(v for k, v in c.items() if k.startswith("disp_"))
        prec = f"{c['disp_fixed'] / reviewed:.0%}" if reviewed else "–"
        lines.append(f"| {g} | {c['reported']} | {c['only_this_general']} | {c['overruled']} | {c['disp_fixed']} | "
                     f"{c['disp_wrong']} | {c['disp_intentional']} | {c['disp_didnt_matter']} | {prec} |")
    return "\n".join(lines) + "\n\nPrecision = fixed ÷ findings a human has dispositioned. A sudden drop after a version change is the dip to investigate.\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["import", "merge", "validate", "compare", "trust"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--commit", default="")
    ap.add_argument("--general")
    ap.add_argument("--previous")
    ap.add_argument("--runs")
    a = ap.parse_args()
    if a.cmd == "import":
        if len(a.args) != 3:
            print("import needs: KIND RUN FILE"); return 2
        kind, run, file = a.args[0], Path(a.args[1]), Path(a.args[2])
        if kind == "cloudflare":
            recs = imp_cloudflare(file, a.commit)
        elif kind == "anthropic":
            recs = imp_anthropic(file, a.commit)
        elif kind == "sarif":
            if not a.general:
                print("import sarif needs --general (e.g. tob-static-analysis)"); return 2
            recs = imp_sarif(file, a.general, a.commit)
        elif kind == "manual":
            recs = imp_manual(file)
        else:
            print("kinds: cloudflare, anthropic, sarif, manual"); return 2
        bad = [r for r in recs if r["verdict"] not in VERDICTS]
        if bad:
            print(f"merge_findings.py: unknown verdicts in {len(bad)} record(s)"); return 1
        append_raw(run, recs)
        return 0
    if a.cmd == "trust":
        if not a.runs:
            print("trust needs --runs DIR"); return 2
        print(trust(Path(a.runs).expanduser()))
        return 0
    if len(a.args) != 1:
        print(f"{a.cmd} needs: RUN"); return 2
    run = Path(a.args[0])
    raw = load_jsonl(run / "raw.jsonl")
    if a.cmd == "merge":
        if not raw:
            print("merge_findings.py: RUN/raw.jsonl is empty; import findings first"); return 2
        findings = merge(raw)
        (run / "findings.json").write_text(json.dumps(findings, indent=2))
        (run / "summary.md").write_text(summary_md(findings, raw))
        p = problems(findings)
        print(json.dumps({"findings": len(findings), "verdicts": dict(Counter(f["verdict"] for f in findings)),
                          "open_problems": len(p), "summary": str(run / "summary.md")}))
        return 0
    findings = json.loads((run / "findings.json").read_text()) if (run / "findings.json").exists() else []
    if a.cmd == "validate":
        p = problems(findings)
        print("ok: every finding is adjudicated" if not p else "fix these and run merge + validate again:\n- " + "\n- ".join(p))
        return 1 if p else 0
    if a.cmd == "compare":
        if not a.previous:
            print("compare needs --previous FILE (findings.json or prior.jsonl)"); return 2
        pf = Path(a.previous)
        prev = json.loads(pf.read_text()) if pf.suffix == ".json" else load_jsonl(pf)
        for p in prev:
            p["category"] = norm_cat(p.get("category"))
        table = compare(findings, prev)
        (run / "regression.md").write_text("## Compared with the previous review\n\n" + table)
        print(table)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
