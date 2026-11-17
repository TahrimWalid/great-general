#!/usr/bin/env python3
"""Deterministic risk scan of a skill/plugin's files, for vetting a general.

Usage (normally called by generals.py, but works alone):
  risk_scan.py DIR [--only FILE ...] [--json]

It flags what a reviewer must look at, not what is "malicious". Security
skills legitimately talk about eval(), curl and prompt injection in their docs,
so the same pattern is weighted by where it appears:
  - in code files (scripts, workflows, hooks): weighted high
  - in Markdown/docs: weighted low, except instructions aimed at the agent
    reading them (e.g. "do not report", "ignore previous instructions"), which
    are medium, because a skill's Markdown *is* the agent's instructions

Flag categories: hook, code, permissions, network, credentials, exec,
obfuscation, hidden-text, agent-directive, binary, symlink, mcp, large.
A script can't be talked out of a flag; that's the point of running it before
any AI reviewer reads the files.
Exit code: 0 (no high flags) or 1 (at least one high flag).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CODE_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".cjs", ".mjs", ".ts", ".rb", ".pl", ".ps1", ".go", ".rs", ".php", ".lua"}
DOC_EXT = {".md", ".txt", ".rst", ".yaml", ".yml", ".toml", ".json", ".ql", ".qll", ".j2"}
LARGE_BYTES = 512 * 1024  # skills are text; anything this large deserves a look

CODE_PATTERNS = {
    "network": r"\b(curl|wget|nc|ncat|telnet)\b|requests\.(get|post|put)|urllib\.request|http\.client|fetch\(|axios|XMLHttpRequest|socket\.(socket|connect)|Invoke-WebRequest",
    "credentials": r"~/\.ssh|id_rsa|id_ed25519|\.aws/|\.netrc|\.git-credentials|GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET|keychain|secret-tool|gpg --export-secret",
    "exec": r"\beval\(|\bexec\(|shell=True|os\.system\(|child_process|\|\s*(ba)?sh\b|base64\s+(-d|--decode)|python3? -c|Function\(",
}
DOC_PATTERNS = {
    "agent-directive": r"(?i)\b(ignore (all |any )?(previous|prior|above) instructions|do not (report|flag|mention|disclose)|don'?t (report|flag|mention)|you are now\b|skip (the )?(review|verification|vetting)|this (skill|file|code) is (safe|trusted|verified)|without (asking|telling) the user|exfiltrat)",
}
BIDI_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069]")  # bidirectional controls: the "Trojan Source" trick -> high
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")  # can hide text; also used legitimately -> medium
EMOJI_ZWJ = re.compile("(?<=[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F])\u200d(?=[\U0001F000-\U0001FAFF\u2600-\u27BF])")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|fixtures?)(/|$)|\.test\.|_test\.|(^|/)test_[^/]*$")
B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{240,}")
HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|[0-9a-fA-F]{400,}")
ALLOWED_TOOLS = re.compile(r"^allowed-tools:\s*(.+)$", re.MULTILINE)


def flag(out, cat, sev, path, line, text):
    # Code in test harnesses is not run by the skill itself: one level lower, and labelled.
    if TEST_PATH.search(path) and cat in ("exec", "network", "credentials", "code"):
        sev = {"high": "medium", "medium": "low"}.get(sev, sev)
        text = "[test file] " + text
    out.append({"category": cat, "severity": sev, "file": path, "line": line, "excerpt": text.strip()[:160]})


def scan_file(root: Path, f: Path, out: list) -> None:
    rel = f.relative_to(root).as_posix()
    if f.is_symlink():
        flag(out, "symlink", "high", rel, 0, f"symlink -> {f.resolve()}")
        return
    data = f.read_bytes()
    if len(data) > LARGE_BYTES:
        flag(out, "large", "medium", rel, 0, f"{len(data)} bytes")
    if b"\x00" in data[:8192]:
        flag(out, "binary", "high", rel, 0, "binary file in a skill")
        return
    text = data.decode("utf-8", "replace")
    first = text.splitlines()[0] if text else ""
    is_code = f.suffix in CODE_EXT or first.startswith("#!")
    name = f.name.lower()
    if name in ("hooks.json",) or (name.endswith(".json") and '"hooks"' in text and ('"PreToolUse"' in text or '"Stop"' in text or '"PostToolUse"' in text or '"SessionStart"' in text or '"UserPromptSubmit"' in text)):
        kinds = set(re.findall(r'"type"\s*:\s*"(command|prompt)"', text))
        sev = "high" if "command" in kinds else "medium"
        flag(out, "hook", sev, rel, 0, f"runs automatically; hook types: {sorted(kinds) or ['unknown']}")
    if name in (".mcp.json", "mcp.json") or '"mcpServers"' in text:
        flag(out, "mcp", "high", rel, 0, "declares MCP servers (new tools / processes)")
    if is_code:
        flag(out, "code", "medium", rel, 0, "executable code" + (f" ({first[:40]})" if first.startswith("#!") else ""))
    for m in ALLOWED_TOOLS.finditer(text):
        tools = m.group(1)
        sev = "medium" if re.search(r"\bBash\b(?!\()", tools) or "*" in tools else "info"
        flag(out, "permissions", sev, rel, text[:m.start()].count("\n") + 1, f"allowed-tools: {tools}")
    for n, line in enumerate(text.splitlines(), 1):
        if BIDI_CHARS.search(line):
            flag(out, "hidden-text", "high", rel, n, "bidirectional control character (can make code read differently than it runs): " + repr(line[:80]))
        elif ZERO_WIDTH.search(EMOJI_ZWJ.sub("", line)):
            flag(out, "hidden-text", "medium", rel, n, "zero-width character (check nothing is hidden): " + repr(line[:80]))
        if B64_BLOB.search(line) or HEX_BLOB.search(line):
            flag(out, "obfuscation", "high" if is_code else "medium", rel, n, "long encoded blob")
        pats = CODE_PATTERNS if is_code else {}
        for cat, pat in pats.items():
            if re.search(pat, line):
                flag(out, cat, "high" if cat in ("credentials", "exec") else "medium", rel, n, line)
        if not is_code and f.suffix in DOC_EXT | {""}:
            for cat, pat in DOC_PATTERNS.items():
                if re.search(pat, line):
                    flag(out, cat, "medium", rel, n, line)
            for cat, pat in CODE_PATTERNS.items():
                if cat == "credentials" and re.search(pat, line):
                    flag(out, cat, "low", rel, n, line)


def scan(root: Path, only: list[str] | None = None) -> list[dict]:
    out: list[dict] = []
    files = [root / o for o in only] if only else sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink())
    for f in files:
        if ".git" in f.relative_to(root).parts:
            continue
        if f.exists() or f.is_symlink():
            scan_file(root, f, out)
    return out


def summarize(flags: list[dict]) -> dict:
    by: dict[str, dict[str, int]] = {}
    for x in flags:
        by.setdefault(x["category"], {}).setdefault(x["severity"], 0)
        by[x["category"]][x["severity"]] += 1
    return {"total": len(flags), "high": sum(1 for x in flags if x["severity"] == "high"), "by_category": by}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--only", nargs="*", help="scan only these files (relative to DIR)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    flags = scan(Path(a.dir), a.only)
    s = summarize(flags)
    if a.json:
        print(json.dumps({"summary": s, "flags": flags}, indent=2))
    else:
        print(json.dumps(s, indent=2))
        for x in [f for f in flags if f["severity"] == "high"][:40]:
            print(f"HIGH {x['category']:<14} {x['file']}:{x['line']}  {x['excerpt']}")
    return 1 if s["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
