#!/usr/bin/env python3
"""Lab machine controls for a QA run: snapshots before changes, restore after,
and opt-in, owner-provided attack simulations (for testing security or
monitoring products in the owner's own lab).

Usage:
  lab.py snapshot    --config .qa/config.yaml --run-dir RUN --machine NAME
  lab.py restore-all --config .qa/config.yaml --run-dir RUN
  lab.py simulate    --config .qa/config.yaml --run-dir RUN --scenario NAME
  lab.py status      --run-dir RUN

Rules enforced here (not just written down):
  - a machine must be listed in lab.machines, its address must be in
    in_scope.hosts, and neither may appear in lab.never_touch
  - commands come only from the config, run without a shell, and are never
    altered; placeholders {host} {name} {run} are the only substitutions
  - simulate refuses unless lab_simulation.enabled is true, the environment is
    not production, and every target machine was snapshotted in this run
  - every action is appended to RUN/logs/actions.jsonl and RUN/logs/lab.jsonl,
    and simulation output goes to RUN/logs/sim-<name>.log

Exit codes: 0 ok, 1 refused or command failed, 2 usage/config error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shlex
import subprocess
import sys
from pathlib import Path

SNAPSHOT_TIMEOUT_S = 600  # creating/restoring a VM snapshot can take minutes


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def load(cfg_path: str) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.exit("lab.py: PyYAML is required: pip install pyyaml")
    try:
        return yaml.safe_load(Path(cfg_path).read_text()) or {}
    except FileNotFoundError:
        sys.exit(f"lab.py: config not found: {cfg_path}")


def log(run: Path, record: dict) -> None:
    (run / "logs").mkdir(parents=True, exist_ok=True)
    record = {"time": now(), **record}
    with (run / "logs" / "lab.jsonl").open("a") as fh:
        fh.write(json.dumps(record) + "\n")
    action = {"time": record["time"], "action": "lab:" + record["event"], "where": record.get("machine") or record.get("scenario"),
              "role": "lab-operator", "created": record.get("snapshot")}
    with (run / "logs" / "actions.jsonl").open("a") as fh:
        fh.write(json.dumps(action) + "\n")


def history(run: Path) -> list[dict]:
    p = run / "logs" / "lab.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def check_machine(cfg: dict, machine: str) -> str | None:
    """Return an error message, or None if the machine may be touched."""
    lab = cfg.get("lab") or {}
    machines = lab.get("machines") or {}
    never = {str(h).lower() for h in (lab.get("never_touch") or [])}
    in_scope = {str(h).lower() for h in ((cfg.get("in_scope") or {}).get("hosts") or [])}
    if machine not in machines:
        return f"'{machine}' is not listed in lab.machines"
    addr = str(machines[machine]).lower()
    if machine.lower() in never or addr in never:
        return f"'{machine}' ({addr}) is in lab.never_touch"
    if addr not in in_scope:
        return f"'{machine}' address {addr} is not in in_scope.hosts"
    return None


def run_cmd(template: str, timeout: float, out: Path | None = None, **subs: str) -> tuple[int, str]:
    try:
        argv = [part.format(**subs) for part in shlex.split(template)]
    except (KeyError, ValueError) as e:
        return 2, f"bad command template {template!r}: {e}"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired as e:
        text = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")) + "\n[timed out]"
        if out:
            out.write_text(text)
        return 124, f"timed out after {timeout:.0f}s"
    text = p.stdout + (("\n" + p.stderr) if p.stderr else "")
    if out:
        out.write_text(text)
    return p.returncode, text.strip()[-500:]


def cmd_snapshot(a, cfg: dict, run: Path) -> int:
    err = check_machine(cfg, a.machine)
    if err:
        print(f"lab.py: refused: {err}")
        return 1
    snap = (cfg.get("lab") or {}).get("snapshot") or {}
    if not snap.get("create") or not snap.get("restore"):
        print("lab.py: lab.snapshot.create and lab.snapshot.restore templates are required")
        return 2
    name = str(snap.get("name", "pre-qa-{run}")).format(run=run.name)
    if any(h.get("event") == "snapshot" and h.get("machine") == a.machine and h.get("ok") for h in history(run)):
        print(json.dumps({"machine": a.machine, "snapshot": name, "status": "already taken in this run"}))
        return 0
    code, msg = run_cmd(snap["create"], SNAPSHOT_TIMEOUT_S, host=a.machine, name=name, run=run.name)
    log(run, {"event": "snapshot", "machine": a.machine, "snapshot": name, "ok": code == 0, "exit": code})
    print(json.dumps({"machine": a.machine, "snapshot": name, "ok": code == 0, "exit": code, "output": msg}))
    return 0 if code == 0 else 1


def cmd_restore_all(a, cfg: dict, run: Path) -> int:
    snap = (cfg.get("lab") or {}).get("snapshot") or {}
    done = {h["machine"] for h in history(run) if h.get("event") == "restore" and h.get("ok")}
    taken = [h for h in history(run) if h.get("event") == "snapshot" and h.get("ok") and h["machine"] not in done]
    failures = 0
    for h in reversed(taken):
        code, msg = run_cmd(snap["restore"], SNAPSHOT_TIMEOUT_S, host=h["machine"], name=h["snapshot"], run=run.name)
        log(run, {"event": "restore", "machine": h["machine"], "snapshot": h["snapshot"], "ok": code == 0, "exit": code})
        print(json.dumps({"machine": h["machine"], "restored": code == 0, "exit": code, "output": msg}))
        failures += code != 0
        if code == 0 and snap.get("delete"):
            dcode, _ = run_cmd(snap["delete"], SNAPSHOT_TIMEOUT_S, host=h["machine"], name=h["snapshot"], run=run.name)
            log(run, {"event": "delete-snapshot", "machine": h["machine"], "snapshot": h["snapshot"], "ok": dcode == 0, "exit": dcode})
    if not taken:
        print(json.dumps({"restored": 0, "note": "no unrestored snapshots recorded in this run"}))
    return 1 if failures else 0


def cmd_simulate(a, cfg: dict, run: Path) -> int:
    sim = cfg.get("lab_simulation") or {}
    if not sim.get("enabled"):
        print("lab.py: refused: lab_simulation.enabled is not true in the config")
        return 1
    if cfg.get("environment") == "production":
        print("lab.py: refused: simulations never run when environment is production")
        return 1
    scen = next((s for s in sim.get("scenarios") or [] if s.get("name") == a.scenario), None)
    if not scen:
        print(f"lab.py: no scenario named '{a.scenario}' in lab_simulation.scenarios")
        return 2
    machines = [scen.get("run_on")] + list(scen.get("targets") or [])
    for m in machines:
        err = check_machine(cfg, m)
        if err:
            print(f"lab.py: refused: {err}")
            return 1
    snapped = {h["machine"] for h in history(run) if h.get("event") == "snapshot" and h.get("ok")}
    missing = [m for m in scen.get("targets") or [] if m not in snapped]
    if missing:
        print(f"lab.py: refused: snapshot these target machines first: {', '.join(missing)} (lab.py snapshot --machine ...)")
        return 1
    minutes = float(scen.get("max_minutes", 5))
    out = run / "logs" / f"sim-{a.scenario}.log"
    log(run, {"event": "simulate-start", "scenario": a.scenario, "machine": scen.get("run_on"), "targets": scen.get("targets")})
    code, msg = run_cmd(scen["command"], minutes * 60, out=out, run=run.name)
    log(run, {"event": "simulate-end", "scenario": a.scenario, "ok": code == 0, "exit": code})
    print(json.dumps({"scenario": a.scenario, "exit": code, "log": str(out), "expect": scen.get("expect"),
                      "next": "now check that the app under test reacted as 'expect' says, and record the result in coverage.csv"}))
    return 0 if code == 0 else 1


def cmd_status(a, cfg: dict, run: Path) -> int:
    h = history(run)
    snaps = {x["machine"]: x["snapshot"] for x in h if x.get("event") == "snapshot" and x.get("ok")}
    restored = {x["machine"] for x in h if x.get("event") == "restore" and x.get("ok")}
    print(json.dumps({"snapshots_taken": snaps, "restored": sorted(restored),
                      "still_to_restore": sorted(set(snaps) - restored),
                      "simulations": [x for x in h if x.get("event", "").startswith("simulate")]}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["snapshot", "restore-all", "simulate", "status"])
    ap.add_argument("--config", default=".qa/config.yaml")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--machine")
    ap.add_argument("--scenario")
    a = ap.parse_args()
    run = Path(a.run_dir)
    if not (run / "run.json").exists():
        print(f"lab.py: {run} is not a run directory (no run.json); run preflight.py (independent-qa) or engagement.py init (great-general) first")
        return 2
    cfg = load(a.config) if a.cmd != "status" else {}
    if a.cmd == "snapshot" and not a.machine:
        print("lab.py snapshot: --machine is required")
        return 2
    if a.cmd == "simulate" and not a.scenario:
        print("lab.py simulate: --scenario is required")
        return 2
    return {"snapshot": cmd_snapshot, "restore-all": cmd_restore_all, "simulate": cmd_simulate,
            "status": cmd_status}[a.cmd](a, cfg, run)


if __name__ == "__main__":
    sys.exit(main())
