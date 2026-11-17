---
tags: [great-general]
max_turns: 300
timeout_seconds: 7200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash, Agent]
---

Run a full security review of tasknest/ under our rules in .great-general/engagement.yaml, and tell me whether anything we fixed last time came back. For this eval the approved roster is ./generals.lock.json with its cache in ./.gg-cache (pass --lock and --cache to the scripts).

Input files: .great-general/engagement.yaml, prior.jsonl
