# Findings, adjudication and the report

Contents: unified record · verdicts · adjudication · converting an earlier report · REPORT.md template · trust over time

## Unified record

One JSON object per line in `<run>/raw.jsonl`. The importers write these; for prose generals, write them yourself and use `import manual`.

```json
{"fingerprint": "access_control:src/app/serve/api.py:handle_export",
 "title": "Export endpoint returns other users' sessions",
 "verdict": "confirmed",
 "severity": "high",
 "confidence": "high",
 "category": "idor",
 "locations": [{"file": "src/app/serve/api.py", "line": 212}],
 "description": "One or two sentences in plain words.",
 "evidence": [{"file": "src/app/serve/api.py", "line": 212, "description": "no owner check before load_session(id)"}],
 "remediation": "Smallest effective fix at the last trusted decision point.",
 "open_question": null,
 "reason": null,
 "source": {"general": "tob-fp-check", "commit": "149d7b21f406", "ref": "verdict 3"}}
```

Allowed values for each field:

| Field | Values |
|---|---|
| `verdict` | `confirmed`, `needs_validation` (with the exact `open_question`, and no severity), `rejected` (with `reason`), or `candidate` (not yet adjudicated) |
| `severity` | `critical`, `high`, `medium`, `low` or `informational`. Only on confirmed findings, and never higher than the impact actually shown. Cloudflare's calibration is a good anchor: critical = unauthenticated code execution, full data-store access or arbitrary account takeover; high = an explicit control fully defeated with real consequences (auth bypass, cross-user read/write, authenticated code execution). |
| `fingerprint` | A stable key: `family:file:symbol-or-route`. Prefer the general's own fingerprint. |
| `category` | Free text; `merge_findings.py` maps it to a family (access_control, injection_sql, ssrf, secrets…) so different generals' names merge. |

## Verdicts after merging

| Merged verdict | Meaning | What to do |
|---|---|---|
| `confirmed` | At least one adjudicated source confirmed it, and none rejected it | Run `variant-analysis` |
| `needs_validation` | A source-grounded question remains open | Lab validation if the policy allows; otherwise report the question |
| `rejected` | Disproved, with a reason | Listed in the appendix, not the findings |
| `candidate` | Only raw scanner or unadjudicated output | **Must** be adjudicated before the report |
| `conflict` | One source confirmed, another rejected | A fresh verifier settles it |

`merge_findings.py validate` fails while any candidate or conflict remains.

## Adjudication

Give each candidate or conflict to a **fresh** subagent that has not seen the general's reasoning. Either it runs `tob-fp-check` on the one finding, or it is told to try to *disprove* the claim from source (trace input to sink, and check the controls on the way). It writes back one manual record with its verdict and evidence. Re-run `merge` afterwards. Critical and high findings that only one general reported deserve a second, independent adjudicator.

## Converting an earlier report

For a prose report (e.g. an earlier REPORT.md and FIXES.md), write one line per finding to `prior.jsonl`:

```json
{"id": "OCT-07", "title": "SSRF in webhook sender", "verdict": "confirmed", "disposition": "fixed",
 "category": "ssrf", "locations": [{"file": "src/app/outbox/webhook.py", "line": 55}]}
```

Use `disposition: "fixed"` for findings the fixes document says were fixed. `compare` then reports each as:
- **REGRESSED**: found again
- **still fixed**: not found again; check the area was covered
- **still open**

Code moves between reviews, so matching uses the fingerprint first, then the same file and bug family (nearest line), then a similar title.

## REPORT.md template

```markdown
# Security review: <repo> @ <commit> (<campaign>, <date>)
Authorisation: <from run.json>. Report only: no changes were made to the target.

## Verdict
3–5 sentences: overall risk, what must be fixed before release, regressions first.

## Summary
<summary.md from merge_findings.py: counts, generals and versions, agreement between generals>

## Regressions since <previous review>
<regression.md table>

## Findings (confirmed), most severe first
For each: id, title, severity + one-line reason, files and lines, how to reproduce it (source trace,
or the lab steps in pocs/), impact in plain words, smallest effective fix, which generals found it.

## Needs validation
For each: the exact open question, why source alone can't settle it, and a safe validation plan.

## Coverage
What each general reviewed (from its own coverage statement, e.g. Cloudflare's coverage ledger),
what nothing reviewed, and why. Never "clean"; say what was covered.

## Generals
Table: id, pinned commit, approved by, updates available upstream (not applied).

## Appendix
Rejected findings with reasons; actions log; lab snapshots taken and restored.
```

## Trust over time

After the owner reviews a report, they set `disposition` on each finding in `findings.json` (fixed / wrong / intentional / didnt_matter). Then:

```bash
python3 scripts/merge_findings.py trust --runs ~/.great-general/runs/<repo>
```

This shows, per general: findings reported, found by it alone, overruled by adjudication, and precision. Bugs found later by users or other reviewers that every general missed go into the owner's notes as escapes. Add each one as an eval case, so future changes to the roster are measured against it.
