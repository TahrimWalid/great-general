# Rules of engagement (`.great-general/engagement.yaml`)

Contents: template · field notes · campaigns · proof policy · what the commander never does

`engagement.py check` validates this file; `engagement.py init` refuses to open a run until it passes. Keep it in the project (it holds no secrets) so every review uses the same rules.

## Template

```yaml
owner: "Your Name"
authorization: "I own this code and the lab listed below, and I authorise this review."   # required

target:
  repo: ~/projects/myapp                 # the repository under review
  worktree: ~/myapp_secrev/wt            # detached worktree: git worktree add --detach <path> <ref>
  ref: main
  scope_paths: []                        # empty = whole repo; or e.g. [src/myapp/serve, src/myapp/authz]
  focus: [src/myapp/serve, src/myapp/connect.py]   # highest priority: what changed since the last review

campaign: full-audit                     # pr | full-audit | release | follow-up | re-check
profile: standard                        # quick | standard | deep (passed to Cloudflare's skill)
budget: {max_agent_invocations: 80, max_spend_usd: 25}

previous_reviews:                        # earlier reports to regression-check against
  - ~/myapp_security_review_v2/findings.json     # or a prior.jsonl you converted from REPORT.md

in_scope:
  hosts: [10.136.28.168]                 # lab machines a proof may touch; nothing else
lab:
  never_touch: [devserver3, 203.0.113.10]
  machines: {myapp-target: 10.136.28.168}
  snapshot: {create: "incus snapshot create {host} {name}", restore: "incus snapshot restore {host} {name}", name: "pre-secrev-{run}"}

app_home_env: MYAPP_HOME                 # the app's own data-dir variable
scratch_home: ~/myapp_secrev/home        # proofs run against this, never the real data folder

poc_policy:
  allowed: false                         # true = minimal proofs for needs_validation items, lab only
  max_minutes: 10

generals:
  skip: []                               # e.g. [tob-agentic-actions-auditor] if there's no CI
report_only: true
```

## Field notes

- **authorization.** One plain sentence from the owner. It is recorded in `run.json` and printed at the top of the report.
- **worktree.** Reviewing a detached worktree keeps the review independent of whatever another session is changing in the main checkout. Record the commit, and say in the report if the worktree is dirty.
- **focus.** List what changed since the last review first: new servers, endpoints, auth code, integrations, outbound requests. Every general is told about it.
- **previous_reviews.** A findings.json from an earlier great-general or Cloudflare run works directly. For a prose report, convert each finding into one `prior.jsonl` line (`references/reporting.md`), keeping the earlier status (`fixed`, open, accepted).
- **budget.** Cloudflare's skill plans its hunters and verifiers against a maximum number of agent invocations. Tell it the budget so it reserves verification before hunting.

## Campaigns

| Campaign | When | What happens |
|---|---|---|
| `pr` | Every pull request or before a commit | `/security-review` on the diff, plus `differential-review` for risky changes (auth, crypto, network, parsing). Quick, high-confidence. |
| `full-audit` | Before a major release, or when nothing has been reviewed yet | Context building, then Cloudflare's six-phase audit, static analysis, insecure defaults, supply chain, CI workflows; then adjudication and variants. |
| `release` | Shipping (e.g. the first PyPI release) | Like full-audit, plus extra weight on release artefacts: CI workflows, pinned actions, Trusted Publishing, package contents, defaults a new user gets. |
| `follow-up` | One or a few specific suspected bugs | `fp-check` on each, then `variant-analysis` for the confirmed ones. |
| `re-check` | After fixes from an earlier review | Earlier findings carried into Cloudflare's prior-run handling, fresh verification of each, regression table. |

## Proof policy

Cloudflare's method executes target code only inside a sandbox with no external network, and never probes deployed systems. Questions it can't settle that way become `needs_validation`, with the exact open question. When the owner sets `poc_policy.allowed: true`, the commander may settle those questions in the owner's lab:

- **Only** a `needs_validation` item, and only its stated open question.
- **Only** lab machines in `in_scope.hosts` and the app's `scratch_home`. Never never-touch hosts, the real data folder, deployed services or anyone else's systems.
- `lab.py snapshot` on every lab machine first, then `lab.py restore-all` after.
- **Minimal:** show the flaw and stop. No persistence, no tooling beyond the one check, no spreading to other machines, within `max_minutes`.
- Write the exact steps to `<run>/pocs/<finding-id>.md`, so the fixing session can turn them into a regression test.

## What the commander never does

- Fix, commit, push, open PRs or change the target's configuration.
- Run any general that isn't approved and hash-verified.
- Update a general during a review.
- Treat silence as safety: an area no general covered is listed as "not reviewed", never as "clean".
