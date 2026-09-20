# Changelog

## Unreleased

- `suggest`: allowlist proposals from your own audit log. Bash commands that were deferred and then ran
  are grouped by shape (`npm run test`, `docker compose up`, `gh pr view`) and turned into anchored
  `allow_patterns`, with counts and examples, for shapes seen at least `--min` times. Shapes that hit a
  tripwire, that would match something denied or tripped in the log, or whose program dispatches on the
  argument the shape strips (`python3 app.py`) are never proposed.
- `suggest --apply '<pattern>'` writes only patterns from that list: into the repository's
  `.jev-bouncer.json` in a trusted project, otherwise into `project_allow` in `~/.jev-bouncer/config.json`,
  a per-project map that `settings()` merges into `allow_patterns` for that directory tree. An untrusted
  repository still cannot widen your guard by editing its own config.
- New `/jev-bouncer:suggest` command: it shows the proposals and asks which to apply; nothing is written
  without you naming a pattern.

## 0.4.0

- Renamed from jev-guard to jev-bouncer; the old name belonged to an unrelated project. Everything that carried the name moved with it: the plugin and marketplace are `jev-bouncer`, commands are `/jev-bouncer:report`, `/jev-bouncer:calibrate`, `/jev-bouncer:judge`, `/jev-bouncer:trust`, the script is `bouncer.py`, settings are `JEV_BOUNCER_*`, the state directory is `~/.jev-bouncer` (key, config, log, cache), and project files are `.jev-bouncer.json` and `.jev-bouncer.md`. To migrate: `mv ~/.jev-guard ~/.jev-bouncer`, rename any project config files, and reinstall from `alsoleg89/jev-bouncer`. GitHub redirects the old repository URL.

## 0.3.0

- Built-in read-only allowlist: `git status`, `ls`, `rg`, `docker ps`, `kubectl get` and about 60 more shapes are allowed locally with no API call and no key. One simple command only: no `;`, `&&`, `|`, redirects, subshells or newlines, and never a tripwire hit.
- Trusted projects: test runners, builds and project scripts (`pytest`, `npm test`, `make test`, `./script`) only auto-run in projects you marked with `bouncer.py trust` or `/jev-bouncer:trust`, because they execute repository-controlled code. New Noul `runs_project_code` enforces this on the API path too.
- File edits are judged: `Write`, `Edit`, `MultiEdit`, `NotebookEdit`. A `curl | sh` planted in `src/app.py`, a reverse shell, an `exec(base64...)`, a `postinstall` hook, or a write to `~/.zshrc` no longer passes as a routine edit. Path tripwires for CI, hooks, manifests, agent config and paths outside the project.
- MCP tool calls are judged: reads auto-allow, side effects (send, deploy, delete, pay, merge, permissions) never do.
- Plain-language project policy: `.jev-bouncer.md` travels with every question.
- Project config restriction: a repository's `.jev-bouncer.json` can set `policy` and `hold_patterns` only. Thresholds and `allow_patterns` come from your own `~/.jev-bouncer/config.json` or apply only in trusted projects, so a cloned repo cannot loosen your guard.
- Secret redaction before any request and before logging: private keys, `sk-`, `ghp_`, `AKIA`, `xox`, JWTs, bearer tokens, `password=`/`token=` values.
- Verdict cache (default 6 h) keyed on the full question: repeats cost nothing and cannot be re-rolled.
- Bash output scanning after network-y commands (`curl`, `git pull`, `npm install`, `gh pr view`), configurable to all or off.
- Head-and-tail clipping for long tool results; configurable scan floor (`scan_min_chars`, default 40).
- `classifierContext` on flagged results: a one-line note for Claude Code's own auto-mode classifier.
- `fail=ask` mode: force a permission prompt when the API is unavailable instead of failing open.
- `inject_action=block` mode: block the turn on a flagged result instead of warning.
- New tripwires: `eval`, `source`, dot-sourcing, `nohup`, `at`, `git push +refspec`, `git -c … push --force`, `.env`, credential and token files (`~/.kube/config`, `~/.config/gh`, `.npmrc`, `.pypirc`, `.pem`, shell history).
- `calibrate`: replay your own log at other thresholds; shows which prompts you answered that Jev would have removed and which denials you overrode.
- `report --json`, `--since`, `--project`; per-tool breakdown; `ran` events join verdicts to what actually executed.
- `judge --edit PATH`, `judge --mcp TOOL JSON`, `judge --ask-jev`; `scan`; `trust`; `version`.
- Log rotation at 20 MB; project name and session id on every row.
- Eval corpus: 268 commands, 32 edits, 30 MCP calls, 6 policy pairs, 34 tool results, threshold sweep, trusted and untrusted verdicts, machine-readable `docs/eval.json`.

## 0.2.0

- Criteria rewritten after a live eval; thresholds 0.10 / 0.40 from a sweep; 266-command eval; CI workflow; hero card.

## 0.1.0

- PreToolUse permission classifier for Bash and PostToolUse injection sentinel, dry mode, report.
