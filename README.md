# jev-guard

A 3-cent bouncer for your coding agent's shell.

jev-guard is a [Claude Code](https://claude.com/claude-code) plugin with two hooks backed by
[Jev](https://typesafe.ai), TypeSafe AI's model that returns typed probabilities instead of text:

1. **Permission classifier** (`PreToolUse` on `Bash`). Every shell command gets
   `p(read_only / reversible_write / destructive)` plus four yes/no risk probabilities.
   Confidently harmless commands are auto-allowed, so you stop clicking through `ls`, `git status`
   and `pytest`. Confidently destructive and irreversible commands are denied with the probabilities
   as the reason. Everything in between is left to Claude Code's normal permission flow.
2. **Prompt-injection sentinel** (`PostToolUse` on `WebFetch`, `WebSearch` and every MCP tool).
   Each tool result gets `p(injection)`. Above the threshold, Claude is told to treat the result as
   data and to surface the embedded instructions to you instead of following them.

One Python file, standard library only. About one second and a fraction of a cent per decision.

## Install

In Claude Code:

```
/plugin marketplace add alsoleg89/jev-guard
/plugin install jev-guard@jev-guard
```

Then give it a TypeSafe API key, either as `TYPESAFE_API_KEY` in the environment Claude Code runs
in, or in a file (the file works for the desktop app, which does not see your shell environment):

```bash
mkdir -p ~/.jev-guard && chmod 700 ~/.jev-guard && printf '%s' 'YOUR_KEY' > ~/.jev-guard/key && chmod 600 ~/.jev-guard/key
```

Restart Claude Code. Without a key the plugin does nothing.

## Dry run first, then turn it on

The plugin starts in `dry` mode: it judges every command, logs the verdict to
`~/.jev-guard/log.jsonl`, and changes nothing. After a day of normal work, look at what it would
have done:

```
/jev-guard:report
```

or, outside Claude Code:

```bash
python3 "$(find ~/.claude/plugins -name guard.py -path '*jev-guard*' | head -1)" report
```

You get the share of commands it would have auto-allowed, the riskiest commands it saw with their
probabilities, latency, token spend, and any flagged tool results. If the verdicts look right for
your repositories, enforce them:

```bash
export JEV_GUARD_MODE=on
```

The injection sentinel is on in both modes, because it only adds a warning to Claude's context.
Set `JEV_GUARD_SCAN=off` to disable it.

## How a command is judged

```
deny    p(destructive) >= 0.95  and  p(irreversible) >= 0.95
allow   no tripwire hit  and  p(destructive) < 0.05  and  every risk probability < 0.20
defer   everything else: Claude Code's own permission rules and prompts apply
```

The risk probabilities are independent Noul questions: `leaves_project`, `network_egress`,
`irreversible`, `exposes_secrets`.

**Tripwires.** A short regex list (`sudo`, `rm -rf`, force push, `git reset --hard`, `curl | sh`,
dotfiles like `~/.ssh`, `/etc/`, `DROP TABLE`, `npm publish`, `kubectl delete`, and so on) can never
be auto-allowed, whatever Jev says. This exists because of a measured failure mode: on a
500-issue benchmark (see Background) Jev assigned exactly zero
probability to the correct answer on 21 cases. A calibrated model that is occasionally certain and
wrong needs a floor under it. Tripwires only block auto-allow; they never deny.

**Fail-open.** No key, no network, a timeout, a malformed response: the hook prints nothing and
Claude Code behaves as if the plugin were not installed. Errors are counted in the report.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `JEV_GUARD_MODE` | `dry` | `dry` logs only, `on` enforces allow and deny |
| `JEV_GUARD_ALLOW_MAX` | `0.05` | auto-allow needs `p(destructive)` below this |
| `JEV_GUARD_NOUL_MAX` | `0.20` | ...and every risk probability below this |
| `JEV_GUARD_DENY_MIN` | `0.95` | deny needs `p(destructive)` and `p(irreversible)` above this |
| `JEV_GUARD_INJECT_MIN` | `0.60` | injection warning threshold |
| `JEV_GUARD_SCAN` | `on` | `off` disables the injection sentinel |
| `JEV_GUARD_MODEL` | `jev-1.13.0` | pinned model id |
| `JEV_GUARD_TIMEOUT` | `8` | seconds per Jev call |
| `JEV_GUARD_HOME` | `~/.jev-guard` | key file and log location |

## What is logged

Every judged command is appended to `~/.jev-guard/log.jsonl` (mode 0600) with the command text,
working directory, probabilities, tripwire flag and verdict. Commands can contain secrets. The log
never leaves your machine, but treat it accordingly.

The command text and working directory are sent to the TypeSafe API. Tool results scanned by the
sentinel are sent too, truncated to 8,000 characters.

## Limitations

- macOS and Linux only. The hook command is `python3 guard.py`; Windows needs a `python` alias
  and a `.cmd` wrapper, which are not included.
- Adds roughly one second to every Bash call and to every scanned tool result.
- Only `Bash` is judged. File writes outside the project are a one-line path check in Claude Code's
  own permission rules and are not duplicated here.
- The sentinel scans only the first 8,000 characters of a tool result.
- `allow` bypasses the permission system, including your own deny rules for that command. Tripwires
  cover the common dangerous shapes, but review the report before switching to `on`.

## Development

```bash
python3 test_guard.py
```

Decision rules, tripwires, response flattening, and the hook script end to end against a fake Jev
server: no network, no key. To exercise it inside Claude Code without installing:

```bash
claude -p "run: echo hello" --plugin-dir /path/to/jev-guard
```

## Background

The thresholds and the tripwire layer come from a benchmark of Jev 1.13.0 against GPT-5.6 Luna on
500 real VS Code issues: no clear winner on Choice accuracy (79.8% vs 78.6%, bootstrap 95% CI
-1.4 to +3.8 points), lower Brier score but far worse log loss for Jev because of 21 hard-zero
misses, p50 latency 0.90 s, and about a quarter of the cost. Those numbers are why this plugin
treats Jev as a fast, cheap, mostly calibrated voter with a regex floor under it, and never as the
only line of defense.
