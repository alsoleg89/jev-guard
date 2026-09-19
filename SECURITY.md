# Security policy

## What jev-guard is and is not

jev-guard is a convenience and audit layer, not a security boundary. It reduces permission prompts for
commands a model is confident are harmless, blocks a small set it is confident are destructive, and
warns about tool results that look like prompt injection. A determined attacker who controls the text
your agent reads can still find inputs the model scores wrong. Sandboxing, network egress control, and
Claude Code's own deny rules are the boundary. Run jev-guard inside them, not instead of them.

## Threat model

Assumed attacker: someone who controls content your agent reads (a web page, a dependency README, an
issue, an MCP result) or a repository you cloned, and who wants the agent to run a destructive command,
exfiltrate data, or persist on your machine. The agent itself is not assumed adversarial.

What jev-guard aims to do against that attacker:

- never auto-allow a command, edit, or MCP call that matches a tripwire, whatever the model says;
- never let a cloned repository loosen your settings: a repo's `.jev-guard.json` can only tighten;
- never auto-run repository-controlled code (tests, builds, scripts) unless you marked the project trusted;
- never send your secrets to the API: token-shaped values are redacted before any request and before logging;
- fail open, or fail to a prompt if you set `fail=ask`, never fail to an allow.

What it does not do:

- it does not read files a command references, so a dangerous `Makefile` target or `package.json` script
  is judged by its name, not its contents (edits to those files are judged when the agent writes them);
- it does not see shell state across calls: `X='rm -rf ~'` in one call and `$X` in the next are two
  separate, individually harmless-looking strings. `eval`, `source` and bare-variable execution are
  tripwires for this reason;
- it cannot withhold a tool result that already reached the model: the injection sentinel adds a warning
  (or blocks the turn with `inject_action=block`), it does not filter;
- it is not deterministic: identical input moves by about ±0.03 between calls, and the cache only makes
  repeats consistent within its TTL.

## Reporting a vulnerability

Open a GitHub issue titled `security:` with a reproduction. For anything that would let an attacker
auto-allow a dangerous action, email the maintainer address on the GitHub profile instead of filing
publicly, and allow a few days for a fix before disclosure. Reports that add a case to `eval.py` are
the most useful kind.
