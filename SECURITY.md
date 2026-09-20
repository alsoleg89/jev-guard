# Security policy

## What jev-bouncer is and is not

jev-bouncer is a convenience and audit layer, not a security boundary. It reduces permission prompts for
commands a model is confident are harmless, blocks a small set it is confident are destructive, and
warns about tool results that look like prompt injection. A determined attacker who controls the text
your agent reads can still find inputs the model scores wrong. Sandboxing, network egress control, and
Claude Code's own deny rules are the boundary. Run jev-bouncer inside them, not instead of them.

## Threat model

Assumed attacker: someone who controls content your agent reads (a web page, a dependency README, an
issue, an MCP result) or a repository you cloned, and who wants the agent to run a destructive command,
exfiltrate data, or persist on your machine. The agent itself is not assumed adversarial, but it is
assumed to be hijackable by that content: the injection sentinel reads a tool result only after it has
already reached the model, so the outbound side is guarded separately, before the request goes out.

What jev-bouncer aims to do against that attacker:

- never auto-allow a command, edit, or MCP call that matches a tripwire, whatever the model says;
- never let a cloned repository loosen your settings: a repo's `.jev-bouncer.json` can only tighten;
- never auto-run repository-controlled code (tests, builds, scripts) unless you marked the project trusted;
- deny the obvious outbound exfiltration shapes on `WebFetch` and `WebSearch` before the request leaves:
  a secret-shaped value or an opaque 40-character blob in the URL or query, a loopback, link-local or
  `.internal` host, a raw IP, a non-standard port, a non-`http(s)` scheme, credentials in the userinfo;
- never send your secrets to the API: token-shaped values are redacted before any request and before logging;
- fail open, or fail to a prompt if you set `fail=ask`, never fail to an allow.

What it does not do:

- it does not follow a command all the way down: it reads what a command runs for a fixed set of shapes
  only, namely `make` targets (the recipe plus one level of prerequisites), `package.json` scripts with
  their `pre`/`post` hooks, `bash`/`sh`/`zsh`/`source` and `./script.sh` files, `python` and `node` file
  arguments, `just` recipes and `Taskfile` tasks. Those are resolved inside the project (a `..` path or a
  symlink that escapes it is refused), at most 64 KB of a file is read, and a ~1500-character excerpt is
  judged along with the command; a tripwire in the excerpt trips the command. Nothing is expanded or
  executed, so variables, `$(shell ...)`, `include`d makefiles, nested `make` and whatever a recipe calls
  in turn are still judged by name, as is every other shape. `read_referenced=off` restores the old
  behaviour, where a dangerous target was judged by its name alone;
- it does not see shell state across calls: `X='rm -rf ~'` in one call and `$X` in the next are two
  separate, individually harmless-looking strings. `eval`, `source` and bare-variable execution are
  tripwires for this reason;
- it cannot withhold a tool result that already reached the model: the injection sentinel adds a warning
  (or blocks the turn with `inject_action=block`), it does not filter;
- the outbound web tier matches shapes, not meaning: a short secret, one encoded to look like a word,
  one split across several requests, or one sent by a channel that is not `WebFetch` or `WebSearch`
  (a Bash `curl`, an MCP tool, a file the agent writes somewhere synced) still gets out. It raises the
  cost of the obvious one-shot exfiltration; network egress control is the boundary;
- it is not deterministic: identical input moves by about ±0.03 between calls, and the cache only makes
  repeats consistent within its TTL.

## Reporting a vulnerability

Open a GitHub issue titled `security:` with a reproduction. For anything that would let an attacker
auto-allow a dangerous action, email the maintainer address on the GitHub profile instead of filing
publicly, and allow a few days for a fix before disclosure. Reports that add a case to `eval.py` are
the most useful kind.
