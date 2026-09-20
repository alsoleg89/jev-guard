---
description: Turn your jev-bouncer log into allow_patterns, so the prompts you keep answering stop coming back
allowed-tools: Bash(python3:*)
---
Show the user this output verbatim in a code block, then list the proposed patterns in plain language (what each one would auto-allow) and ask which of them to apply. Apply only the ones the user names, by running the same command again with `--apply` and those exact pattern strings as arguments, for example `--apply '^npm run test\b'`. Never apply anything the user did not name, and never invent a pattern that is not in the list above: only patterns from this output can be written.

!`python3 "${CLAUDE_PLUGIN_ROOT}/bouncer.py" suggest`
