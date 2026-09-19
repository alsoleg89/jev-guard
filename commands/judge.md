---
description: Ask Jev how it would judge one shell command, without running it
allowed-tools: Bash(python3:*)
argument-hint: <shell command>
---
Show the user this jev-guard verdict verbatim in a code block, then one sentence on what the verdict means (allow: would run without a prompt; deny: would be blocked; defer: your normal permission rules apply). Do not run the command.

!`python3 "${CLAUDE_PLUGIN_ROOT}/guard.py" judge $ARGUMENTS`
