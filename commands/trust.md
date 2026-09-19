---
description: Mark this project trusted so test runners and project scripts can auto-run here
allowed-tools: Bash(python3:*)
---
Show the user this output verbatim, then remind them in one sentence that trust means commands like `pytest` or `npm test` will run without a prompt in this directory, which executes code from the repository.

!`python3 "${CLAUDE_PLUGIN_ROOT}/guard.py" trust`
