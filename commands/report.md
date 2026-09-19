---
description: Show what jev-guard would have allowed, deferred, or denied so far
allowed-tools: Bash(python3:*)
---
Below is the jev-guard report. Show it to the user verbatim in a code block, then add one sentence saying whether the auto-allow verdicts look safe enough to switch `JEV_GUARD_MODE=on`.

!`python3 "${CLAUDE_PLUGIN_ROOT}/guard.py" report`
