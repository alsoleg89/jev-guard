---
description: Show what jev-bouncer would have allowed, deferred, or denied so far
allowed-tools: Bash(python3:*)
---
Below is the jev-bouncer report. Show it to the user verbatim in a code block, then add one sentence saying whether the auto-allow verdicts look safe enough to switch `JEV_BOUNCER_MODE=on`.

!`python3 "${CLAUDE_PLUGIN_ROOT}/bouncer.py" report`
