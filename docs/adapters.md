# Other agents: Cursor and Gemini CLI

jev-bouncer's judges, tripwires, settings, cache and log are agent-agnostic. Only the hook wire
format is Claude Code's. `bouncer.py cursor <event>` and `bouncer.py gemini <event>` are thin
translation layers: they read the foreign stdin JSON, build the same internal payload that `pre`
and `post` already consume, call the same `judge_command` / `judge_edit` / `judge_mcp` /
`scan_text`, and render the same verdict in that agent's dialect. There is no second copy of any
rule. Log rows get an `agent` field (`cursor`, `gemini`); Claude Code rows are unchanged and are
read as `claude` by default.

**Verification level: the protocols below are taken from the vendors' own documentation, quoted
field name by field name. Neither adapter has been run inside Cursor or Gemini CLI by the author.**
The offline test suite drives each adapter with a fixture built from the documented schema and
asserts the documented output shape; it cannot prove the real client agrees. Treat the first run in
your own editor as the real test, and start in `mode: dry`.

## Sources

| Agent | Primary docs |
| --- | --- |
| Cursor | <https://cursor.com/docs/hooks> |
| Gemini CLI | <https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md>, <https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/writing-hooks.md>, <https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md> |
| Gemini CLI tool argument names | <https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/shell.md>, <https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/file-system.md>, <https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md> |

Retrieved 2026-09-20. Neither vendor versions its hook protocol in the document, so re-check these
pages before trusting the field names below.

## The two protocols, side by side

| | Claude Code (native) | Cursor | Gemini CLI |
| --- | --- | --- | --- |
| Before a shell command | `PreToolUse`, `tool_name: "Bash"` | `beforeShellExecution` | `BeforeTool`, `tool_name: "run_shell_command"` |
| Command text | `tool_input.command` | `command` | `tool_input.command` |
| Working directory | `cwd` | `cwd` | `cwd` |
| Before a file edit | `PreToolUse`, `tool_name: "Write"`/`"Edit"`/`"MultiEdit"` | `preToolUse` (generic; edit tool names **not documented**) | `BeforeTool`, `tool_name: "write_file"` / `"replace"` |
| Edit path / content | `tool_input.file_path`, `.content` / `.old_string` / `.new_string` | `tool_input` (shape not documented for edit tools) | `tool_input.file_path`, `.content` / `.old_string` / `.new_string` |
| Before an MCP call | `PreToolUse`, `tool_name: "mcp__<server>__<tool>"` | `beforeMCPExecution` | `BeforeTool`, `tool_name: "mcp_<server>_<tool>"` |
| MCP arguments | `tool_input` (object) | `tool_input` (**JSON string**) + `mcp_server_name` | `tool_input` (object) |
| After a tool returns | `PostToolUse`, `tool_response` | `postToolUse`, `tool_output` (JSON string) | `AfterTool`, `tool_response` (`llmContent`, `returnDisplay`, `error`) |
| Session id | `session_id` | `conversation_id` | `session_id` |
| Allow | `{"hookSpecificOutput":{"permissionDecision":"allow"}}` | `{"permission":"allow"}` | `{"decision":"allow"}` |
| Deny | `…"permissionDecision":"deny"` | `{"permission":"deny","user_message":…,"agent_message":…}` | `{"decision":"deny","reason":…}` |
| Ask the human | `…"permissionDecision":"ask"` | `{"permission":"ask"}` | **no equivalent** |
| Say nothing | print nothing | **not available on permission hooks** — empty or off-schema stdout *blocks* the action | print nothing |
| Add context after a tool | `hookSpecificOutput.additionalContext` | `additional_context` | `hookSpecificOutput.additionalContext` |
| Replace/suppress a tool result | `{"decision":"block","reason":…}` | not available | `{"decision":"deny","reason":…}` (replaces what the model sees) |
| Exit code 2 | n/a | block (same as `permission: "deny"`) | block; `stderr` is the reason |
| Other non-zero exit | n/a | fail open unless `failClosed: true` | warning, interaction proceeds |
| Config file | `hooks/hooks.json` (plugin) | `~/.cursor/hooks.json` or `<project>/.cursor/hooks.json` | `~/.gemini/settings.json` or `<project>/.gemini/settings.json` |
| Config shape | `hooks.<Event>[].hooks[]` | `{"version": 1, "hooks": {"<event>": [{"command", "matcher", "timeout", "failClosed"}]}}` | `{"hooks": {"<Event>": [{"matcher", "hooks": [{"type": "command", "command", "timeout"}]}]}}` |
| Timeout unit | seconds | not stated in the docs (examples use `30`; assumed seconds) | milliseconds, default `60000` |

### Cursor specifics

- Base input on every hook: `conversation_id`, `generation_id`, `model`, `model_id`,
  `model_params`, `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`,
  `transcript_path`. The adapter uses `conversation_id` as the session id and falls back to
  `workspace_roots[0]` when an event carries no `cwd`.
- `beforeShellExecution` input is `{"command", "cwd", "sandbox"}`; output is
  `{"permission": "allow" | "deny" | "ask", "user_message", "agent_message"}`.
- `beforeMCPExecution` input is `{"tool_name", "tool_input", "mcp_server_name"}` plus either
  `{"url", "mcp_server_url"}` (HTTP/SSE) or `{"command"}` (stdio). Note `tool_input` here is a
  **JSON params string**, not an object; the adapter parses it.
- `postToolUse` input is `{"tool_name", "tool_input", "tool_output", "tool_use_id", "cwd",
  "duration", …}`; `tool_output` is a JSON-stringified payload. Output is
  `{"updated_mcp_tool_output", "additional_context"}` — there is no way to block from here, so
  `inject_action: block` degrades to `warn` on Cursor.
- `preToolUse` input is `{"tool_name", "tool_input", "tool_use_id", "cwd", "agent_message"}`;
  output is `{"permission": "allow" | "deny", "user_message", "agent_message", "updated_input"}`.
  The docs give the `tool_input` shape only for `"tool_name": "Shell"`
  (`{"command", "working_directory"}`) and say `"Shell, Read, Write, MCP, Task, etc."` without
  enumerating the file-edit tools or their arguments. **Not confirmed, not invented:** the adapter
  does not match on Cursor tool names at all. It judges a `preToolUse` payload as an edit when
  `tool_input.file_path` is present and `tool_input.command` is not, reading
  `content` / `old_string` + `new_string` / `edits[]` — the same shapes `edit_parts` already
  handles. If your Cursor build names those arguments differently, the edit guard silently does
  nothing; check `bouncer.py report` for `edits: judged` rows after the first session.
- `afterFileEdit` fires *after* the edit and has no output fields, so it cannot gate an edit. It is
  not wired.
- **There is no "no opinion" answer on a Cursor permission hook.** The docs are explicit: for
  `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `beforeTabFileRead`,
  `subagentStart` and `preToolUse`, "invalid JSON or a response that doesn't match the hook's
  schema blocks the action". The adapter therefore always prints a schema-valid object and uses
  `"ask"` as the neutral. Consequences:
  - On `beforeShellExecution` / `beforeMCPExecution`, anything jev-bouncer does not auto-allow or
    deny becomes a permission prompt. In `mode: dry` that means Cursor asks you about every judged
    command instead of staying silent: dry on Cursor reads as "log everything, decide nothing,
    never auto-run". It never *widens* what Cursor would have allowed.
  - On `preToolUse`, `"ask"` is documented as "accepted by the schema but not enforced for
    `preToolUse` today", so the neutral is a genuine no-op there.
- Cursor watches its config files and reloads them automatically.
- Cloud agents load command hooks only from `<repo>/.cursor/hooks.json`, and do not run
  `beforeMCPExecution` / `afterMCPExecution`.

### Gemini CLI specifics

- Base input on every hook: `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`.
- `BeforeTool` input adds `tool_name`, `tool_input`, `mcp_context`, `original_request_name`.
  `AfterTool` adds `tool_response`, an object with `llmContent`, `returnDisplay` and an optional
  `error` (the plugin's existing `flatten` handles it unchanged).
- Output: `decision` is `"allow"` or `"deny"` (alias `"block"`), with `reason` required on a deny —
  that text is sent to the agent as a tool error. `hookSpecificOutput.additionalContext` is
  appended to the tool result. `systemMessage` is shown to the user. There is **no `ask`**, so a
  jev-bouncer `defer` prints nothing and Gemini's own approval rules apply — and `fail: ask` has no
  Gemini equivalent, so an API failure in `mode: on` fails open there.
- Built-in tool argument names, from the tools docs: `run_shell_command` takes `command`,
  `description`, `directory`; `write_file` takes `file_path`, `content`; `replace` takes
  `file_path`, `old_string`, `new_string`. These line up with Claude Code's `Bash`, `Write` and
  `Edit` one for one, which is why the adapter is a rename.
- MCP tools are named `mcp_<serverName>_<toolName>`. Gemini's own docs warn that the parser splits
  on the first underscore after the `mcp_` prefix and that a server name containing an underscore
  breaks it; the adapter splits the same way and inherits the same limitation.
- Hooks must print nothing to stdout but the final JSON. If stdout is not JSON, "the CLI will
  default to 'Allow' and treat the entire output as a `systemMessage`" — so a crash in the adapter
  fails open, matching the plugin's own default.
- `timeout` is in **milliseconds** here (default `60000`), unlike Claude Code's seconds.

## What is not confirmed

- Cursor's file-edit tool names and their `tool_input` argument names (see above). The adapter
  matches on payload shape instead of inventing names.
- Whether an empty stdout on a Cursor permission hook is treated as "no decision" or as invalid
  output. The docs only say off-schema output blocks, so the adapter never relies on silence there.
- The unit of Cursor's `timeout` field. The examples use `30`, which is only sensible as seconds.
- Whether Gemini's `{"decision": "allow"}` on `BeforeTool` skips Gemini's own confirmation prompt
  or merely declines to block. The docs say `"allow"` means the hook consents and that "specific
  impact depends on the event", without stating it for `BeforeTool`. If it does not skip the
  prompt, `mode: on` simply behaves like `mode: guard` on Gemini.
- Neither vendor states a minimum client version for these fields.

## Install

Nothing here writes into `~/.cursor` or `~/.gemini`. Run this yourself, from the repo root, after
reading it:

```sh
#!/usr/bin/env sh
# install.sh -- wire jev-bouncer into Cursor and/or Gemini CLI (user-level config).
set -eu
BOUNCER="$(cd "$(dirname "$0")" && pwd)/bouncer.py"
test -f "$BOUNCER" || { echo "bouncer.py not found next to this script" >&2; exit 1; }
python3 "$BOUNCER" version >/dev/null

# --- Cursor: ~/.cursor/hooks.json
mkdir -p "$HOME/.cursor"
if [ -e "$HOME/.cursor/hooks.json" ]; then
  echo "~/.cursor/hooks.json already exists -- merge adapters/cursor/hooks.json into it by hand." >&2
else
  sed "s#python3 /ABSOLUTE/PATH/TO/jev-bouncer/bouncer.py#python3 $BOUNCER#g" \
    adapters/cursor/hooks.json > "$HOME/.cursor/hooks.json"
  echo "wrote ~/.cursor/hooks.json"
fi

# --- Gemini CLI: ~/.gemini/settings.json
mkdir -p "$HOME/.gemini"
if [ -e "$HOME/.gemini/settings.json" ]; then
  echo "~/.gemini/settings.json already exists -- merge the \"hooks\" key from" \
       "adapters/gemini/settings.json into it by hand." >&2
else
  sed "s#python3 /ABSOLUTE/PATH/TO/jev-bouncer/bouncer.py#python3 $BOUNCER#g" \
    adapters/gemini/settings.json > "$HOME/.gemini/settings.json"
  echo "wrote ~/.gemini/settings.json"
fi

echo "Start in mode: dry. Set it in ~/.jev-bouncer/config.json, then read 'bouncer.py report'."
```

Both clients already have config files for most people, so expect the merge branch. The only thing
that matters is that the `command` strings hold an absolute path to `bouncer.py` and end in
`cursor <event>` or `gemini <event>`.

## Checking it works

```sh
echo '{"command":"git status","cwd":"'"$PWD"'","hook_event_name":"beforeShellExecution"}' \
  | python3 bouncer.py cursor beforeShellExecution
# -> {"permission": "allow", ...}   (from the built-in allowlist, no API call)

echo '{"tool_name":"run_shell_command","tool_input":{"command":"git status"},"cwd":"'"$PWD"'","session_id":"x"}' \
  | python3 bouncer.py gemini BeforeTool
# -> {"decision": "allow", ...}
```

Then `python3 bouncer.py report` — rows judged through an adapter carry `"agent": "cursor"` or
`"agent": "gemini"`.
