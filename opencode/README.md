# OpenCode integration

`install.sh` copies the skill (`skills/autodiag-oracle`), the restricted agent
(`agents/autodiag-triage.md`) and the commands (`/triage`, `/compare-stacks`,
`/compare-sqltrace`, `/sr-report`) into `~/.config/opencode/`. OpenCode also reads
`~/.claude/skills`, so the same skill works from Claude Code.

Register the MCP server in `~/.config/opencode/opencode.json` (see
`opencode.json.example`): either a local stdio server (`autodiag mcp stdio`) or the
shared HTTP service (`autodiag mcp http`, `http://127.0.0.1:8790/mcp` with a bearer
token). Tools appear as `autodiag_<tool>`.

The model is chosen by each environment's own `opencode.json` (`model` key); the agent
file deliberately carries no model. With Ollama, set `num_ctx` to 32768 or more on the
server side, otherwise tool calls break once the tool schemas are loaded.
