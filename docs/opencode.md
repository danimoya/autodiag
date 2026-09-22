# Using AutoDiag from OpenCode

1. Install the AutoDiag venv on the machine where OpenCode runs (`pip install -e .`).
2. `opencode/install.sh --merge` copies the skill, the `autodiag-triage` agent and the
   commands into `~/.config/opencode/` and registers the local MCP server
   (`autodiag mcp stdio`) in `opencode.json`. For the shared service use the remote form
   from `opencode/opencode.json.example` (`http://127.0.0.1:8790/mcp` plus bearer token).
3. Choose the model in `opencode.json` (`"model": "ollama/<model>"` with the provider block
   from the example, or any provider you have). With Ollama, raise `num_ctx` to 32768 on
   the server: the tool schemas alone exceed the 4096 default and tool calls silently break.
4. Run `autodiag mcp selftest`, then in OpenCode: `/triage <target> "<problem key>"`.

Commands: `/triage`, `/compare-stacks <left artifact> <right artifact>`,
`/compare-sqltrace <normal artifact> <anomaly artifact>`, `/sr-report <case id>`.

The agent has no shell: it can only call `autodiag_*` tools and read files. Findings it
records must cite `evidence_id` values returned by tools, and the store rejects findings
without evidence. Headless use: `opencode run --agent autodiag-triage --format json "..."`.
