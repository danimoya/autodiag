# Bootstrap and operate the GUI

The GUI, REST API and MCP share one AutoDiag process. No frontend build is needed.
See the [page reference](gui.md) and [screenshot gallery](screenshots/README.md).
Screenshots were captured against real disposable 23ai and 26ai databases, not mock pages.

## 1. Start locally first

From a clone of this repository, using Python 3.11:

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e .
mkdir -p ~/.config/autodiag
chmod 700 ~/.config/autodiag
```

Create `~/.config/autodiag/targets.yaml` and `config.toml` using the inventory shape
in [the testbed](../testbed/targets.23ai.yaml). Keep real inventory and secrets out of Git.
Put passwords in `~/.config/autodiag/autodiag.env` as `NAME=value`, referenced by
`sqlnet.password_env`; restrict that file to mode 600. Never put the password itself
in YAML, screenshots, commands committed to Git, or reports.

Minimal `config.toml` (substitute your own paths):

```toml
listen_host = "127.0.0.1"
listen_port = 8790
targets_file = "~/.config/autodiag/targets.yaml"
ssh_config = "~/.ssh/config"
data_dir = "~/.local/share/autodiag"
scan_enabled = false
# Optional: point at an available Ollama endpoint and an installed model.
# ollama_primary_url = "http://127.0.0.1:11434"
# ollama_advisor_model = "your-installed-model"
```

```bash
.venv/bin/autodiag targets list
.venv/bin/autodiag adr problems -t <target-name>
.venv/bin/autodiag mcp selftest
.venv/bin/autodiag serve
```

Open `http://127.0.0.1:8790/targets`. `/healthz` confirms the process and inventory,
**not** SSH, SQL connectivity or model availability. Check those separately.
Without a reachable model, diagnosis can use a clearly labelled rules fallback;
a successful HTTP response alone does not prove a live LLM assessment ran.

## 2. Use 23ai and 26ai side by side

Follow [testbed setup](testbed.md) for the default container and the separately
pinned `testbed/compose.23ai.yaml`. Wait for database health **and** completion of
the diagnostic-user setup. Do not reuse a newer database's volume for 23ai.

| GUI target name | Container | Host SQL / SSH ports | Oracle home | Verified release |
|---|---|---|---|---|
| `oracle-23ai` | `autodiag-oradb-23ai` | 1522 / 2223 | `/opt/oracle/product/23ai/dbhomeFree` | 23.9.0.25.07 |
| `oracle-26ai` | `autodiag-oradb` | 1521 / 2222 | `/opt/oracle/product/26ai/dbhomeFree` | 23.26.3.0.0 |

These are the releases observed during the 2026-10-05 GUI validation. The default
container is not a reproducible 26ai pin; inspect `V$VERSION`/the `db_info` catalog
query each time. Image tags and inventory labels are not proof of database version.

Use a GUI-only `targets.gui.yaml` with **unique names and SSH aliases**, the two
correct port pairs, and each container's actual Oracle home. Both use ADR base
`/opt/oracle`, ADR home `diag/rdbms/free/FREE`, and SQL service `FREE` for CDB-level
diagnostics. Configure `FREEPDB1` only when deliberately querying that PDB.
Use the diagnostic user and grants in [sql-user.md](sql-user.md), not SYS for the GUI.
Do not enable Diagnostics Pack queries on production targets without entitlement.

An SSH config can include both repository testbed configs by absolute path:

```sshconfig
Include /absolute/path/to/autodiag/testbed/ssh_config
Include /absolute/path/to/autodiag/testbed/ssh_config.23ai
```

Verify each alias independently with `ssh -F <gui-ssh-config> <alias>` and the
allowlisted ADR commands. Keep known-hosts entries separate; after a legitimate
container recreation verify the new host key before replacing a stale entry.

To run alongside an existing CLI/MCP service, choose a different port and data store:

```bash
AUTODIAG_TARGETS_FILE="$HOME/.config/autodiag/targets.gui.yaml" \
AUTODIAG_SSH_CONFIG="$HOME/.config/autodiag/ssh_config.gui" \
AUTODIAG_DATA_DIR="$HOME/.local/share/autodiag/gui" \
AUTODIAG_LISTEN_PORT=8791 \
AUTODIAG_SCAN_ENABLED=false \
  .venv/bin/autodiag serve
```

Settings precedence: explicit settings, `AUTODIAG_*` environment variables, working
directory `.env`, the TOML selected by `AUTODIAG_CONFIG`, then defaults. The private
`autodiag.env` is loaded first; existing environment variables win. Check overrides
when an inventory, model or port appears to be ignored.

## 3. Keep it running with systemd

Copy [the supplied user unit](../systemd/autodiag.service) to
`~/.config/systemd/user/autodiag-gui.service`. Adjust `WorkingDirectory` and `ExecStart`
for the clone location. Under `[Service]`, add the GUI inventory, SSH, data and port
environment overrides above using **absolute paths** (`%h` is supported in user units;
shell `$HOME` expansion is not). Recommended additions:

```ini
Environment=AUTODIAG_SCAN_ENABLED=false
Environment=AUTODIAG_NOTIFY_COMMAND=
UMask=0077
NoNewPrivileges=true
```

```bash
systemd-analyze --user verify ~/.config/systemd/user/autodiag-gui.service
systemctl --user daemon-reload
systemctl --user enable --now autodiag-gui.service
systemctl --user status autodiag-gui.service
journalctl --user -u autodiag-gui.service -n 100
```

For operation after logout, an administrator can enable lingering for the service
user. User-service `After=docker.service` does not wait for the system Docker daemon
or database health. Ensure the bridge exists before binding its address and the
databases are ready before collecting evidence. Keep restart-on-failure enabled.

## 4. Publish safely through Nginx Proxy Manager

The HTML UI has **no built-in login or per-user authorization**. The optional
`AUTODIAG_MCP_TOKEN` protects `/api/*` and `/mcp`, not HTML pages, reports or artifacts.
Every user granted GUI access should be trusted with the configured diagnostic data
and case actions. Prefer a VPN/identity-aware gateway for broader access.

1. Point your hostname at the NPM host. Check that no existing proxy host owns it.
2. Make the upstream reachable **from the NPM container**. Its `127.0.0.1` is not
   the host. Use a verified host bridge gateway/private address and restrict direct
   access with the host firewall; never casually bind the app to public `0.0.0.0`.
3. Create a dedicated access list with a strong unique password. For a password-only
   list with no allowed IP clients, enable **Satisfy Any**: NPM emits a final `deny all`
   for IP rules, so **Satisfy All** rejects even valid passwords. Adding allowed IPs
   with Satisfy Any would bypass the password for those IPs; do not do that accidentally.
4. Obtain a certificate, attach the access list to the entire vhost, force HTTPS and
   enable WebSocket support. Leave caching off for sensitive diagnostics.
5. Allow synchronous diagnosis requests enough time. Example advanced configuration:

```nginx
proxy_read_timeout 600s;
proxy_send_timeout 600s;
proxy_connect_timeout 15s;
proxy_buffering off;
client_max_body_size 64m;
```

Use a timeout suitable for your collector and model budgets; 600 seconds is an
example, not a universal guarantee. A proxy timeout does not cancel backend work:
check the case list before retrying and creating duplicate diagnoses.

NPM Basic authentication and the application's Bearer token both use the
`Authorization` header. Do not assume a browser Basic login satisfies the Bearer
check. For a fully gated private GUI upstream, NPM can strip Basic credentials
(`pass_auth=false`) and enforce all access at the proxy. If agent clients require
Bearer auth too, design a separate restricted route or explicit trusted header
injection; never expose an unprotected bypass.

Validate trusted HTTPS, HTTP-to-HTTPS redirect, unauthenticated/wrong-password
rejection and successful authenticated requests to `/targets`, `/api/v1/tools`,
and the intended MCP client flow. Test `nginx -t`; keep a backup of the pre-change
NPM host configuration and leave unrelated vhosts untouched.

## 5. Acceptance checks and operating pitfalls

- Confirm SQL `db_info` reports the expected version for **each** target; then open
  ADR problems, incidents and alert logs. An empty seven-day window may simply mean
  older faults: expand the window before assuming collection failed.
- On disposable testbeds only, use the [fault kit](testbed.md) for real error evidence.
  Never run it on production. Oracle flood control can suppress repeated incidents.
- Click **triage**, inspect a trace and raw lines, render a DBA report and an SR draft,
  then click **diagnose**. Verify the report's model/fallback label and proof counts.
  Review findings before sharing: quote verification is not proof of a correct root cause.
- Compare two incident traces for stack differences and a normal/anomalous 10046 pair
  for SQL-profile differences. Wrong artifact types or missing IDs are not valid demos.
- Keep captures limited to synthetic testbed data. Stored traces and downloaded reports
  are not automatically sanitized by LLM-boundary redaction. Inspect images for SQL,
  bind values, machine names, internal paths and personal data before publishing.
- Back up the SQLite database consistently (SQLite backup API or stop the service)
  together with the case artifact directory. Do not copy only a live WAL-mode `.db`.
  Review retention settings: closed cases can be purged.
- Rotate exposed credentials, keep secret files mode 600, and do not commit browser
  authentication state. Authentication is not a substitute for network isolation,
  CSRF-aware gateway controls or per-user auditing in a larger deployment.

The captured GUI validation covers single-instance 23ai/26ai testbeds. It does not
establish real RAC, Exadata, AHF or 19c support; see [the roadmap](roadmap.md).
