# Testbed: Oracle Database Free with ssh access

The default testbed simulates a database node as AutoDiag sees one: Oracle Database
Free reachable over key-based SSH as the `oracle` user (port 2222) and over SQL*Net
(port 1521), both bound to loopback on the host. Nothing else is needed on the host.
The historical local image tag says `23ai`, but its actual release depends on the base
image; the existing default testbed reports 26ai. Use the pinned environment below for 23ai.

## Start

```bash
cd testbed
cp .env.example .env              # set passwords and the public key path
docker compose build              # adds openssh-server to the Oracle Free image
docker compose up -d              # first start creates the DB: 5-10 minutes
docker compose logs -f oradb      # wait for "DATABASE IS READY TO USE!" and "sshd started"
ssh -F ssh_config autodiag-testbed 'adrci exec="show homes"'
```

The setup hook creates:

- `C##AUTODIAG` — the read-only diagnostic user (common user; see `docs/sql-user.md`).
- `AUTODIAG_TEST` in `FREEPDB1` — `customers` (100k), `orders` (100k), `order_items`
  (300k), `lock_demo`, and package `pkg_orders` with workload, deadlock, busy-loop and
  slow-scan procedures used by the fault kit.

## Fault-injection kit

Each script in `faults/` produces real material in the ADR of the instance and prints a
proof line `AUTODIAG_FAULT name=... problem_key="..." incident_ids=[...] traces=[...]
status=...`. `faults/inject.sh all` runs them in order and writes `faults/out/faults.log`.

| Script | Produces |
|---|---|
| `ora600.sh [arg]` | ORA-600 incident via `oradebug unit_test dbke_test dde_flow_kge_ora` |
| `ora600_repeat.sh` | three incidents under one problem key |
| `ora700.sh` | ORA-700 soft incident |
| `ora7445.sh` | ORA-7445 incident (SIGSEGV sent to a busy foreground process) |
| `ora60.sh` | deadlock: alert-log entry + deadlock trace |
| `errorstack.sh` | errorstack level 3 dump |
| `hang.sh` | hanganalyze level 3 + systemstate 266 dump with a blocker/waiter pair |
| `sqltrace_pair.sh` | 10046 level 12 traces `*_AUTODIAG_NORMAL.trc` and `*_AUTODIAG_ANOMALY.trc` |
| `opt10053.sh` | 10053 optimizer trace |
| `ora1578.sh` | block corruption read (best effort; tablespace dropped afterwards) |
| `ora1555.sh` | snapshot too old (best effort) |

Repeated faults with the same problem key are flood-controlled by Oracle after a few
occurrences per hour; the scripts vary their arguments to avoid that.

### ORADEBUG on Oracle Database Free

The Free edition disables ORADEBUG (`ORA-32519`), which the ORA-600 / ORA-700 scripts
need. The first-start hook therefore sets `_disable_oradebug_commands = none` in the
spfile and restarts the instance once (`AUTODIAG_ENABLE_ORADEBUG=false` in `.env` keeps
it disabled). This is only appropriate on a throwaway test instance; never change it on
a production database.

## Pinned Oracle 23ai validation (separate from the default testbed)

The default testbed can run a newer Oracle release despite its historical `23ai`
image tag. Use the separate AMD64 Compose file for reproducible 23ai testing:

```bash
docker compose -f testbed/compose.23ai.yaml build
docker compose -f testbed/compose.23ai.yaml up -d
# Wait for health and completion of the one-time diagnostic schema setup.
AUTODIAG_EVAL_OPENCODE_MODEL=deepseek/deepseek-flash bash scripts/validate_23ai.sh
```

`compose.23ai.yaml` pins Oracle Free 23.9.0.0 to the AMD64 manifest digest
`sha256:109421eb0e97db4ba5f01086d02c20ace673b809cd8c9a1a6e193bb04424abfb`.
It uses container `autodiag-oradb-23ai`, project `autodiag23ai`, dedicated volumes,
and loopback ports **1522** (SQL) and **2223** (SSH). Never reuse a 26ai data volume.
The build includes `zip`, required for ADRCI IPS generation.

The validation script reads the existing private `testbed/.env`, uses
`targets.23ai.yaml` and `ssh_config.23ai` without changing the operational inventory,
checks the actual `V$VERSION` banner before injecting faults, and creates temporary
case storage, fault proofs and JUnit results. Set `AUTODIAG_VALIDATION_DIR` to keep
results in a chosen directory. Choose an available OpenCode model for your installation.
The live agent evaluation derives its expected frame from the fresh fault proof and
requires a completed MCP result with that incident and a 23.9 version. To rerun only
the live tests against the same evidence, set `AUTODIAG_REUSE_FAULT_LOG=true` together
with the original `AUTODIAG_VALIDATION_DIR`.
Real RAC, Exadata, AHF and 19c still need separate environments.

## Oracle 19c candidate (not yet validated)

Checked 2026-10-05: Oracle documents this official Enterprise Edition image:

```text
container-registry.oracle.com/database/enterprise:19.3.0.0
```

[Oracle's download instructions](https://docs.oracle.com/cd/G30554_01/books/DeployCont/c-Setting-Up-Oracle-Database.html)
require accepting the applicable license agreement and authenticating to the registry.
The manifest check on the validation host returned `unauthorized: Auth failed`;
no image was downloaded or started, and no digest has been verified. This is not
the freely accessible Oracle Database Free image used for the other two targets.
An authorized operator must complete the required access steps locally; do not
send credentials through chat or commit them.

```bash
docker login container-registry.oracle.com
docker manifest inspect container-registry.oracle.com/database/enterprise:19.3.0.0
```

An alternative is Oracle's [official local build recipe](https://github.com/oracle/docker-images/tree/main/OracleDatabase/SingleInstance),
using separately obtained 19c installation binaries. Neither route establishes
permission to use Enterprise Edition or optional management packs by itself.

After authorized access, the validation work is:

1. Resolve and pin the AMD64 image digest. Record the actual database release/RU;
   a run on 19.3 alone must not be described as testing all 19c release updates.
2. Use a separate project, container, data volumes and free loopback ports (proposed
   SQL 1523 / SSH 2224; check availability before binding). Never reuse 23ai/26ai data.
3. Adapt the SSH layer to the image's package manager and actual Oracle home
   (Oracle's 19c build recipe uses `/opt/oracle/product/19c/dbhome_1`). Configure
   SID/PDB/ADR paths explicitly: the setup SQL currently hardcodes `FREEPDB1`.
   Do not blindly apply the Free-edition ORADEBUG-enabling restart hook to 19c.
4. Verify the read-only grants and version banner, then run fault injection only
   in the disposable database. Exercise incident/deadlock/hang/10046 parsing,
   alert logs, SQL catalog, IPS, CLI/API/MCP, GUI reports and live LLM proofs.
5. Preserve results and representative sanitized 19c fixtures; update the roadmap
   and compatibility statement only for the scenarios that actually passed.

Current evidence supports tested single-instance 23ai and 26ai scenarios, **not yet
three-version compatibility**. Real RAC, Exadata and AHF remain separate claims.

## CRS / Oracle Restart / RAC candidates (checked 2026-10-06)

Docker Hub has a community single-node Grid/ASM candidate:
[`lhrbest/oracle19clhr_asm_db_12.2.0.3:2.0`](https://hub.docker.com/r/lhrbest/oracle19clhr_asm_db_12.2.0.3).
Despite the historical repository suffix, its publisher identifies Oracle 19c and
shows `crsctl stat res -t` output with ASM, listeners and two databases on one host.
Hub reports AMD64, approximately 9.02 GB compressed, last updated August 2020,
digest `sha256:a3779200fe0e8d1fd663770f3fa139696fd36f7653a9d42dc1a82c189a14e8f8`.
Its documented run requires privileged mode, systemd and host ASMLib setup.
Treat it as an isolated-lab candidate, not a verified AutoDiag testbed: the actual
GI release, Restart/cluster mode and container startup have not been tested here.
Its predecessor is [`lhrbest/oracle19casm_lhr:1.0`](https://hub.docker.com/r/lhrbest/oracle19casm_lhr).

Docker Hub search did not establish a maintained, reproducible 19c+ multi-node RAC
image. Oracle's [official RAC recipes and image list](https://github.com/oracle/docker-images/blob/main/OracleDatabase/RAC/OracleRealApplicationClusters/README.md)
document these Oracle Container Registry alternatives (not Docker Hub):

| Candidate | Documented image |
|---|---|
| RAC 19c / Oracle Linux 9 | `container-registry.oracle.com/database/rac_ru:latest-19` |
| RAC 21c / Oracle Linux 8 | `container-registry.oracle.com/database/rac_ru:latest` |
| RAC 23.26ai / Oracle Linux 9 | `container-registry.oracle.com/database/rac:latest` |

Pin the resolved digest and verify the installed GI/DB versions before claiming
coverage; these moving tags are discovery references. Oracle also supplies local
build recipes requiring separately obtained GI and database installation media.
The [19c RAC container guide](https://docs.oracle.com/en/database/oracle/oracle-database/19/racdk/oracle-rac-on-docker.html)
describes shared storage, cluster networking and host prerequisites. An ordinary
single-instance database image does not provide these components.

[Oracle Restart](https://docs.oracle.com/en/database/oracle/oracle-database/19/ssdbi/about-oracle-grid-infrastructure-for-a-standalone-server.html)
is the standalone Grid Infrastructure configuration; it is distinct from a
multi-node RAC cluster. Validate both independently. The initial registry research
did not start a container; the subsequent 26ai lab is described below.

### CRS validation still needed

Use an isolated Restart environment and a two-node RAC environment. Validate discovery
as a sudo-capable SSH user; verify Grid/DB owners and homes, CRS XML alert collection,
incident/IPS retrieval and cross-node identity. The 26ai lab below subsequently
validated discovery and ordinary CRS/ASM collection, but not incident/IPS retrieval
or live 19c/Restart compatibility. Discovery visits only the specified Linux
host and its mount namespace, not cluster peers or nested containers.

### Official RAC build attempt: 2026-10-06

Attempted the Oracle-maintained 19c path first:

- `docker pull container-registry.oracle.com/database/rac_ru:latest-19` failed with
  `401 Unauthorized` from the registry token endpoint.
- `docker manifest inspect container-registry.oracle.com/database/rac:latest`
  (26ai) failed with `unauthorized: Auth failed`.
- Cloned Oracle's maintained recipes at commit
  `0d782d440a427aac6a58d0a12c50bc50abfa3f96` into
  `~/.cache/autodiag/oracle-docker-images`.
- Ran `buildContainerImage.sh -v 19.3.0 -t autodiag-rac:19c -o '--build-arg BASE_OL_IMAGE=oraclelinux:8'`.
  Its media preflight reported missing `LINUX.X64_193000_grid_home.zip` and
  `LINUX.X64_193000_db_home.zip`. No RAC image or cluster was created.

After configuring registry authentication, `docker login` succeeded, but retrying
the 19c pull returned `pull access denied` and the 26ai manifest returned
`requested access to the resource is denied`. Authentication alone did not grant
repository access. Review/accept the relevant repository terms in Oracle's web
interface and verify account entitlement; see the [registry FAQ](https://container-registry.oracle.com/faq.html).
No credentials are included in this repository.

There is sufficient disk/RAM for further lab preparation, but repository access
remains blocked and no GI/DB media were found in the checked local software
locations. The host uses cgroup v2; final runtime planning
must follow the chosen image's cgroup/storage/network requirements. The existing
database containers and host storage/kernel configuration were not changed.

Resume through either authenticated Oracle Container Registry access (complete
repository terms/access through Oracle and run `docker login container-registry.oracle.com`
locally), or stage legitimately obtained Grid and DB ZIPs in the upstream
`containerfiles/19.3.0/` directory. Do not put credentials or installation ZIPs in this repo.

For a local 19.3 build, verify the media explicitly before invoking the build:

```bash
set -e
cd ~/.cache/autodiag/oracle-docker-images/OracleDatabase/RAC/OracleRealApplicationClusters/containerfiles/19.3.0
md5sum -c Checksum
cd ..
bash buildContainerImage.sh -v 19.3.0 -i -t autodiag-rac:19c \
  -o '--build-arg BASE_OL_IMAGE=oraclelinux:8'
docker image inspect autodiag-rac:19c
```

The explicit checksum working directory avoids an upstream helper path problem.
The helper also returned exit code zero after missing-media errors during this attempt;
verify the image exists rather than trusting that status alone. `-i` above skips only
the helper's duplicate checksum step, after the preceding verification succeeds.
Base 19.3 media requires OL8; the maintained recipe documents why it cannot be built
unpatched on OL9. Later 19c RU media needs the corresponding build arguments/checksums.

After an image is available: provision isolated storage and public/private container
networks; configure two RAC nodes; verify CRS, ASM and DB state; add passwordless SSH
and noninteractive sudo for discovery; collect sanitized ADR fixtures; run
`targets discover HOST --dry-run --json` on each node before adding the test inventory.
Only then can CRS/ASM/RAC coverage be described as live-validated.

### 26ai RAC lab

Repository access was subsequently enabled for `database/rac`, but not
`database/rac_ru`. The user selected the accessible 26ai image instead of 19c.
The downloaded image is Oracle Linux 9.7 with SQL*Plus **23.26.1.0.0**, pinned at
`container-registry.oracle.com/database/rac@sha256:521f074979e508df4bfcde85d5424aa8d2df009ca23c03bfdf920d250d540a20`.
Downloading the image does **not** validate RAC runtime compatibility.

Live checks on 2026-10-06 discovered `rac1-crs`, `rac2-crs`, `rac1-_ASM1` and
`rac2-_ASM2` over passwordless SSH and sudo. All four passed `diagnose instance
--no-assess --case new`: no collection errors, real ADR problem queries and parsed
XML alerts; CRS dossiers also contain Clusterware status. Cases were kept separately
from the deployed GUI. The probe now falls back to reading process links as the
process owner when container root lacks ptrace permission. For RAC's setgid database
binary, that fallback is insufficient: the lab diagnostic SSH daemon additionally
needs `SYS_PTRACE`. Routine exits of unidentified processes are ignored.

DBCA subsequently reached **100%**. `GV$INSTANCE` returned `ORCLCDB1` and `ORCLCDB2`
as `OPEN`, `ACTIVE`, `PARALLEL=YES`, version `23.26.1.0.0`; `ORCLPDB` was `READ WRITE`
on both. Discovery added `rac1-ORCLCDB1` and `rac2-ORCLCDB2` without replacing the
four existing targets. Both database targets also passed rules-only instance
diagnosis with zero collection errors. The opt-in two-node integration tests passed
for discovery, owner/home identity, ADR problem queries and parsed alerts (CRS XML,
ASM/database text).

A follow-up validation on 2026-10-06 confirmed CRS/CSS/EVM online on both nodes,
ASM `+ASM1`/`+ASM2` running with database clients attached, and both database
instances running. The expanded three-test live suite also passed absent-ID
incident detail/list queries for all six targets and grouped two-node CRS alert
reads. Grouped CRS targets now resolve configured homes against each node's own
ADR inventory; alert paths honor per-node ADR bases. These checks do not create
incidents and therefore do not establish real incident extraction or IPS coverage.

Read-only performance validation used a temporary in-memory SQL configuration:
the all-instance sample produced evidence for IDs 1 and 2, correctly omitting four
new/reset counters; the instance-2-only sample had no errors. The test used the lab
`SYSTEM` account only for validation, without saving its credentials or SQL settings
into the discovered inventory. Normal installations should use the documented
least-privilege diagnostic account. This run did not validate RAC performance LLM
assessments, fault injection, incident extraction, IPS packaging or restart recovery
at that stage. See the follow-up checks below.

#### Extended validation (2026-10-06)

- Changed node 2's database and ASM `DIAGNOSTIC_DEST` in memory to new lab directories.
  Discovery found the live location using `V$DIAG_INFO`; alert collection worked
  through the normal context factory even with a deliberately different target-level
  base. Both original settings were restored in `finally` blocks and verified by
  SQL afterward. Custom-path tests
  also cover local SQL authentication failure and the warning-based fallback.
- Restarted only `autodiag-rac2`; node 1 remained running. After restoring the
  dedicated diagnostic SSH daemon with `configure-ssh.sh`, CRS/CSS/EVM were online
  on both nodes, both ASM instances had their database clients, and the live
  discovery/ADR suite passed again. This does not cover host reboot/loop-device
  reattachment, storage failure, network partition or forced node eviction.
- Created **file-based**, not incident-based, IPS packages for CRS and ASM on both
  nodes, adding each real alert log. AutoDiag generated and fetched all four ZIPs;
  local CRC checks passed and the expected alert files were present. This exposed
  and fixed sudo working-directory handling and zero-exit ADRCI error detection.
  The published image lacks `zip`; the adapter now installs it. The running lab
  received host-signature-verified Rocky EL9 `zip-3.0-35` RPMs because its isolated
  DNS cannot resolve the external Oracle package mirror. No host packages changed.
- Both DB and ASM rejected the session-local ORADEBUG soft-error hook with
  `ORA-32519` (disabled for the instance). No hidden parameter/security setting was
  relaxed and no process was crashed. **Real incident extraction and the
  incident-driven MCP IPS job remain unvalidated**; empty incident queries and
  file-based packaging are not substitutes for those checks.
- Built a wheel and installed it into a fresh Python virtual environment outside
  the checkout. Discovery/performance CLI help, the packaged discovery probe,
  performance SQL catalog and all seven knowledge-base YAML files passed checks.
  This validates the local working-tree wheel, not a published release or commit.
- Final regression: **266 passed**, 16 opt-in tests deselected, one upstream
  Starlette deprecation warning; **3 live RAC tests passed**. Lint and diff checks
  passed. Fresh rules-only diagnoses of all six targets had zero collection errors.
  Both database instances were OPEN/ACTIVE/PARALLEL, both ORCLPDBs READ WRITE and
  node 2's ASM DATA disk group MOUNTED after recovery.
- Local LLM attempts used `qwen2.5:7b-instruct` for RAC performance and ASM through
  native Ollama and CRS through its OpenAI-compatible endpoint (180-second limits).
  Smaller, bounded CRS prompts with the already-loaded `gemma3:latest` were also
  tried through both protocols (90-second limits). All five requests timed out;
  AutoDiag returned explicit rules-only assessments with the timeout reason.
  **Timeout fallback passed; successful live LLM assessment remains unvalidated.**
  No models were unloaded and the shared Ollama service was not restarted.

Evidence remains in the separate lab case store: final six-target collection
cases `case_4c683d11d2`, `case_068bf0260a`, `case_68d82a1ee5`, `case_140eb782d6`,
`case_9c8e7f62dc`, `case_e0798bf679`; LLM attempts `case_f945ca4fa8`,
`case_ecb92be946`, `case_75d6358d16`, `case_efaac3fe6d`, `case_454447c381`.
The four fetched archives are under the lab data directory's `ips-validation/`.
The extra custom ADR directories are retained as validation evidence; they are no
longer the active diagnostic destinations. Findings can include historical startup
or restart warnings even when the final cluster health checks pass.

#### Review follow-up (2026-10-07)

The independent DeepSeek review was checked against source and live systems. Fixes
cover full execution-context transport caching, new/reset/restarted counter
accounting, ADRCI stdout payload versus stderr failures, grep no-match handling,
quoted XML arguments/entities, the empty Dismissed section, UTF-8/null inventories,
and stale compatibility/security documentation. Inventory saves deliberately
normalize YAML; backups retain original comments. Review claims are not treated as
proof: for example, `load_targets` also rejected null inventories before this fix.

Additional discovery hardening rejects utilities executed as root and rejects a
non-root CRS process selecting a different installation owner. Invalid JSON/login
banners fail with a clear error. These checks supplement, not replace, the trusted
operator and trusted-host requirements documented in [safety](safety.md).

Validation against the current working tree:

| Test target | Live pytest checks passed |
|---|---:|
| Oracle Free 23ai 23.9 | 17 |
| Oracle Free 26ai 23.26.3 | 17 |
| RAC 26ai ORCLCDB1 endpoint | 6 |
| RAC 26ai ORCLCDB2 endpoint | 6 |
| Two-node CRS/ASM/DB discovery and grouped CRS | 3 |

The Free suites include real existing incident/trace and SQL diagnosis tests.
All four database endpoints exercised the performance catalog with actual binds,
top-N bounds, all-instance and per-instance selection, plus CLI/MCP performance
entry points with model assessment disabled. All six RAC component targets also
passed fresh rules-only instance diagnosis without collection errors. CRS text
alert paths were confirmed by real matching and no-match grep calls, resolving the
review's missing-path hypothesis. No fault injection or service restart was needed.

The default suite passed **299 tests**, with 22 opt-in tests deselected and one
upstream Starlette deprecation warning. Lint, shell syntax and diff checks passed.
`scripts/check_dist.py` built from publishable source in a temporary clean tree,
installed the wheel, and verified KB/templates/prompts, performance SQL, and the
packaged discovery probe's Python 3.6 syntax. Remaining version, real RAC incident,
and successful live LLM limitations from the earlier validation still apply.

Lab files are in `testbed/rac/`. They use rootful Podman, matching Oracle's current
recipe, separately from the existing Docker Free databases. The local node image
corrects shell quoting in the published `initsh`: values such as `CRS_NODES`
contain semicolons and must be quoted when writing `/etc/rac_env_vars`. It also
adds `-A` to the helper's OpenSSL Base64 decoder so single-line secrets do not
silently decode to an empty value. The creation script now emits newline-terminated
Base64. This bug was found by a SQL login check; the live lab's SYS/SYSTEM/PDBADMIN
and grid/oracle accounts were reset to the generated private secret after fixing
the helper. No Oracle database binaries were modified.

Review `create-lab.sh` before running it. It reserves three non-overlapping subnets
(`10.203.0.0/24`, `10.203.1.0/24`, `10.203.2.0/24`), creates DNS and two RAC containers,
allocates a **new 60 GiB file-backed loop device** for shared ASM, and generates a
private Podman password secret. Each RAC node is capped at 4 CPUs and 16 GiB RAM,
with no swap allowance. There are no published host ports, host PID/network
namespaces, existing host disks, or global sysctl changes. Loop-backed ASM is a
disposable development choice, not a production storage recommendation.

Build/run sequence (after installing Podman and authenticating to Oracle locally):

```bash
sudo podman pull --authfile "$HOME/.docker/config.json" \
  container-registry.oracle.com/database/rac@sha256:521f074979e508df4bfcde85d5424aa8d2df009ca23c03bfdf920d250d540a20
cd testbed/rac
sudo podman build -t localhost/autodiag-rac-dns:lab -f Containerfile.dns .
sudo podman build -t localhost/autodiag-rac:26ai-lab -f Containerfile.node .
sudo bash create-lab.sh "$HOME/.local/share/autodiag/rac26ai"
sudo podman ps -a --filter label=autodiag.lab=rac26ai
```

The creation script deliberately refuses to overwrite existing lab storage,
containers, networks or password secrets. Interrupted setup needs inspection,
not blind rerunning. A reboot also requires reattaching the file-backed loop device;
automatic host startup is intentionally not configured. Database readiness, SSH
discovery and ADRCI must be verified separately before adding a live inventory.

For SSH validation, generate a dedicated key at
`~/.config/autodiag/rac26ai/id_ed25519` and run
`sudo bash testbed/rac/configure-ssh.sh "$HOME/.config/autodiag/rac26ai/id_ed25519.pub"`.
This creates the **lab-only** public-key login `autodiag` with passwordless sudo.
It starts a dedicated diagnostic SSH daemon on **container port 2222**, restricted
to that login. A privileged exec grants capabilities to `setpriv`, which drops all
but the daemon's required root capabilities (including PAM audit control) and
`SYS_PTRACE` before starting sshd. The containers themselves remain non-privileged,
without host PID/network access. This extra daemon must be started again after a
container restart by rerunning `configure-ssh.sh`.
Read each container's `/etc/ssh/ssh_host_ed25519_key.pub` directly using `sudo podman
exec`; register the verified public keys for `[10.203.0.11]:2222` and `[10.203.0.12]:2222` in
`~/.config/autodiag/rac26ai/known_hosts`. The supplied SSH config requires strict
host-key checking; do not disable it to work around a missing key.

From the repository root, keep discovery and case storage separate from deployed
inventories:

```bash
export AUTODIAG_SSH_CONFIG="$PWD/testbed/rac/ssh_config"
export AUTODIAG_TARGETS_FILE="$HOME/.config/autodiag/targets.rac26ai.yaml"
export AUTODIAG_DATA_DIR="$HOME/.local/share/autodiag/rac26ai-diagnostics"
autodiag targets discover autodiag-rac1 --dry-run --json
autodiag targets discover autodiag-rac2 --dry-run --json
autodiag targets discover autodiag-rac1
autodiag targets discover autodiag-rac2
autodiag diagnose instance -t rac1-crs --no-assess --case new --dossier
autodiag diagnose instance -t rac2-_ASM2 --no-assess --case new --dossier
AUTODIAG_RAC_SSH_CONFIG="$AUTODIAG_SSH_CONFIG" \
  pytest -m integration tests/integration/test_rac_discovery_live.py -q
```

The integration checks require a running DB, ASM and CRS on **each** node and read
their ADR homes, problems and alert logs. Discovery adds local-instance targets;
it does not merge RAC topology or configure SQL credentials. Configure a read-only
CDB-root SQL account separately before [performance diagnosis](cli.md#autodiag-diagnose).

## Reset the default testbed

```bash
docker compose down -v            # drops the database and ADR
```
