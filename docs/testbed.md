# Testbed: Oracle Database Free with ssh access

The testbed simulates a database node as AutoDiag sees one: an Oracle Database (23ai
Free) reachable over key-based SSH as the `oracle` user (port 2222) and over SQL*Net
(port 1521), both bound to loopback on the host. Nothing else is needed on the host.

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

## Reset

```bash
docker compose down -v            # drops the database and ADR
```
