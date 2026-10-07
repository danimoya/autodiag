"""Read-only Linux probe, sent over SSH and executed by sudo python3.

No imports from AutoDiag: only Python's standard library is required remotely.
Only running processes in this host's mount namespace are considered.
"""

# Remote Oracle Linux hosts can still ship Python 3.6.
# ruff: noqa: UP021, UP022

import json
import os
import pwd
import re
import subprocess
from pathlib import Path


def _utility_owner(process_uid, oracle_uid=None):
    """A non-root process must never select a different OS execution identity."""
    owner_uid = process_uid if oracle_uid is None else oracle_uid
    if owner_uid == 0 or process_uid not in (0, owner_uid):
        raise ValueError("unsafe discovered utility owner")
    return pwd.getpwuid(owner_uid).pw_name


def _process_link(path, owner):
    try:
        return os.readlink(path)
    except PermissionError:
        # Container root may lack CAP_SYS_PTRACE. The process owner can usually
        # read these links; do not require a privileged container for discovery.
        try:
            result = subprocess.run(
                ["sudo", "-n", "-u", owner, "--", "readlink", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5,
                check=True,
            )
        except subprocess.CalledProcessError:
            raise PermissionError(
                "cannot inspect process metadata as its owner; "
                "check /proc access and CAP_SYS_PTRACE"
            ) from None
        return result.stdout.strip()


def probe(proc_root=Path("/proc")):
    found, warnings, seen = [], [], set()
    namespace = os.readlink(proc_root / "self/ns/mnt")
    for process in proc_root.iterdir():
        if not process.name.isdigit():
            continue
        candidate = False
        try:
            # cmdline preserves SIDs longer than Linux's 15-character comm field.
            cmd = (process / "cmdline").read_bytes().split(b"\0", 1)[0].decode().strip()
            pmon = re.fullmatch(r"(?:ora|asm)_pmon_([A-Za-z0-9_+$#-]+)", cmd)
            if not pmon and Path(cmd).name not in {"ohasd.bin", "crsd.bin"}:
                continue
            candidate = True
            process_uid = process.stat().st_uid
            process_owner = pwd.getpwuid(process_uid).pw_name
            if _process_link(process / "ns/mnt", process_owner) != namespace:
                continue
            executable = Path(_process_link(process / "exe", process_owner)).resolve(strict=True)
            crs = executable.name in {"ohasd.bin", "crsd.bin"}
            if not pmon and not crs:
                continue
            home = executable.parent.parent
            sid = pmon.group(1) if pmon else None
            component = "crs" if crs else "asm" if cmd.startswith("asm_") else "rdbms"
            identity = (str(home), component, sid)
            if identity in seen:
                continue
            seen.add(identity)
            owner = _utility_owner(
                process_uid, (home / "bin/oracle").stat().st_uid if crs else None
            )

            def run(binary, *args, home=home, sid=sid, owner=owner, input_text=None):
                env = [f"ORACLE_HOME={home}", f"PATH={home}/bin:/usr/bin:/bin"]
                if sid:
                    env.append(f"ORACLE_SID={sid}")
                result = subprocess.run(
                    [
                        "sudo",
                        "-n",
                        "-u",
                        owner,
                        "--",
                        "env",
                        *env,
                        str(home / "bin" / binary),
                        *args,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=20,
                    check=True,
                    input=input_text,
                )
                return result.stdout.strip()

            base_lines = []
            actual_home = None
            if sid:
                try:
                    output = run(
                        "sqlplus",
                        "-L",
                        "-s",
                        "/ as " + ("sysasm" if component == "asm" else "sysdba"),
                        input_text="whenever sqlerror exit failure\n"
                        "whenever oserror exit failure\n"
                        "set heading off feedback off pagesize 0 linesize 32767 trimspool on\n"
                        "select name || '=' || value from v$diag_info "
                        "where name in ('ADR Base', 'ADR Home');\nexit\n",
                    )
                    locations = dict(
                        line.strip().split("=", 1)
                        for line in output.splitlines()
                        if line.strip().startswith(("ADR Base=", "ADR Home="))
                    )
                    base_lines = [locations["ADR Base"]]
                    actual_home = locations["ADR Home"]
                except (OSError, KeyError, subprocess.SubprocessError):
                    warnings.append(
                        f"{component} {sid}: live ADR location unavailable; "
                        "falling back to Oracle base (custom destinations may be missed)"
                    )
            if not base_lines:
                base_lines = run("orabase").splitlines()
            if not base_lines:
                raise ValueError("orabase returned no ADR base")
            base = base_lines[-1]
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", base) or ".." in base.split("/"):
                raise ValueError("invalid Oracle base")
            output = run("adrci", f"exec=set base {base}; show homes")
            homes = [
                line.strip()
                for line in output.splitlines()
                if line.strip().startswith(f"diag/{component}/")
            ]
            if sid:
                homes = [h for h in homes if h.rsplit("/", 1)[-1].casefold() == sid.casefold()]
                if actual_home:
                    homes = [h for h in homes if base.rstrip("/") + "/" + h == actual_home]
            else:
                # Only the local machine's CRS home, not old/copied host homes.
                hostname = os.uname().nodename.split(".")[0].casefold()
                homes = [h for h in homes if h.split("/")[2].split(".")[0].casefold() == hostname]
            if not homes:
                warnings.append(f"{component} {sid or 'CRS'}: no matching ADR home")
                continue
            try:
                version = run("sqlplus", "-V") if (home / "bin/sqlplus").exists() else ""
            except (OSError, subprocess.SubprocessError):
                version = ""
                warnings.append(f"{component} {sid or 'CRS'}: version could not be read")
            versions = re.findall(r"(?:Release|Version)\s+([\d.]+)", version)
            found.append(
                {
                    "component": component,
                    "instance": sid,
                    "owner": owner,
                    "oracle_home": str(home),
                    "adr_base": base,
                    "adr_homes": homes,
                    "version": versions[-1] if versions else None,
                }
            )
        except PermissionError as exc:
            warnings.append(f"process {process.name}: {exc}")
        except (FileNotFoundError, ProcessLookupError) as exc:
            # Normal /proc race: unrelated short-lived processes may already be gone.
            if candidate:
                warnings.append(f"process {process.name}: {type(exc).__name__}")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            warnings.append(f"process {process.name}: {type(exc).__name__}")
    return {"hostname": os.uname().nodename, "instances": found, "warnings": warnings[:50]}


if __name__ == "__main__":
    print(json.dumps(probe()))
