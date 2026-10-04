"""Build and exercise an installed wheel from publishable source files, outside the tree.

Run with the development virtualenv: python scripts/check_dist.py.
Includes non-ignored new files so it also works before a change is committed.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    files = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    with tempfile.TemporaryDirectory(prefix="autodiag-dist-") as folder:
        work = Path(folder)
        source = work / "source"
        source.mkdir()
        for name in set(files) - {""}:
            src = ROOT / name
            if not src.is_file():
                continue
            dest = source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        env = {k: v for k, v in os.environ.items() if not k.startswith("AUTODIAG_")}
        env.update(AUTODIAG_CONFIG=str(work / "none.toml"), AUTODIAG_SECRETS=str(work / "none.env"))
        subprocess.run(
            [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(work / "dist")],
            cwd=source,
            env=env,
            check=True,
        )
        installed = work / "installed"
        python = sys.executable
        wheel = next((work / "dist").glob("*.whl"))
        subprocess.run(
            [python, "-m", "pip", "install", "--no-deps", "--target", str(installed), str(wheel)],
            cwd=work,
            env=env,
            check=True,
        )
        subprocess.run(
            [
                python,
                "-I",
                "-c",
                "\n".join(
                    [
                        f"import sys; sys.path.insert(0, {str(installed)!r})",
                        "from pathlib import Path",
                        "import autodiag",
                        f"assert Path(autodiag.__file__).is_relative_to({str(installed)!r})",
                        "from autodiag.kb.loader import load_yaml",
                        "for name in ('components', 'ora600', 'ora7445', 'alertlog_signatures', "
                        "'wait_events', 'exadata', 'severity_rules'):",
                        "    assert load_yaml(name + '.yaml')",
                        "from autodiag.llm.assess import SYSTEM_PROMPT",
                        "assert SYSTEM_PROMPT",
                        "from autodiag.web.app import _env",
                        "assert _env().get_template('targets.html')",
                        "print('Installed wheel: knowledge base, model prompt and templates OK')",
                    ]
                ),
            ],
            cwd=work,
            env=env,
            check=True,
        )
        subprocess.run(
            [
                python,
                "-I",
                "-c",
                f"import sys; sys.path.insert(0, {str(installed)!r}); "
                "from autodiag.cli.main import app; app()",
                "--help",
            ],
            cwd=work,
            env=env,
            check=True,
        )


if __name__ == "__main__":
    main()
