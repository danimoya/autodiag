"""Notifications: always appended to data_dir/notifications.log; optionally handed to a
configured command (the message is its last argument, never interpolated into a shell)."""

from __future__ import annotations

import shlex
import subprocess
from datetime import UTC, datetime

from autodiag.core.settings import Settings


def notify(settings: Settings, message: str) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    line = f"{datetime.now(UTC).replace(microsecond=0).isoformat()} {message}\n"
    with (settings.data_dir / "notifications.log").open("a", encoding="utf-8") as fh:
        fh.write(line)
    if settings.notify_command:
        try:
            subprocess.run(
                [*shlex.split(settings.notify_command), message], timeout=30, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            with (settings.data_dir / "notifications.log").open("a", encoding="utf-8") as fh:
                fh.write(f"{datetime.now(UTC).isoformat()} notify command failed\n")
