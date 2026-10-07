"""Target inventory: the YAML file that names the databases AutoDiag may reach."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from autodiag.core.models import Target


class TargetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[Target] = []

    @field_validator("targets", mode="before")
    @classmethod
    def _empty_targets(cls, value):
        return [] if value is None else value

    @field_validator("targets")
    @classmethod
    def _unique_names(cls, v: list[Target]) -> list[Target]:
        seen: set[str] = set()
        for t in v:
            if t.name in seen:
                raise ValueError(f"duplicate target name {t.name!r}")
            seen.add(t.name)
        return v

    def get(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(name)

    def names(self) -> list[str]:
        return [t.name for t in self.targets]


def load_targets(path: Path) -> TargetInventory:
    """Load the inventory; a missing file is an empty inventory, not an error."""
    if not path.is_file():
        return TargetInventory()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return TargetInventory.model_validate(data)


def remove_target(path: Path, name: str) -> Path:
    """Remove one inventory entry, retaining a private backup and all other values.

    Does not touch databases, SSH settings, secrets, or historical case data.
    """
    path = path.resolve()
    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    data = yaml.safe_load(original) or {}
    TargetInventory.model_validate(data).get(name)  # fail before writing on unknown names
    data["targets"] = [t for t in data["targets"] if t["name"] != name]
    backup_fd, backup_name = tempfile.mkstemp(prefix=path.name + ".bak-", dir=path.parent)
    with os.fdopen(backup_fd, "w", encoding="utf-8") as backup:
        backup.write(original)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            yaml.safe_dump(data, output, sort_keys=False)
        shutil.copymode(path, temporary)
        if path.read_text(encoding="utf-8") != original:
            raise RuntimeError("inventory changed during removal; retry")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return Path(backup_name)


def add_targets(path: Path, targets: list[Target]) -> tuple[list[str], list[str]]:
    """Merge discoveries without replacing existing operator configuration."""
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    data = yaml.safe_load(original) or {"targets": []}
    existing = TargetInventory.model_validate(data)
    if data.get("targets") is None:
        data["targets"] = []
    added, skipped = [], []
    for target in targets:
        if target.name in existing.names():
            skipped.append(target.name)
            continue
        data.setdefault("targets", []).append(target.model_dump(mode="json", exclude_none=True))
        existing.targets.append(target)
        added.append(target.name)
    if added:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                yaml.safe_dump(data, out, sort_keys=False)
            if (path.read_text(encoding="utf-8") if path.exists() else "") != original:
                raise RuntimeError("inventory changed during discovery; retry")
            if path.exists():
                backup_fd, backup = tempfile.mkstemp(prefix=path.name + ".bak-", dir=path.parent)
                with os.fdopen(backup_fd, "w", encoding="utf-8") as out:
                    out.write(original)
                shutil.copymode(path, temporary)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return added, skipped
