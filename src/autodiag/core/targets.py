"""Target inventory: the YAML file that names the databases AutoDiag may reach."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from autodiag.core.models import Target


class TargetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[Target] = []

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
