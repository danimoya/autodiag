"""Loads the packaged knowledge-base YAML files."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

_DATA = "autodiag.kb.data"


@lru_cache
def load_yaml(name: str) -> dict:
    with resources.files(_DATA).joinpath(name).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache
def component_prefixes() -> list[tuple[str, str]]:
    """(prefix, component) sorted longest prefix first."""
    items = load_yaml("components.yaml").get("prefixes", {})
    return sorted(items.items(), key=lambda kv: -len(kv[0]))


def component_of(func: str) -> str | None:
    f = func.lstrip("_")
    for prefix, comp in component_prefixes():
        if f.startswith(prefix):
            return comp
    return None
