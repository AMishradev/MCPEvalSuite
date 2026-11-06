"""Check registry. Import every check module so @register runs."""
from __future__ import annotations

import importlib

_MODULES = ["manifest", "auth", "llm_lane", "static", "supply_chain", "behavior"]


def load_all_checks() -> None:
    for m in _MODULES:
        try:
            importlib.import_module(f"{__name__}.{m}")
        except ModuleNotFoundError as e:  # a lane module that is not written yet
            if m not in str(e):
                raise
