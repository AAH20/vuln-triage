"""Filesystem anchors. The repo root is two levels above packages/<pkg>/."""
from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    # packages/triage_core/paths.py -> parents[2] == repo root
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return repo_root() / "data"
