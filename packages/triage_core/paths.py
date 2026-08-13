"""Filesystem anchors that work from a source checkout and an installed wheel."""
from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    # packages/triage_core/paths.py -> parents[2] == repo root
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    packaged = Path(__file__).resolve().parent / "data"
    return packaged if packaged.exists() else repo_root() / "data"
