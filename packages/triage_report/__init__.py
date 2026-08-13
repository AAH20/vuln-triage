"""triage_report: turn verdicts into artifacts a human and a board can act on."""
from __future__ import annotations

from .boardmemo import board_memo
from .register import treatment_register
from .terminal import terminal_summary

__all__ = ["terminal_summary", "treatment_register", "board_memo"]

TIER_LABEL = {"fix_now": "FIX NOW", "fix_cycle": "FIX THIS CYCLE", "monitor": "MONITOR / ACCEPT"}
