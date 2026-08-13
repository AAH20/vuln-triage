"""triage_decide: the decision engine. A scanner gives a list; this gives a verdict."""
from __future__ import annotations

from .engine import decide, decide_all

__all__ = ["decide", "decide_all"]
