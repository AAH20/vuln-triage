"""Authorized asset-to-CVE correlation and benchmark engine."""

from .engine import correlate, naive_correlate, scope_digest, validate_scope_receipt
from .models import Advisory, Correlation, Observation, ScopeReceipt, ScopeTarget

__all__ = [
    "Advisory",
    "Correlation",
    "Observation",
    "ScopeReceipt",
    "ScopeTarget",
    "correlate",
    "naive_correlate",
    "scope_digest",
    "validate_scope_receipt",
]
