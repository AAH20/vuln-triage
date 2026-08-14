"""Typed inputs and outputs for passive, authorized exposure correlation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class ScopeTarget:
    pattern: str
    in_scope: bool
    active_testing: bool = False


@dataclass(frozen=True)
class ScopeReceipt:
    program: str
    retrieved_at: str
    rules_hash: str
    targets: List[ScopeTarget]


@dataclass(frozen=True)
class Observation:
    asset: str
    product: str
    vendor: str = ""
    version: str = ""
    confidence: float = 0.0
    observed_at: str = ""
    evidence: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Advisory:
    cve: str
    product: str
    vendor: str = ""
    introduced: str = ""
    fixed: str = ""
    required_component: str = ""
    kev: bool = False
    epss: float = 0.0


@dataclass(frozen=True)
class Correlation:
    asset: str
    cve: str
    product: str
    status: str
    evidence_level: str
    score: float
    reasons: List[str]
    contradictions: List[str]
    active_validation_permitted: bool
