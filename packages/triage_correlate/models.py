"""Typed inputs and outputs for passive, authorized exposure correlation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
    protocols: List[str] = field(default_factory=list)
    configurations: Dict[str, Any] = field(default_factory=dict)
    ownership_confidence: float = 1.0
    reachable: Optional[bool] = None
    expires_at: str = ""
    source_type: str = "unknown"


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
    affected_ranges: List[Dict[str, Any]] = field(default_factory=list)
    applicability: Dict[str, Any] = field(default_factory=dict)
    exploit_sources: List[Dict[str, Any]] = field(default_factory=list)
    published_at: str = ""
    disputed: bool = False


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
    entity_confidence: float = 0.0
    exploit_confidence: float = 0.0
    vulnerable_probability: float = 0.0
    evidence_expired: bool = False
    source_quality: float = 0.0
