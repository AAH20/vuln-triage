"""Deterministic correlation policy; it never sends traffic to a target."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Iterable, List, Optional, Tuple

from .models import Advisory, Correlation, Observation, ScopeReceipt, ScopeTarget


def scope_digest(targets: Iterable[ScopeTarget]) -> str:
    rows = [
        {"active_testing": row.active_testing, "in_scope": row.in_scope, "pattern": row.pattern}
        for row in targets
    ]
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def validate_scope_receipt(receipt: ScopeReceipt) -> None:
    if not receipt.program or not receipt.retrieved_at:
        raise ValueError("scope receipt requires program and retrieved_at")
    actual = scope_digest(receipt.targets)
    if receipt.rules_hash != actual:
        raise ValueError(f"scope receipt hash mismatch: expected {actual}")


def _normal(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _version(value: str) -> Optional[Tuple[int, ...]]:
    """Parse conservative numeric versions; unknown formats remain unknown."""
    if not value or not re.fullmatch(r"v?\d+(?:\.\d+)*", value.strip(), re.I):
        return None
    return tuple(int(part) for part in value.strip().lstrip("vV").split("."))


def _cmp(left: Tuple[int, ...], right: Tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _scope_target(asset: str, receipt: ScopeReceipt) -> Optional[ScopeTarget]:
    matches = [target for target in receipt.targets if fnmatch.fnmatch(asset, target.pattern)]
    if not matches:
        return None
    # An explicit exclusion always wins over a broad wildcard inclusion.
    if any(not target.in_scope for target in matches):
        return next(target for target in matches if not target.in_scope)
    return max(matches, key=lambda target: len(target.pattern))


def _applies(observation: Observation, advisory: Advisory) -> tuple[bool, str, List[str]]:
    contradictions: List[str] = []
    if _normal(observation.product) != _normal(advisory.product):
        return False, "L0", ["product mismatch"]
    if advisory.vendor and observation.vendor and _normal(observation.vendor) != _normal(advisory.vendor):
        return False, "L0", ["vendor mismatch"]

    observed = _version(observation.version)
    introduced = _version(advisory.introduced)
    fixed = _version(advisory.fixed)
    if observed is None:
        return True, "L1", ["affected version is not proven"]
    if introduced and _cmp(observed, introduced) < 0:
        return False, "L2", [f"version {observation.version} predates affected range"]
    if fixed and _cmp(observed, fixed) >= 0:
        return False, "L2", [f"version {observation.version} is at or above fixed version {advisory.fixed}"]
    if advisory.required_component:
        present = {_normal(component) for component in observation.components}
        if _normal(advisory.required_component) not in present:
            return True, "L2", [f"required component {advisory.required_component} is not proven"]
        return True, "L3", contradictions
    return True, "L2", contradictions


def correlate(
    receipt: ScopeReceipt,
    observations: Iterable[Observation],
    advisories: Iterable[Advisory],
) -> List[Correlation]:
    """Return hypotheses only. L4 requires a separate authorized validator."""
    validate_scope_receipt(receipt)
    results: List[Correlation] = []
    advisory_list = list(advisories)
    for observation in observations:
        target = _scope_target(observation.asset, receipt)
        if target is None or not target.in_scope:
            continue
        for advisory in advisory_list:
            applies, level, contradictions = _applies(observation, advisory)
            if not applies:
                continue
            reasons = ["asset is in an immutable scope snapshot", "product evidence matches advisory"]
            if level in ("L2", "L3"):
                reasons.append("observed version is inside the affected range")
            if level == "L3":
                reasons.append(f"required component {advisory.required_component} is observed")
            if advisory.kev:
                reasons.append("CISA KEV: exploitation observed in the wild")
            elif advisory.epss:
                reasons.append(f"EPSS {advisory.epss:.1%}")

            scope_certainty = 1.0
            technology_confidence = min(1.0, max(0.0, observation.confidence))
            version_confidence = 1.0 if level in ("L2", "L3") else 0.35
            exploitation = 1.0 if advisory.kev else min(1.0, max(0.05, advisory.epss))
            freshness = 1.0 if observation.observed_at else 0.6
            score = 100 * scope_certainty * technology_confidence * version_confidence * exploitation * freshness
            component_proven = not advisory.required_component or level == "L3"
            status = "validation_candidate" if level in ("L2", "L3") and component_proven else "insufficient_evidence"
            results.append(
                Correlation(
                    asset=observation.asset,
                    cve=advisory.cve,
                    product=advisory.product,
                    status=status,
                    evidence_level=level,
                    score=round(score, 3),
                    reasons=reasons,
                    contradictions=contradictions,
                    active_validation_permitted=target.active_testing and status == "validation_candidate",
                )
            )
    return sorted(results, key=lambda result: (-result.score, result.asset, result.cve))


def naive_correlate(
    observations: Iterable[Observation], advisories: Iterable[Advisory]
) -> List[tuple[str, str]]:
    """Product-name baseline intentionally ignores scope, versions and evidence."""
    return sorted(
        {
            (observation.asset, advisory.cve)
            for observation in observations
            for advisory in advisories
            if _normal(observation.product) == _normal(advisory.product)
        }
    )
