"""Deterministic correlation policy; it never sends traffic to a target."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from datetime import datetime
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


def _bounded(value: float) -> float:
    return min(1.0, max(0.0, value))


def _expired(expires_at: str, as_of: str) -> bool:
    if not expires_at or not as_of:
        return False
    try:
        return datetime.fromisoformat(expires_at.replace("Z", "+00:00")) < datetime.fromisoformat(
            as_of.replace("Z", "+00:00")
        )
    except ValueError:
        return True


def _source_quality(source_type: str) -> float:
    return {
        "credentialed_inventory": 1.0,
        "sbom": 0.98,
        "lockfile": 0.95,
        "source_code": 0.90,
        "authenticated_scanner": 0.90,
        "vendor_api": 0.85,
        "passive_fingerprint": 0.60,
        "platform_tag": 0.45,
        "mention": 0.20,
        "unknown": 0.30,
    }.get(source_type, 0.30)


def _range_match(version: Tuple[int, ...], rule: dict) -> bool:
    start = _version(str(rule.get("introduced", "")))
    end = _version(str(rule.get("fixed", "")))
    if start:
        comparison = _cmp(version, start)
        if comparison < 0 or (comparison == 0 and not rule.get("introduced_inclusive", True)):
            return False
    if end:
        comparison = _cmp(version, end)
        if comparison > 0 or (comparison == 0 and not rule.get("fixed_inclusive", False)):
            return False
    return True


def _version_applies(version: Tuple[int, ...], advisory: Advisory) -> bool:
    ranges = advisory.affected_ranges or [{"introduced": advisory.introduced, "fixed": advisory.fixed}]
    return any(_range_match(version, rule) for rule in ranges)


def _predicate(predicate: dict, observation: Observation) -> Optional[bool]:
    """Evaluate applicability using true/false/unknown semantics."""
    if not predicate:
        return True
    if "all" in predicate:
        values = [_predicate(item, observation) for item in predicate["all"]]
        if False in values:
            return False
        return True if all(value is True for value in values) else None
    if "any" in predicate:
        values = [_predicate(item, observation) for item in predicate["any"]]
        if True in values:
            return True
        return False if all(value is False for value in values) else None
    if "not" in predicate:
        value = _predicate(predicate["not"], observation)
        return None if value is None else not value
    if "component" in predicate:
        present = _normal(str(predicate["component"])) in {_normal(value) for value in observation.components}
        return present if present or observation.configurations.get("components_complete") is True else None
    if "protocol" in predicate:
        present = _normal(str(predicate["protocol"])) in {_normal(value) for value in observation.protocols}
        return present if present or observation.configurations.get("protocols_complete") is True else None
    if "reachable" in predicate:
        return None if observation.reachable is None else observation.reachable is bool(predicate["reachable"])
    if "configuration" in predicate:
        key = str(predicate["configuration"])
        if key not in observation.configurations:
            return None
        return observation.configurations[key] == predicate.get("equals", True)
    raise ValueError(f"unsupported applicability predicate: {predicate}")


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
    if observed is None:
        return True, "L1", ["affected version is not proven"]
    if not _version_applies(observed, advisory):
        return False, "L2", [f"version {observation.version} is outside every affected range"]
    policy = advisory.applicability
    if not policy and advisory.required_component:
        policy = {"component": advisory.required_component}
    policy_result = _predicate(policy, observation)
    if policy_result is False:
        return False, "L3", ["applicability prerequisites are contradicted"]
    if policy_result is None or (policy and policy_result is not True):
        return True, "L2", ["applicability prerequisites are not proven"]
    if policy:
        return True, "L3", contradictions
    return True, "L2", contradictions


def _exploit_confidence(advisory: Advisory) -> float:
    values = [_bounded(float(item.get("confidence", 0.0))) for item in advisory.exploit_sources]
    if advisory.kev:
        values.append(1.0)
    if advisory.epss:
        values.append(_bounded(advisory.epss))
    return max(values, default=0.05)


def correlate(
    receipt: ScopeReceipt,
    observations: Iterable[Observation],
    advisories: Iterable[Advisory],
    as_of: str = "",
    include_rejected: bool = False,
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
                if include_rejected and _normal(observation.product) == _normal(advisory.product):
                    results.append(
                        Correlation(
                            asset=observation.asset,
                            cve=advisory.cve,
                            product=advisory.product,
                            status="rejected",
                            evidence_level=level,
                            score=0.0,
                            reasons=["product evidence matches advisory"],
                            contradictions=contradictions,
                            active_validation_permitted=False,
                            source_quality=_source_quality(observation.source_type),
                        )
                    )
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

            expired = _expired(observation.expires_at, as_of)
            source_quality = _source_quality(observation.source_type)
            scope_certainty = 1.0
            technology_confidence = _bounded(observation.confidence) * source_quality
            version_confidence = 1.0 if level in ("L2", "L3") else 0.35
            configuration_confidence = 1.0 if level == "L3" else (0.5 if level == "L2" else 0.25)
            reachability_confidence = 1.0 if observation.reachable is True else (0.2 if observation.reachable is False else 0.5)
            ownership = _bounded(observation.ownership_confidence)
            freshness = 0.0 if expired else (1.0 if observation.observed_at else 0.6)
            entity_confidence = scope_certainty * ownership * technology_confidence
            vulnerable_probability = entity_confidence * version_confidence * configuration_confidence * reachability_confidence * freshness
            exploitation = _exploit_confidence(advisory)
            score = 100 * vulnerable_probability * exploitation
            prerequisites_proven = (
                (not advisory.applicability and not advisory.required_component) or level == "L3"
            )
            status = "validation_candidate" if level in ("L2", "L3") and prerequisites_proven and not expired else "insufficient_evidence"
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
                    entity_confidence=round(entity_confidence, 4),
                    exploit_confidence=round(exploitation, 4),
                    vulnerable_probability=round(vulnerable_probability, 4),
                    evidence_expired=expired,
                    source_quality=source_quality,
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
