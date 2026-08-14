"""CLI for passive scope-to-CVE correlation and baseline comparison."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .engine import correlate, naive_correlate
from .models import Advisory, Observation, ScopeReceipt, ScopeTarget


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="triage-correlate",
        description="Passive authorized asset-to-CVE correlation; never scans targets.",
    )
    parser.add_argument("--scope", required=True, help="scope receipt JSON")
    parser.add_argument("--observations", required=True, help="passive technology observations JSON")
    parser.add_argument("--advisories", required=True, help="normalized vendor advisories JSON")
    parser.add_argument("--ground-truth", default="", help="optional labeled asset/CVE pairs for precision and recall")
    parser.add_argument("--out", default="", help="optional JSON output path")
    args = parser.parse_args(argv)

    scope_doc = _load(args.scope)
    receipt = ScopeReceipt(
        program=scope_doc["program"],
        retrieved_at=scope_doc["retrieved_at"],
        rules_hash=scope_doc["rules_hash"],
        targets=[ScopeTarget(**row) for row in scope_doc["targets"]],
    )
    observations = [Observation(**row) for row in _load(args.observations)]
    advisories = [Advisory(**row) for row in _load(args.advisories)]
    baseline = naive_correlate(observations, advisories)
    results = correlate(receipt, observations, advisories)
    candidates = [row for row in results if row.status == "validation_candidate"]
    reduction = 0.0 if not baseline else 1 - (len(candidates) / len(baseline))
    candidate_pairs = {(row.asset, row.cve) for row in candidates}
    quality = {}
    if args.ground_truth:
        truth = {(row["asset"], row["cve"]) for row in _load(args.ground_truth)}
        baseline_set = set(baseline)

        def metrics(predicted):
            true_positive = len(predicted & truth)
            return {
                "true_positive": true_positive,
                "false_positive": len(predicted - truth),
                "false_negative": len(truth - predicted),
                "precision": round(true_positive / len(predicted), 4) if predicted else 0.0,
                "recall": round(true_positive / len(truth), 4) if truth else 0.0,
            }

        quality = {"baseline": metrics(baseline_set), "policy": metrics(candidate_pairs)}
    payload = {
        "mode": "passive_correlation_only",
        "program": receipt.program,
        "scope_receipt": {"retrieved_at": receipt.retrieved_at, "rules_hash": receipt.rules_hash},
        "benchmark": {
            "naive_candidates": len(baseline),
            "version_constrained_candidates": len(candidates),
            "candidate_reduction": round(reduction, 4),
            "out_of_scope_active_requests": 0,
            "network_requests": 0,
            "quality": quality,
        },
        "correlations": [asdict(row) for row in results],
    }
    output = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(f"wrote correlation benchmark to {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
