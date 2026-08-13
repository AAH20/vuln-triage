# Contributing

Thanks for helping make vulnerability triage a decision instead of a list.

## Run it

```bash
PYTHONPATH=packages python -m triage_cli.main -i examples/sample-trivy.json -a examples/assets.json
python tests/test_decide.py      # property tests must stay green
```

No dependencies. Python 3.9+. Pure standard library on purpose — keep it that way so anyone can run it anywhere.

## The two rules that never bend

1. **It never executes anything against a target.** The ATT&CK output is a *narrative* risk story, not an attack. No scanning, no exploitation, no reaching out to third-party hosts. Ever.
2. **It never claims false precision.** Expected-loss figures are a scaffold (measured likelihood × supplied impact), always a range, always labeled as such. If you can't measure it honestly, don't print a number.

## Adding a scanner adapter

The highest-value contribution. Each adapter lives in `packages/triage_ingest/` and turns a scanner's output into `list[Finding]`:

- Add `packages/triage_ingest/<scanner>.py` with a `load(doc)` function.
- Wire detection into `detect_and_load()` in `packages/triage_ingest/__init__.py`.
- Add a sample under `examples/`.

Wanted: OpenVAS/Greenbone XML, Nmap NSE (`vulners`) output, Nessus `.nessus`, OSV-Scanner, OWASP Dependency-Check.

## Changing the decision engine

`packages/triage_decide/engine.py` is the core. Any change must keep every property test in `tests/test_decide.py` passing, and add a new property test for the new behavior. The engine must remain **deterministic** — identical input, byte-identical output.

## Scope

This is the *prioritization* layer. Remediation engineering, authorized emulation and calibrated CRQ are deliberately out of scope for the open-source tool.

Apache-2.0. By contributing you agree your work is licensed under it.
