# Triage — Exploit-Aware Vulnerability Triage

**Stop scanning. Start deciding.**

Your scanner found 500 CVEs. Which 12 actually matter *right now*? `triage` answers that — by prioritizing on real-world exploitation, not CVSS severity alone.

It is **not another scanner.** It sits on top of the one you already run (Trivy, Grype, OpenVAS, Nmap NSE, or a plain CVE list), enriches every finding with **CISA KEV** (is it *actually* being exploited?) and **FIRST EPSS** (30-day probability?), factors in reachability and business criticality, and produces a decision — with a board-ready memo.

```
$ triage -i scan.json -a assets.json

  Exploit-Aware Vulnerability Triage
  ==========================================================
  Demo mode: sample intelligence is never treated as a production decision.
  ----------------------------------------------------------
  TIER      CVE                 EPSS  KEV  CVSS  ASSET
  ----------------------------------------------------------
  FIX NOW   CVE-2021-44228       98%  yes  10.0  web-prod-01
  FIX NOW   CVE-2023-4966        94%  yes   9.4  web-prod-01
  FIX CYCLE CVE-2023-38545       11%    -   9.8  web-prod-01
  ----------------------------------------------------------
  Top exposure CVE-2021-44228: expected loss $60K-$1.8M, fix within 7 days.
```

Production decisions require live or explicitly supplied feed snapshots. Absence from KEV is not proof of non-exploitation, and missing EPSS remains `UNKNOWN`.

## Why CVSS alone is the noise

CVSS is *technical severity in the abstract*. FIRST (who maintain CVSS) and CISA both say **do not prioritize on it alone**. Every org has hundreds of "Criticals"; CVSS cannot tell you which to fix first. `triage` combines the signals that determine *real* risk:

| Signal | Question it answers | Source |
|---|---|---|
| **KEV** | Is it *actually* exploited in the wild? (strongest) | CISA |
| **EPSS** | How likely in the next 30 days? | FIRST |
| **Reachability** | Internet-facing or segmented? | your asset context |
| **Criticality** | Does the asset matter? | your asset context |

## The three-tier decision

- **FIX NOW** — KEV **and** (reachable **or** business-critical). 7-day deadline.
- **FIX THIS CYCLE** — in KEV, or EPSS ≥ 10%. 30-day window.
- **MONITOR CANDIDATE** — no KEV match in the supplied catalog and comparatively low EPSS. A named risk owner decides acceptance.
- **UNKNOWN** — missing, sample, or incomplete intelligence; cannot be deprioritized.

## Install & run

```bash
git clone <this repo> && cd vuln-triage
pip install -e .                      # gives you the `triage` command
# or run with no install:
PYTHONPATH=packages python -m triage_cli.main --demo -i examples/sample-trivy.json -a examples/assets.json

triage --refresh -i scan.json
triage --feed-files kev.json epss.csv -i scan.json -a assets.json -f memo
```

Ships with explicit `--demo` fixtures; demo results are always `UNKNOWN`. `--refresh` pulls live feeds. **Pure standard library — no runtime dependencies.**

## Feeds any scanner

```bash
trivy image -f json myapp:latest > scan.json && triage -i scan.json
grype myapp:latest -o json > scan.json && triage -i scan.json
nmap --script vulners target -oX - | ... > cves.txt && triage -i cves.txt   # any CVE list
```

## What it is, and isn't — honestly

- Monetary values appear only when the organization supplies an explicit loss scenario and source. KEV membership is never converted into a fabricated organizational compromise probability.
- The ATT&CK path is a **narrative** — the plausible chain a vuln enables, mapped to ATT&CK — **not an executed attack.** `triage` runs nothing against any target. It is not a Caldera-class emulation platform.
- Public exploitation activity does **not** prove *you* are being targeted; only authorized environment evidence does. The memo says so.

## Architecture (monorepo)

```
packages/
  triage_core     models, impact defaults, determinism
  triage_ingest   scanner adapters (trivy, grype, generic CVE list)
  triage_enrich   CISA KEV + FIRST EPSS lookup
  triage_decide   the three-tier engine + ATT&CK narrative
  triage_report   terminal table, treatment register, board memo
  triage_cli      the `triage` command
```

Every identical input produces the same decision output, verified by executable invariant tests (`python tests/test_decide.py`).

## Authorized asset-to-CVE correlation benchmark

`triage-correlate` compares naïve product-name CVE matching with a scope-, version-, component-, and evidence-aware policy. It is passive by design: it reads supplied JSON and makes **zero network requests**. Correlations remain hypotheses; the tool never claims that a target is vulnerable.

```bash
PYTHONPATH=packages python -m triage_correlate.cli \
  --scope examples/correlation/scope.json \
  --observations examples/correlation/observations.json \
  --advisories examples/correlation/advisories.json \
  --ground-truth examples/correlation/ground-truth.json \
  --out correlation-benchmark.json
```

Evidence levels are explicit:

- **L0** — mention or incompatible product evidence.
- **L1** — passively observed product, version unknown.
- **L2** — observed version is within the advisory range.
- **L3** — required vulnerable component is also observed.
- **L4** — reserved for separate, authorized safe validation; this passive engine cannot emit it.
- **L5** — reserved for remediated and independently retested closure.

An explicit scope exclusion overrides a wildcard inclusion. A required component that has not been observed blocks promotion to a validation candidate. See [`docs/ADR-001-authorized-correlation-plane.md`](docs/ADR-001-authorized-correlation-plane.md).

The applicability compiler also supports discontinuous `affected_ranges`, Boolean `all` / `any` / `not` predicates over components, protocols, configuration and reachability, source-quality weighting, deterministic evidence expiry, negative-policy records, and separate entity/exploit confidence. Exploit intelligence cannot compensate for unknown asset applicability. See [`docs/ADR-002-evidence-separated-confidence.md`](docs/ADR-002-evidence-separated-confidence.md).

## From triage to closure

`triage` tells you **what to fix and why it matters** — free and open source. Validating reachability in *your* environment, engineering the safe remediation, running *authorized* threat emulation, and verifying that exposure stays closed with calibrated risk quantification is a follow-on engagement.

→ [a2zsoc.com/productized-services](https://a2zsoc.com/productized-services?utm_source=github&utm_medium=readme&utm_campaign=vuln-triage)

## License

Apache-2.0.
