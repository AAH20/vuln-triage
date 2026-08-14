# ADR-001: Separate passive correlation from active validation

- **Status:** accepted
- **Context:** Asset-to-CVE joins can create useful hypotheses, but a public fingerprint does not prove vulnerability. Program scope can also change, and active testing can create legal and operational risk.
- **Decision:** `triage-correlate` is a deterministic, offline control-plane component. It consumes an immutable scope receipt, passive observations and normalized advisories. It makes zero network requests and cannot label a correlation as validated. Active validation belongs in a separately authorized execution plane and must consume the scope receipt again.
- **Consequences:** The OSS benchmark can be run safely and reproducibly. L0-L3 records remain hypotheses; L4 requires a future validator and evidence receipt. This deliberately favors defensibility over finding volume.
