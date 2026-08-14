# ADR-002: Separate entity confidence from exploit confidence

- **Status:** accepted
- **Context:** Exploit-DB, OTX, KEV and EPSS can establish exploit maturity or threat activity, but cannot prove that a named entity deploys an affected version and configuration. Multiplying these signals into one opaque score creates confident false positives.
- **Decision:** The correlation engine maintains separate `entity_confidence`, `exploit_confidence`, and `vulnerable_probability` fields. Applicability is evaluated with true/false/unknown semantics across version ranges and Boolean configuration predicates. Exploit intelligence may affect priority only after asset evidence is calculated; it cannot promote L1 evidence to a validation candidate.
- **Consequences:** Outputs distinguish possible association, version applicability, configuration applicability and verified vulnerability. The passive engine always reports zero verified vulnerable assets because L4 requires a separate authorized validator.
