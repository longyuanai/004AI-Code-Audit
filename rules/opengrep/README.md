# CodeGuard Opengrep rules

This directory is the production, Semgrep-compatible rule pack used by the
`OpengrepBackend`.

- Rule IDs are stable and must not contain machine-specific paths.
- Every taint rule declares source, sink, CWE, confidence, language, and
  category metadata.
- New rules require at least one vulnerable and one safe fixture.
- Phase 0 benchmark rules remain under `benchmarks/phase0/rules`; they are
  evaluation inputs rather than the production policy.

Run locally:

```powershell
opengrep scan --json --taint-intrafile --config rules/opengrep <repository>
```
