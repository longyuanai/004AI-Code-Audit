# Code-audit LLM evaluation fixtures

- Baseline recorded: 2026-08-13
- Model identifier: `synthetic-replay-v1`
- Mode: deterministic replay only in CI

The fixtures represent reviewed Stage 2 JSON responses for entirely synthetic
code-analysis contexts. They intentionally contain no repository paths,
customer identifiers, network addresses, or credentials. This product emits a
`confirmed` verdict rather than a severity, so the gate validates that native
field together with the actual confidence and reasoning fields.
