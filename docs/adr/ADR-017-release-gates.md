# ADR-017 — Tests, Evidence, and Owner Approval Gate Releases

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Quality, security, privacy, cost, rollback, teardown, and redacted evidence checks
must pass before independent validation and owner approval can authorize a release.

## Rationale and trade-offs

Subjective demos are faster but cannot prove security, reversibility, or regression
control. Executable gates add work while preventing silent acceptance failures.

## Consequences and revisit trigger

FAIL and NOT RUN remain distinct from PASS, and historical failures are preserved.
Thresholds change only through measured evidence and owner approval. This ADR does
not approve deployment.
