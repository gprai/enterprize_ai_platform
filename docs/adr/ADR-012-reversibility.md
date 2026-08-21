# ADR-012 — Every Material Change Must Be Reversible

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Define release rollback, infrastructure rollback, and complete teardown as separate
procedures with their own approvals and verification. Every material change records
an executable recovery path before acceptance.

## Rationale and trade-offs

Destroy is not rollback, and release rollback does not remove infrastructure.
Separate procedures add documentation but prevent data loss and confused recovery.

## Consequences and revisit trigger

Evidence must prove the applicable path and mark unexecuted paths NOT RUN. The
concepts will not be merged; only their implementation may be refined.
