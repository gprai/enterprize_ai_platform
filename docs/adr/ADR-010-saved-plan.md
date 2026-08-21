# ADR-010 — Reviewed Saved Plans Before Mutation

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Infrastructure mutation requires a reviewed saved plan whose immutable bytes are
bound to an expiring, command-specific owner approval and exact target.

## Rationale and trade-offs

This slows delivery but prevents approval drift between review and execution.
Direct apply of an unreviewed configuration was rejected.

## Consequences and revisit trigger

Missing, changed, expired, or mismatched artifacts fail closed. Revisit only
through a superseding control decision. This ADR does not authorize any mutation.
