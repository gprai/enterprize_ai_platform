# ADR-016 — Governed Feature Implementation Cycle

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Use PLAN, owner Pre-Edit Approval, bounded implementation and evidence, independent
TEST-001, owner Final Approval, and owner tracker update as the controlled feature
cycle.

## Rationale and trade-offs

The cycle is slower than bulk generation but provides explicit scope, evidence,
rollback, and segregation between implementation and validation.

## Consequences and revisit trigger

Codex cannot self-approve or edit the tracker. Revisit only if a mature process
provides equivalent or stronger traceability and control.
