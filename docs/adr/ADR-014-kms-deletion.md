# ADR-014 — Delayed, Separately Approved KMS Deletion

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

KMS key deletion is delayed and separately approved. `PendingDeletion` is the only
documented sandbox teardown exception and must include a scheduled deletion date.

## Rationale and trade-offs

AWS does not support immediate key deletion. The delay leaves a visible residual
but makes the key unusable and auditable. Treating active or unknown resources as
equivalent exceptions was rejected.

## Consequences and revisit trigger

Follow-up verification remains required until deletion completes. Revisit if AWS
behavior or organization retention policy changes. No key operation is approved.
