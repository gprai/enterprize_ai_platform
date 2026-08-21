# ADR-011 — No Routine Manual Cloud Mutation

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Routine cloud changes use reviewed infrastructure-as-code workflows. Codex never
self-approves or automatically applies or destroys infrastructure. A controlled
break-glass action requires a separate owner decision, bounded scope, evidence, and
post-action reconciliation.

## Rationale and trade-offs

Manual console or ad-hoc CLI changes are faster but create drift and weak evidence.
The controlled path adds time while preserving auditability and reversibility.

## Consequences and revisit trigger

No routine manual mutation is permitted. Revisit only after mature controls and a
superseding owner-approved governance decision. Week 1 authorizes no break glass.
