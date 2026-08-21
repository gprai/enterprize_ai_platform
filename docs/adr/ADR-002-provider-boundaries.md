# ADR-002 — Provider Interfaces and Replaceable Boundaries

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Keep LLM, embedding, and vector-store vendor SDK types behind typed,
provider-neutral interfaces. Normalize errors at every provider and adapter
boundary.

## Rationale and trade-offs

Interfaces permit deterministic fakes, contract tests, and replacement of local
Qdrant with AWS OpenSearch or a fake provider. They add adapter code and may hide
provider-specific features. Direct SDK coupling was rejected because it weakens
portability, testing, and rollback.

## Consequences and revisit trigger

Vendor objects and raw exceptions cannot escape adapters. Revisit only when a
measured provider capability cannot be represented safely by the common contract.
No provider access is approved here.
