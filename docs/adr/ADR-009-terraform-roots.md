# ADR-009 — Separate Terraform Bootstrap and Environment Roots

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Maintain separate `infra/bootstrap` and `infra/environments/sandbox` roots. The
bootstrap lifecycle owns future remote state; the environment lifecycle owns the
platform. Destroy and verify the platform before removing remote state last.

## Rationale and trade-offs

One root cannot safely destroy the backend holding its own state. Two roots add
coordination but provide explicit rollback and teardown order. A single root was
rejected.

## Consequences and revisit trigger

Week 1 roots remain provider-free and resource-free. Revisit if an approved managed
external state service changes the lifecycle. No init of a real backend, plan,
apply, destroy, credential use, or AWS access is approved.
