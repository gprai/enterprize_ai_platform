# ADR-018 — Feature-management adoption decision

- **Status:** Owner-approved non-adoption for the bounded W7-004 scope;
  W7-004 documentation closure approved after owner test on 2026-10-12
  18:11:00 SGT. This is not an organization-wide decision.
- **Decision owner:** Project Owner, as recorded in the W7-004 owner-approved
  recommendations and Column L authorization.
- **Decision date:** 2026-10-12 (Asia/Singapore). Final owner approval:
  Gyan Prakash Rai, Project Owner and Final Approval Reviewer, 2026-10-12
  18:11:00 SGT — FINAL APPROVAL AFTER OWNER TEST — APPROVED.
- **Scope:** W7-004 feature-management decision. This is not an organization-
  wide statement that no structured-ML feature reuse exists.

## Context

The platform needs evidence of a real structured-ML workflow that reuses
features across training and serving before it adds a feature-management
system. The existing RAG-001 path is document ingestion, embedding and
retrieval; a feature store must not be inserted into that path merely because
it is an available technology.

W7-004 did not establish a named structured-ML product workflow with an
accountable producer, consumer, reusable feature set and measurable online or
offline requirement. The owner-approved decision rule is therefore to avoid
deploying infrastructure until that evidence exists.

## Decision

**NOT ADOPTED for W7-004.** Do not create or deploy a feature store or a
conditional feature-serving integration in this task. Keep W7-004 linked to
RAG-001 as a decision/evidence item, not as a new feature runtime or a new
feature-matrix identity. This decision may be revisited when an owner-approved,
measurable structured-ML reuse use case is supplied.

## Alternatives considered

| Option | Decision and revisit condition |
|---|---|
| No feature store | Selected now. It avoids unused infrastructure while no qualifying producer/consumer workflow has been evidenced. |
| SageMaker Feature Store | Preferred candidate if a proven use case is AWS-first and the owner approves the specific workflow, region, access, cost and lifecycle. No AWS integration or service was created or tested. |
| Feast | Candidate only if provider portability is an explicit requirement for a proven use case. No Feast dependency, service or integration was created or tested. |

None of these technologies belongs in the core document-RAG path. The existing
vector-store adapters in ADR-003 serve retrieval; they are not a structured-ML
feature store.

## Admission conditions for a future proposal

A later adoption proposal must identify the business workflow, accountable
feature producer and consumer, expected reuse, entity and tenant keys, feature
schema/versioning, source lineage, freshness and point-in-time join semantics.
It must demonstrate online/offline parity and define training-serving skew
detection, retention, deletion, backfill/replay, tenant isolation, encryption,
least-privilege IAM, a quantified cost ceiling and exact resource teardown.
The proposal must state whether AWS-first operation or provider portability is
required and provide owner-approved access, region and lifecycle boundaries.

These are decision gates, not controls implemented or proven by W7-004. No
feature schema, feature data, feature IAM policy, encryption configuration,
retention rule, service or deletion workflow was added.

## Consequences and limitations

- No feature-store dependency, runtime, cloud resource or RAG integration is
  introduced.
- Existing RAG retrieval, authorization, classification and retention
  decisions remain unchanged.
- The qualitative non-adoption rationale is recorded; a numeric lifecycle
  estimate is deferred because feature volumes, storage, latency/availability
  needs and an applicable cost ceiling were not supplied.
- Future adoption remains blocked until the use case and admission conditions
  are reviewed and approved. This ADR supplies no deployment, rollback,
  deletion, restore or teardown authority.
- W7-004 documentation closure is approved under Column N for the exact
  approved manifest. The owner-led teach-back and quantified future-store
  lifecycle estimate remain pending/deferred; they are not conditions silently
  marked complete by this documentation closure.

## Evidence

The canonical [W7-004 evidence record](../test-evidence/W7/W7-004.md) documents
the source-only decision linkage, exact local validation results, intermediate
failures and remediations, skips, deselections, warning, and the NOT RUN live
and lifecycle work. Passing local tests do not establish a live feature store,
cloud readiness or production approval.
