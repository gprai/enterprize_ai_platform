# Week 10 test evidence

Week 10 begins advanced RAG work by adding an explicit, deterministic hybrid
retrieval mode inside the existing authorized OpenSearch adapter boundary. It
does not create a second RAG stack or establish live OpenSearch, AWS,
deployment, production-quality, lifecycle, or cost readiness.

## Records

- [W10-002 bounded reranking and backend parity](W10-002.md) — adds a
  default-off provider-neutral reranking stage that receives only authorized
  backend candidates, binds an immutable local deterministic identity, limits
  candidates/tokens/time/concurrency/queue/retries, validates the exact
  response identity set, and reauthorizes final results. Timeout,
  unavailability, saturation, or malformed output returns the exact authorized
  baseline; backend authorization defects still fail closed. Final local/offline
  TEST-001 passed: the focused scope recorded 157 passed, 1 skipped,
  1 deselected, 1 warning, and 10 passing subtests; the full non-AWS/non-paid
  suite recorded 2,578 passed, 8 skipped, 4 deselected, 1 warning, and
  10 passing subtests. Ruff, MyPy, platform and YAML/config validation, strict
  OPA and 196 OPA tests, Terraform and Kubernetes Checkov, exact-manifest and
  owner-completed 836-file secret scanning, pre-commit, boundary checks, and
  external-cache cleanup passed after all failures and retries were preserved.
  Adoption remains **INDETERMINATE** because no representative owner-approved
  corpus, measured live workload, or monetized production-cost evidence ran.
  No Docker/service, model, cloud, deployment, operational rollback, teardown,
  billing, or paid test ran. The canonical post-closure evidence identity is
  `d6773665c296ec752a00722602265536bee094966c3f5e064dc5f96670a51ab2`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-18 at 00:01:00 SGT. Every warning, historical INDETERMINATE event,
  remediation, skip, deselection, NOT RUN item, limitation, adoption gap,
  dependency, deferred action, lifecycle fact, retained resource, and cost
  boundary remains preserved. Tracker update responsibility is **Owner**.
- [W10-001 authorized deterministic hybrid retrieval](W10-001.md) — combines
  bounded vector KNN and lexical BM25 channels behind the existing
  provider-neutral contract; applies identical authorization filters before
  both searches; reauthorizes every returned chunk; binds collection,
  embedding, mode, analyzer, and policy identities; and performs deterministic
  min-max normalization, equal-weight fusion, and stable tie-breaking. Final
  local/offline TEST-001 passed: the affected scope recorded 163 passed and
  one deselected; the complete non-AWS/non-paid suite recorded 2,557 passed,
  8 skipped, 4 deselected, 1 third-party warning, and 10 passing subtests.
  Ruff, MyPy, platform and YAML/config validation, strict OPA and 196 OPA
  tests, Terraform and Kubernetes Checkov, exact-manifest secret scanning,
  exact-manifest pre-commit, full-inventory secret scanning, boundary checks,
  and task-cache cleanup passed after every intermediate failure and
  remediation was preserved. No live OpenSearch/AWS call, index mutation,
  deployment, Docker/service, model download, operational rollback, cloud
  teardown, billing, or paid test ran. The canonical post-closure evidence
  identity is
  `c3378176664c41a8a58a8e57b9a2429d0beee076413d7be83618ce6468b2737a`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-17 at 22:10:00 SGT. Every warning, historical failure,
  INDETERMINATE event, remediation, skip, deselection, NOT RUN item,
  limitation, dependency, deferred action, lifecycle fact, retained resource,
  and cost boundary remains preserved. Tracker update responsibility is
  **Owner**.

## Current boundary

`RAG-002` remains `In Progress`. OpenSearch is the only backend that advertises
hybrid capability; Qdrant and the in-memory backend remain vector-only and do
not silently downgrade. Hybrid search uses exactly two concurrent channels,
two total attempts per channel, at most four provider search calls, and a
candidate limit of four times `top_k` bounded to 20–100. Both channels use one
authorization policy, and a failure, malformed hit, conflicting identity, or
unauthorized result aborts the complete request.

The Column M dependency/status input `W7-001-remediation; W9-004 / Blocked` is
preserved and remains unresolved by this record. The dedicated Week 10 owner
teach-back and `docs/learning/W10-learning-review.md` are **NOT RUN /
OWNER-DEFERRED**. Only the owner may reconcile the tracker. Column M does not
grant Git, cloud, deployment, rollback, teardown, or Column N closure authority.
W10-001 documentation is now closed under Column N within the recorded
local/offline boundary; this does not authorize or establish any of those
excluded activities.

`RAG-003` also remains `In Progress`. The approved W10-002 local identity is
`enterprise-ai/deterministic-token-overlap` revision `w10-002.v1`; reranking is
default-off, permits at most 20 candidates, four concurrent calls, no queue,
no retries, and one 250 ms local call. Synthetic comparison tests prove the
adoption gate but do not supply an adoption decision. The carried W10-002
dependency/status input `W7-001-remediation; W10-001 / Blocked` remains
unresolved. W10-002 documentation is closed under Column N within the recorded
local/offline boundary; this does not activate reranking, adopt it for
production, or authorize any excluded operational activity.

