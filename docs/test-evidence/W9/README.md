# Week 9 test evidence

Week 9 introduces governed training, experiment-lineage, and model-registry
contracts while preserving the platform's existing authorization,
orchestration, serving, lifecycle, and evidence boundaries.

## Records

- [W9-001 governed SageMaker training contracts](W9-001.md) — immutable
  model/data/code/container/cache identities; ordered tenant, classification,
  policy, approval, budget, PEFT, resource, concurrency, capability, and
  idempotency gates; deterministic SageMaker-compatible rendering; and
  source-only cleanup planning. Local/offline TEST-001 passed after preserved
  Ruff, MyPy, and temporary-path remediation. Across the two Pytest marker
  selections, all 2,484 collected items were exercised: 2,473 passed and 11
  remained intentionally skipped. Ruff, MyPy, platform validation, YAML,
  changed-scope secret scanning, both pre-commit scopes, whitespace, and index
  checks passed. The literal complete-inventory secret scan remains
  **INDETERMINATE** because the owner-controlled Excel lock filename is rejected
  as `UNSAFE_PATH`. No SageMaker job, model download, registry, Docker/service,
  AWS, deployment, live rollback, operational teardown, native residue, or
  billing test ran. The canonical evidence identity after closure is
  `6489203ef3c74f10d59ec16c107d71baa52f85ab8771dc423b2f2cd3ee03fcdd`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-14 at 15:20:00 SGT, with every warning, historical failure and
  remediation, skip, NOT RUN/INDETERMINATE item, limitation, deferred action,
  lifecycle fact, retained resource, and cost boundary preserved.
- [W9-002 experiment evaluation and lineage contracts](W9-002.md) — immutable
  dataset, code, prompt, model, embedding, retrieval, and evaluation identities;
  privacy-safe parameters, aggregate metrics, and artifact references;
  authorization-first process-local run recording; compatible-context metric
  comparison; and disable, export, exact purge, rollback, and cleanliness
  contracts. Local/offline TEST-001 passed after bounded Ruff formatting and
  import-order remediation. Across the two Pytest marker selections, all 2,511
  collected items were exercised: 2,500 passed and 11 remained intentionally
  skipped. Ruff, MyPy, platform validation, YAML, exact-manifest secret
  scanning, both pre-commit scopes, whitespace, and staged-path checks passed.
  The literal complete-inventory secret scan remains **INDETERMINATE** because
  the owner-controlled Excel lock filename is rejected as `UNSAFE_PATH`. No
  MLflow server/backend, production data, registry, model download,
  Docker/service, AWS, deployment, promotion, operational teardown, or paid
  test ran. The canonical evidence identity after closure is
  `0129bf26358d526ac360fe7c7074a10ad9b2186d6712ee8830c7c55b1b4d618b`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-14 at 21:20:00 SGT. Every warning, skip, NOT RUN/INDETERMINATE item,
  limitation, deferred action, lifecycle fact, retained resource, and cost
  boundary remains preserved.
- [W9-003 governed model registry, promotion, and rollback contracts](W9-003.md)
  — exact artifact, container, code, training, experiment/evaluation,
  model-card, policy, approval, stage, current-target, and known-good
  identities; authorization-first process-local registration; independent
  review and promotion approvals; adjacent environment promotion; exact
  rollback; hash-linked audit export; and bounded cleanup planning.
  Local/offline TEST-001 passed after bounded formatting, import-order,
  assertion, protected-hash, and stale-consumer remediation. The default suite
  and explicit execution of its four opt-in deselections accounted for all
  2,529 default-collected items: 2,518 passed and 11 remained intentionally
  skipped. Ruff, MyPy, platform
  validation, duplicate-safe YAML parsing, exact-manifest secret scanning,
  both pre-commit scopes, patch/path/index checks, and task-cache cleanup
  passed. The literal complete-inventory secret scan remains
  **INDETERMINATE** because the active owner-controlled Excel lock filename is
  rejected as `UNSAFE_PATH`; no secret finding was emitted. No SageMaker
  registry mutation, model download, Docker/service, AWS, deployment,
  operational rollback/restore/teardown, or paid test ran. The canonical
  evidence identity after closure is
  `547c8d3d7db7414597d4543320d3efe5d862c8b683620b5f04135b0e06ba2527`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-15 at 10:46:00 SGT. Every warning, unsuccessful attempt, skip,
  NOT RUN/INDETERMINATE item, limitation, deferred action, lifecycle fact,
  retained resource, and cost boundary remains preserved.
- [W9-004 governed model supply-chain and CI/CD evidence gates](W9-004.md) —
  exact model artifact, container, source, license, evaluation, training,
  experiment, SBOM, scanner, provenance, policy, tenant, and classification
  identities; fail-closed archive inspection and evidence reconciliation;
  registry-admission binding; and a manual, OIDC-based GitHub evidence gate.
  The final local/offline TEST-001 suite recorded 2,530 passed, 8 skipped,
  4 deselected, 1 third-party warning, and 10 subtests; its explicit opt-in
  complement recorded 1 passed and 3 intentionally skipped, accounting for
  all 2,542 collected items across the two selections. Ruff, MyPy, platform
  validation, duplicate-safe YAML/config validation, actionlint, strict OPA
  validation and 196 OPA tests, Checkov, exact-manifest secret scanning, both
  pre-commit scopes, whitespace, and residue checks passed after preserved
  bounded remediations. The literal complete-inventory secret scan remains
  **INDETERMINATE** because the active owner-controlled Excel lock filename is
  rejected as `UNSAFE_PATH`; no secret finding was emitted. No GitHub-hosted
  workflow, AWS/OIDC/S3 operation, real artifact or scanner run, registry
  mutation, Docker/service, deployment, operational rollback/teardown, or paid
  test ran. The canonical evidence identity after closure is
  `ec4149986ac1837e75a09c443bb2fd3aa5a5afc37b09a5baab95c3744a592726`.
  Documentation closure received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
  from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on
  2026-10-15 at 13:33:00 SGT. Every warning, unsuccessful attempt, remediation,
  skip, NOT RUN/INDETERMINATE item, limitation, concurrency gap, deferred
  action, lifecycle fact, retained resource, and cost boundary remains
  preserved.
- [W9-LEARN-001 governed-MLOps learning review](../../learning/W9-learning-review.md)
  — consolidates W9-001 through W9-004 into business, technical, architecture,
  five-answer, scenario, and STAR teach-back guidance. The predecessor
  local/offline results remain governed by their canonical records. No
  owner-authored teach-back or W9-LEARN-specific TEST-001 output was supplied,
  so both remain **NOT RUN / OWNER-DEFERRED** and are not converted to PASS.
  Final reviewer, decision, timestamp/timezone, accepted limitations, and
  closure remain **DEFERRED TO COLUMN N**. No deployment, cloud, lifecycle,
  tracker, or new cost claim is inferred.

## Current boundary

W9-001 is an offline contract, not a training deployment. W9-002 is a
process-local experiment-lineage contract, not a live MLflow service. W9-003
is a process-local registry contract, not a live SageMaker Model Registry,
deployment, or endpoint. `TRAIN-001`, `COST-006`, `MLFLOW-001`, `RET-003`, and
`REGISTRY-001` remain `In Progress`. Live training, tracking, registry
mutation, deployment, and inference are `NOT_AUTHORIZED`; environment-specific
bindings remain `OWNER_BINDING_REQUIRED`.

W9-002 limits active runs to one globally and one per tenant, retains at most
100 in-memory records, bounds a run to 900 seconds with zero automatic retries,
accepts only synthetic non-production `PUBLIC` or `INTERNAL` lineage, and
requires disablement plus a latest verified redacted export before exact purge.
Metrics remain evidence for review and cannot authorize deployment or
promotion.

W9-003 limits active registry mutations to one globally and one per tenant,
retains at most 100 process-local packages and 1,000 audit events, bounds a
request to 900 seconds with zero automatic retries, requires independent
review and promotion approvals, and permits only adjacent
`CANDIDATE → STAGING → PRODUCTION` movement. Exact known-good rollback
preserves the failed candidate and audit evidence. SageMaker-compatible request
rendering and serving-artifact projection remain non-submitting and cannot
authorize deployment.

W9-004 allows one candidate workflow per immutable digest, zero automatic
retries, a 60-minute workflow limit, 900-second OIDC sessions, and evidence no
older than 24 hours. It accepts only `PUBLIC` or `INTERNAL` evidence and only
`PUBLIC` raw artifacts on hosted runners; requires Apache-2.0, `.safetensors`,
two SBOM formats, four ordered scanner records, current signed provenance,
zero critical findings, current owner treatment for every high finding,
scanner agreement, and OPA allow; and fixes deployment approval to
`NOT_AUTHORIZED`.

The W9-001 Column M approval carries W7-001-remediation and W8-004 / Blocked as
dependencies. The W9-002 Column M approval carries W7-001-remediation and
W9-001 / Blocked. The W9-003 Column M approval carries W7-001-remediation and
W9-002 / Blocked. The W9-004 Column M approval carries W7-001-remediation and
W9-003 / Blocked. None rewrites historical evidence or updates the tracker.
W9-001, W9-002, W9-003, and W9-004 documentation are final-approved within
their recorded boundaries. Tracker update responsibility remains with the
owner; no production, cloud, managed-MLflow, SageMaker-registry,
hosted-workflow, deployment, promotion, model-training, lifecycle, or cost
readiness is inferred.

