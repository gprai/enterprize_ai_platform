# Week 4 Sign-off Record — Governed API, Agent, Observability and Release Rollback

## Document control

| Field | Value |
| --- | --- |
| Tracker checkpoint | `W4-12` |
| Business checkpoint | Review the completed Week 4 local application boundary, safety controls and release-recovery evidence before any separately governed deployment work |
| Evidence path | `docs/deployment-records/W4-signoff.md` |
| Current document status | **FINAL WEEK 4 SIGN-OFF — COMPLETED AND APPROVED** |
| Completed implementation and evidence | W4-001, W4-002, W4-003, W4-09, W4-10 and W4-ROLLBACK-001/W4-11 |
| Deployment status | **NOT RUN** |
| W4-12 reviewer decision | **COMPLETED AND APPROVED** |
| W4-12 approval time and timezone | `2026-08-31 18:03:21 SGT` (`UTC+08:00`) |
| Tracker update responsibility | Owner |

This document consolidates the final-approved Week 4 evidence and closes the
separate W4-12 checkpoint. It does not execute or authorize a deployment,
production release, external telemetry export, live provider integration,
infrastructure change, tracker edit or Git mutation. No unresolved Week 4
documentation, approval, learning or sign-off checkpoint blocks the start of
separately governed Week 5 work.

## Executive business summary

Week 4 converted the approved cited-RAG foundation into a locally testable
application platform with controlled entry points, bounded agent behavior,
redacted operational visibility and deterministic recovery evidence.

The completed local platform can:

- accept typed API requests without exposing internal retrieval, model or
  agent objects;
- obtain identity and authority from an injected trusted boundary rather than
  client-controlled JSON;
- reject overload immediately instead of creating a hidden queue;
- run a bounded agent graph with explicit budgets, human approval and narrow
  tool permissions;
- record safe, correlated operational metadata without exporting prompts,
  answers, evidence, identities, secrets or tool data;
- terminate denial, malformed-input, injection, timeout, budget and rejection
  scenarios without an unauthorized write;
- measure a deterministic in-process API load profile without presenting it
  as a production service-level objective; and
- detect a safe synthetic application regression, restore the exact known-good
  application identity, run restored-state smoke gates and remove the local
  drill residue.

The business outcome is a governed local application foundation with evidence
for access control, bounded automation, diagnosability, overload protection and
recovery. It is not evidence of live-model quality, production deployment,
cloud operations, production capacity, legal retention compliance or a
production recovery-time objective.

## Week 4 implementation and evidence status

| Work item | Delivered outcome | Final-approved evidence position | W4 checkpoint effect |
| --- | --- | --- | --- |
| W4-001 | FastAPI service boundary, strict transport validation, trusted authentication seam, authorization-before-work, request deadlines and bounded admission | Owner-tested and final-approved; original ordinary suite: 537 passed, 7 skipped and 4 deselected | Local API and authorization contract accepted |
| W4-002 | Bounded LangGraph agent, strict budgets, durable local approval state, narrow tools and redacted persistence | Owner-tested and final-approved; original ordinary suite: 613 passed, 7 skipped, 4 deselected and 10 subtests | Local governed-agent contract accepted |
| W4-003 | Vendor-neutral metrics, traces and structured safe logs with default-off export and bounded in-memory test composition | Owner-tested and final-approved; core ordinary suite: 679 passed, 7 skipped, 4 deselected and 10 subtests | Local observability contract accepted |
| W4-09 | Agent denial and failure-mode verification | Final rerun: 10 passed with one accepted warning; historical first-run failure preserved | Safe negative-path evidence accepted under `AGENT-001` |
| W4-10 | Deterministic in-process API load smoke | Final rerun: 1 passed with one accepted warning; historical Windows socket-guard failure preserved | Informational local load evidence accepted under `API-001` |
| W4-ROLLBACK-001 / W4-11 | Immutable local application-release rollback and restored-N smoke | Exact N restored in 838 ms; smoke passed in 563 ms; cleanup and zero residue passed | Local application-release recovery evidence accepted under `REL-001` |

All task-specific approvals remain authoritative at their recorded paths. This
summary neither transfers feature ownership nor rewrites the historically
correct status of work that was deferred at an earlier task closure and
completed later under a separate approval.

## W4-001 — API and trusted authorization boundary

### Business outcome

Clients receive a stable HTTP boundary without gaining direct access to the
retriever, vector store, provider or agent internals. The service fails closed
when authentication is unavailable or invalid and refuses unauthorized work
before RAG, retrieval, provider, graph or tool invocation.

### Accepted local controls

- The default application remains the approved health-only foundation unless
  API routes are explicitly enabled.
- Interactive documentation, OpenAPI and slash redirects remain disabled.
- Requests use strict JSON, reject unknown fields and apply the raw-body limit
  before full schema processing.
- The server generates a new UUIDv4 request ID and ignores inbound request,
  correlation and forwarded identifiers.
- Authentication is injected and asynchronous; the default producer fails
  closed when no authenticator is configured.
- Authorization denial occurs before downstream AI work.
- Query admission permits at most four in-flight requests with zero queue;
  excess work receives the approved immediate safe overload response.
- Request timeout and cancellation release capacity without replacement work
  or API-level retry.
- API errors use stable content-free codes and do not expose raw exceptions,
  provider envelopes, prompts, evidence or internal objects.

The original W4-001 closure recorded 537 passed, 7 skipped, 4 deselected and
one accepted warning. Historical MyPy, focused-test and complete-suite failures
remain preserved with their separately approved corrections and passing
reruns.

## W4-002 — Bounded agent and human approval

### Business outcome

The agent can coordinate approved read-oriented stages without becoming an
unbounded autonomous actor. It uses explicit graph nodes, budgets, role checks,
approval rules and terminal outcomes.

### Accepted local controls

- Authentication and authorization precede protected graph and tool work.
- Graph steps, provider calls, tool calls, tokens, elapsed time and concurrent
  runs are bounded.
- Human approval uses the approved local SQLite contract, a same-tenant
  `REVIEWER` role, requester/approver separation, a ten-minute pending expiry
  and terminal rejection/expiry behavior.
- Tool identity and arguments are allowlisted; no arbitrary tool or write
  capability is accepted from user text, retrieved evidence or model output.
- Persisted state is strict, bounded and redacted. It excludes raw prompts,
  answers, evidence, credentials, PII, provider envelopes, tool output and
  reasoning content.
- Cancellation, deadline and budget exhaustion terminate safely and do not
  start replacement work.

The original W4-002 closure recorded 613 passed, 7 skipped, 4 deselected and
10 subtests with one accepted warning. Its historical Ruff, MyPy, focused-test
and stale-consumer failures remain part of the audit history; each approved
remediation rerun passed.

## W4-003 — Redacted observability

### Business outcome

Engineering, SRE, security and audit users can identify which safe workflow
stages ran and how they ended without storing protected business content.

### Accepted local controls

- Telemetry is default-off and uses a null runtime unless explicitly composed.
- Manual request instrumentation creates a new local root trace per request
  scenario and does not trust inbound distributed-trace context.
- Three honest trace scenarios—query, agent start and agent decision—cover the
  actual API, authorization, guardrail, RAG, retrieval, embedding, LLM, graph,
  approval and tool stages without fabricating a cross-request trace.
- Metric labels use finite allowlisted values. Request, trace, span, tenant,
  subject, approval, query, source, document and chunk identifiers are not
  metric labels.
- Safe logs and spans exclude prompts, answers, retrieved content, evidence,
  credentials, PII, tool arguments/results, exception text, stack traces and
  chain-of-thought.
- In-memory span and log storage is bounded to 512 records with drop-oldest
  behavior. Application telemetry has no queue, retry or background worker.
- Export failure is isolated and cannot change a business or security result
  or retry downstream work.
- The local collector YAML is configuration-only. Collector execution and
  runtime/schema compatibility remain NOT RUN.

The W4-003 core closure recorded 679 passed, 7 skipped, 4 deselected and 10
subtests with one accepted warning. The later W4-09/W4-10 complete suite
recorded 690 passed, 7 skipped, 4 deselected and 10 subtests. Historical lint,
typing, import-cycle, cleanliness, socket-guard and downstream-consumer
failures remain preserved with their approved passing reruns.

## W4-09 — Safe failure behavior

The final ten-scenario local evidence passed authorization denial,
malformed-input isolation, prompt-injection handling, deterministic timeout,
cancellation and capacity release, step-budget exhaustion, human rejection and
replay, telemetry-export failure isolation, telemetry redaction and
cleanliness.

The first run reported one failed and nine passed because its test expected a
synchronous exporter failure to make a later no-queue `force_flush()` return
false. The exporter failure had already been captured safely when the span
ended. The separately approved test-only correction preserved production
behavior, and the complete rerun passed 10 tests with one accepted warning.
No open FAIL or INDETERMINATE result remains.

## W4-10 — Informational local load smoke

The approved in-process ASGI profile used deterministic dependencies, 20
warm-up requests and 200 measured requests at concurrency levels 1, 4 and 8.
The observed profile was:

| Concurrency | Successful | Safe overload | Maximum downstream in-flight | p50 ms | p95 ms | p99 ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 200 | 0 | 1 | 1.5465 | 1.9021 | 1.9813 |
| 4 | 200 | 0 | 4 | 5.4603 | 26.6258 | 31.5353 |
| 8 | 100 | 100 | 4 | 6.8823 | 25.0595 | 27.5770 |

All 600 measured requests completed inside the approved 30-second local
profile bound. The profile proved the four-request atomic capacity limit,
zero queue, immediate safe overload, unique server-generated request IDs,
redacted aggregate output and zero unexpected task, thread, process, limiter,
socket, file or report residue.

The first run failed before acceptance checks because a function-valued socket
guard was incompatible with a Windows Proactor event-loop type check. The
owner-approved type-compatible, non-instantiable test guard preserved the
no-new-socket rule, and the complete rerun passed. These local timings are
informational and are not a production latency, throughput, capacity or SLO
claim.

## W4-11 — Immutable local application-release rollback

### Approved identities and regression

- Known-good release N: `w4-known-good-v1`.
- Repository commit identity:
  `faf5552f1eb8f2aaa884a9a68a3e3f8a38bec496`.
- Package version: `0.1.0`.
- Canonical 99-artifact composition SHA-256:
  `5340439d876036885558c32738416dd908a27f763bd87fc5e43fd1690f08dbdc`.
- Synthetic candidate N+1: `w4-synthetic-regression-v1`.
- Deliberate safe defect: agent route disabled.
- Expected safe candidate result: HTTP 501 with `agent_disabled` and zero RAG,
  retrieval, embedding, provider, graph, approval and tool calls.

### Executed local recovery

The owner executed the bounded local drill. Candidate N+1 failed its approved
gate safely. The release-control plane validated the exact expected current
identity, acquired its exclusive writer lock, revalidated generation and
artifacts, atomically restored N and verified the published identity.

Rollback completed in **838 ms**, below the 30,000 ms hard limit. The agent
route latch remained closed until the restored-N smoke recipe passed every
approved gate. Smoke then passed in **563 ms**, including 51 tests, and opened
the latch. The owner removed the local runtime reports and independently
verified **ZERO_RESIDUE**.

This was a deterministic local application-release selection and restoration
drill. It did not change application source, Git history, shared data,
infrastructure or the immutable N/N+1 descriptors.

### Final W4-11 verification facts

| Check | Final result |
| --- | --- |
| Ruff | PASS |
| Strict MyPy | PASS — 106 source files |
| Release unit/contract scope | PASS — 11 tests |
| Corrected functional/security/rollback/cleanliness scope | PASS — 21 tests |
| Feature/platform consumers | PASS — 32 tests and 10 subtests |
| Protected W3/W4 regressions | PASS — 40 tests with one accepted warning |
| Complete ordinary suite | PASS — 724 passed, 7 skipped, 4 deselected, 1 warning and 10 subtests |
| Immutable release validation | PASS — exact 99-file identity |
| Local application-release rollback | PASS — exact N restored in 838 ms |
| Restored-N smoke | PASS — 51 tests and all smoke gates; 563 ms |
| Cleanup and zero residue | PASS |

The first combined release scope reported one failed and 20 passed because a
test matched `smoke:` inside the earlier `test-smoke:` Make target. The bounded
test-only correction compared exact target lines, and the affected scope
passed 21 tests. The historical failure remains recorded.

## Complete Week 4 result classification

### PASS within the approved local boundary

- W4-001 API, authentication, authorization, overload, rollback-disable and
  cleanliness contracts.
- W4-002 bounded agent, approval, tool, budget, persistence, rollback-disable
  and cleanliness contracts.
- W4-003 telemetry schema, correlation, redaction, bounded storage,
  failure-isolation, rollback-disable and cleanliness contracts.
- W4-09 deterministic negative-path scenarios.
- W4-10 deterministic in-process load profile.
- W4-11 exact local application-release rollback, restored-N smoke and
  zero-residue cleanup.
- Final complete ordinary suite: 724 passed, 7 skipped, 4 deselected, one
  warning and 10 subtests.

### Historical FAIL facts preserved

Each task evidence record preserves its initial lint, typing, focused-test,
consumer, cleanliness or socket-guard failures and the exact separately
approved remediation and passing rerun. W4-11 also preserves the intended N+1
gate failure as a designed release-rejection result. Current open FAIL results:
none.

### NOT RUN

- Seven skipped and four deselected ordinary-suite activities.
- Python 3.11 execution; owner evidence used Python 3.13.7.
- Live identity provider, Bedrock/model, Qdrant/OpenSearch and external
  approval-service integration.
- Real production data, provider-quality and production privacy/residency
  validation.
- Collector runtime, external telemetry export, dashboards, alerting and
  production telemetry retention.
- Local service deployment, production deployment and cloud deployment.
- Production performance, capacity, availability, SLO and disaster-recovery
  validation.
- Source/Git, shared-data, infrastructure, Kubernetes/EKS and cloud rollback.
- Operational production service, container and cloud teardown.

### INDETERMINATE

Remaining open TEST-001 INDETERMINATE activities: none. Historical and
non-test environment-inspection limitations remain preserved in their source
records and are not rewritten as PASS.

## Security, privacy, cost and operational boundaries

| Area | Week 4 evidence position |
| --- | --- |
| Identity | Trusted injected authentication boundary; live identity-provider integration NOT RUN |
| Authorization | Denial occurs before protected RAG, retrieval, provider, graph or tool work |
| Agent control | Finite graph, budgets, approval and narrow tool contracts; no arbitrary autonomous write |
| Data minimization | API, state, errors and telemetry exclude raw prompts, answers, evidence, credentials, PII, provider envelopes, tool data and reasoning content |
| Observability | Vendor-neutral, redacted and bounded local evidence; external export and production retention NOT RUN |
| Network | Ordinary evidence was deterministic, local, fake or in-process; no deployment or live provider/cloud network activity |
| Provider/cloud cost | Recorded provider/cloud cost was USD 0 where task evidence measured it |
| Other cost | Local CPU, memory, disk, electricity and owner time were real and were not monetized as zero |
| Production claim | None |

The accepted Starlette/httpx TestClient deprecation warning remains open. Git
LF-to-CRLF working-copy notices were non-failing and are retained where
recorded. No production vulnerability scan, SBOM attestation, live privacy or
residency assessment, production operations proof or deployment approval is
created by this record.

## Deployment, rollback, teardown and residual-resource reconciliation

| Lifecycle area | Exact Week 4 position |
| --- | --- |
| Local service deployment | **NOT RUN** |
| Production/cloud deployment | **NOT RUN** |
| Configuration/test rollback | **PASS** within the recorded API, agent and telemetry automated scopes |
| Local immutable application-release rollback | **PASS** — exact N restored in 838 ms |
| Source/Git or shared-data rollback | **NOT RUN** |
| Infrastructure/Kubernetes/EKS/cloud rollback | **NOT RUN** |
| Restored-N smoke | **PASS** — 51 tests and all approved smoke gates; 563 ms |
| Local drill cleanup | **PASS — ZERO_RESIDUE** |
| Operational production/container/cloud teardown | **NOT RUN** because no such resource was created |
| Retained intended resources | Approved source, configuration, immutable descriptors, automated tests, evidence, documentation and external development environment |
| Unexpected runtime residue | None recorded after final owner cleanup and independent verification |

Cleanup is not rollback. The W4-11 rollback changed the active local release
reference from synthetic N+1 back to exact N; cleanup subsequently removed the
approved reports, lock, atomic temporary files and isolated runtime directory.
Neither action deployed or removed a production service or cloud resource.

## Accepted limitations and deferred work

The following items remain separately governed and must not be inferred as
completed by this W4-12 local checkpoint approval:

- exact live Bedrock account, model, region, quota, IAM, privacy, residency and
  cost authorization;
- production identity and external approval-service integration;
- production telemetry backend, retention, alerting, dashboards and on-call
  operations;
- Python 3.11 execution;
- deployed-service, production performance, capacity, availability and SLO
  evidence;
- production security, privacy, residency and compliance assessment;
- source, shared-data, infrastructure and cloud recovery evidence;
- production deployment, operational rollback and operational teardown; and
- any separate owner decision or tracker row that its governing record still
  classifies as In Progress.

Responsible owner: Gyan Prakash Rai unless another owner is explicitly
recorded for an individual deferred action. Each deferred item requires its
own bounded approval and actual evidence.

## Evidence authority

This sign-off summary relies on, but does not replace, the detailed records:

- `docs/test-evidence/W4/W4-001.md`;
- `docs/test-evidence/W4/W4-002.md`;
- `docs/test-evidence/W4/W4-003.md`;
- `docs/test-evidence/W4/W4-09-failures.txt`;
- `docs/test-evidence/W4/W4-10-load.json`;
- `docs/rollback-records/W4-release.md`;
- `docs/test-evidence/README.md`; and
- `docs/learning/W4-learning-review.md` for the separately governed Week 4
  learning record.

If this summary conflicts with a task-specific final-approved evidence record,
the task-specific record remains authoritative. The Week 4 learning approval
and W4-12 checkpoint are separate owner approvals, and both are complete.

## Final Owner Approval — W4-12

| Required approval fact | Owner-approved value |
| --- | --- |
| Prompt/task ID | `W4-12` |
| Reviewer exact name | Gyan Prakash Rai |
| Reviewer role | Project Owner and Final Approval Reviewer |
| Exact owner decision | **COMPLETED AND APPROVED** |
| Approval date, time and timezone | `2026-08-31 18:03:21 SGT` (`UTC+08:00`) |
| Final status | **FINAL WEEK 4 SIGN-OFF — APPROVED** |
| Code and evidence review | Approved within the recorded deterministic local boundaries of W4-001, W4-002, W4-003, W4-09, W4-10 and W4-ROLLBACK-001/W4-11 |
| Documentation review | Approved; this W4-12 sign-off and the separately approved W4-13 learning record are complete |
| Owner-executed test status | **PASS within the approved local scope** — final complete suite 724 passed, 7 skipped, 4 deselected, 1 warning and 10 subtests; exact N restored in 838 ms; restored-N smoke and zero-residue cleanup passed |
| Historical FAIL facts | Preserved with their owner-approved bounded remediations and passing reruns; current open FAIL results: none |
| NOT RUN and INDETERMINATE facts | All recorded NOT RUN activities remain NOT RUN and none is converted to PASS; remaining open TEST-001 INDETERMINATE results: none |
| Warnings, risks and limitations | Accepted exactly as recorded, including the Starlette/httpx warning, Git line-ending notices, local/fake/in-process boundaries, Python 3.11 not executed and no production performance, SLO, deployment or cloud-readiness proof |
| Deployment facts | Local service, production and cloud deployment remain **NOT RUN**; no deployment is authorized by this sign-off |
| Rollback facts | Deterministic local immutable application-release rollback **PASS**; source/Git, shared-data, infrastructure, Kubernetes/EKS and cloud rollback remain **NOT RUN** |
| Teardown and residual-resource facts | Local drill cleanup and independent zero-residue verification **PASS**; operational production/container/cloud teardown remains **NOT RUN** because no such resource was created; intended repository artifacts remain retained |
| Deferred actions | Live integrations and production/cloud lifecycle work remain separately governed; they do not block Week 5 design or implementation conducted under its own approval gates |
| Conditions and next-task handover | Preserve all recorded classifications and scope limits; Week 5 may proceed under its own four approval gates plus owner testing and learning; this approval grants no deployment, cloud, Excel or Git authority |
| Tracker update responsibility | Owner |

No unresolved Week 4 documentation, approval, learning or sign-off item remains.
The owner may reconcile W4-12 in the tracker and begin separately governed Week
5 tasks. Production and cloud work still require their own explicit approvals
and evidence.

**FINAL APPROVAL — WEEK 4 CHECKPOINT CLOSED — W4-12.**
