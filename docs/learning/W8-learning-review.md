# W8-LEARN-001 — Week 8 production-serving learning handover

## Learning status and boundary

- **Task/week:** W8-LEARN-001 / Week 8.
- **Source tasks:** W8-001 production serving architecture and adapter decision;
  W8-002 inference API hardening; W8-003 asynchronous workflow orchestration.
- **Status:** Supporting learning handover reviewed as part of W8-001
  documentation closure. Owner teach-back has **not yet been supplied** and
  remains open. W8-002 factual learning is included in the documentation
  closure approved by Gyan Prakash Rai, Project Owner and Final Approval
  Reviewer, on 2026-10-13 at 16:01:00 SGT. This does not complete or infer the
  owner teach-back. W8-003 factual learning is included in the documentation
  closure approved by the same owner and role on 2026-10-13 at 20:20:00 SGT;
  the owner teach-back remains a separate open learning obligation.
- **Evidence rule:** This learning record does not create a new TEST-001 PASS,
  authorize deployment, prove cloud behavior, close dependencies, or update
  the tracker.
- **Documentation closure:** **FINAL APPROVAL AFTER OWNER TEST — APPROVED** by
  Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on 2026-10-13 at
  14:01:00 SGT. This supporting-document reconciliation is not a duplicate
  task-level approval section. A later owner teach-back remains a separate
  learning fact.

## Business explanation

W8-001 answers a governance question before infrastructure is purchased or
deployed: which serving lane is appropriate for each model class, and what
evidence is required before an exceptional lane can be used?

Application owners need predictable behavior, model owners need immutable
artifact identity, platform engineering needs an operable default, security
needs least privilege and fail-closed authorization, and FinOps needs bounded
capacity and explicit cost authority. The measurable outcome is an
ADR-compatible topology that assigns approved and conditional paths without
provisioning them.

## Plain-language analogy

Think of model serving as selecting a secured transport lane for cargo:

- the manifest identifies the cargo, owner, version, digest, license, tenant,
  classification, and approvals;
- ordinary foundation-model cargo uses the governed Bedrock lane;
- approved custom cargo that needs managed hosting uses the SageMaker lane;
- the EKS lane is opened only for documented platform-control, GPU,
  multi-model, or latency needs and an explicit approval reference; and
- unidentified, unapproved, wrong-tenant, or wrongly classified cargo stops at
  the gate instead of being placed on a convenient fallback lane.

The design of a lane is not proof that the lane exists or that cargo travelled
through it.

## End-to-end technical flow

`ArtifactIdentity → approval/admission check → request authorization → deterministic route → provider-neutral infer contract → normalized response or normalized failure`

The artifact identity is immutable and canonically serialized. It includes
model class, name/version/digest, source, license, approval, tenant,
classification, region, separate training/inference identities, and optional
supersession. The request adds request identity, caller tenant,
classification, explicit authorization, and a defensively copied JSON payload.

Foundation models route to Bedrock. Custom artifacts default to SageMaker
real-time. Structured models first need W7-004 admission. EKS additionally
needs workload evidence and an explicit approval. Ray Serve and Triton are not
defaults; they are future EKS choices only when measured requirements justify
their extra operating burden.

## Trust, security, and privacy boundaries

Authorization, tenant, classification, artifact approval, provider, network,
identity, evidence, and lifecycle are separate boundaries. Passing one does
not imply passing another. Training identity is not inference identity. A
model digest is not deployment authority. Relevance or successful parsing is
not authorization.

The source defines a fail-closed authorization function, but no production
orchestrator wiring or provider adapter exists yet. Future runtime composition
must call authorization before provider invocation, use private access and
least privilege, and avoid standing mutation authority. Raw prompts, tenant
content, credentials, provider envelopes, model output, and chain-of-thought
do not belong in logs or evidence.

## Reliability, failure, and recovery

The design bounds connect/read/request time, attempts, circuit state,
concurrency, and autoscaling. The YAML is not runtime-loaded, so those limits
are design obligations rather than production proof.

An unapproved artifact, missing structured-ML admission, missing EKS approval,
wrong tenant, classification mismatch, timeout, access denial, unavailable
dependency, or malformed response must produce a normalized stop. It must not
become a successful answer or trigger an uncontrolled fallback.

Diagnosis reads facts. Retry repeats an eligible bounded operation. Source
remediation changes a contract. Artifact supersession identifies a predecessor.
Application rollback restores known-good application bytes. Infrastructure
rollback reverses reviewed infrastructure changes. Restore rebuilds state.
Teardown removes exact task-owned resources and proves native absence. W8-001
tested only source-level identity/supersession and local cleanliness; live
rollback, restore, and teardown were not run.

## Cost and operational boundary

No live cost ceiling is bound, no endpoint or cluster workload was created,
and no provider or cloud call ran. Local workstation cost was not measured.
The `2..4` replica and 70% CPU values are proposed limits, not deployed
capacity. Any future live proposal needs exact region/account/model/artifact,
traffic and token assumptions, private-network and identity design, owner cost
ceiling, rollback identity, teardown plan, residue checks, and delayed billing
reconciliation.

## What the validation proved—and did not prove

The complete local suite included the seven W8 unit/contract/feature/
integration/security/rollback/cleanliness modules. YAML, platform validation,
Ruff, MyPy, full Pytest, secret scanning, and isolated all-files pre-commit
behavior passed after preserved intermediate failures and bounded remediation.

This proves source contracts are internally consistent in the tested local
working tree. It does not prove a live Bedrock, SageMaker, EKS, Ray Serve, or
Triton call; runtime timeout/circuit/autoscaling enforcement; private network
or IAM behavior; production performance/SLO; deployment readiness; cost; or
cloud cleanup.

## Pending owner teach-back

The owner teach-back remains pending. Suggested questions are:

1. Explain why Bedrock remains the foundation-model default and when a custom
   artifact instead belongs on SageMaker real-time.
2. Name the exact evidence required before choosing EKS, Ray Serve, or Triton.
3. Trace artifact identity, authorization, routing, inference, and normalized
   failure without confusing any of them with deployment approval.
4. Explain why separate training and inference identities, private access, and
   no standing mutation authority matter.
5. Distinguish retry, artifact supersession, application rollback,
   infrastructure rollback, restore, and teardown.
6. State which local results passed and which cloud, lifecycle, performance,
   and cost claims remain NOT RUN or deferred.

Answers must come from the owner. This document does not pre-fill or infer
them.

## W8-002 learning handover — reinforcing the existing inference counter

W8-002 answers a different question from W8-001. W8-001 chose the governed
serving lanes; W8-002 reinforces the application counter through which an
authorized caller reaches the existing RAG dependency. It does not create a
second counter, change the provider decision, or prove that a cloud lane is
deployed.

The end-to-end runtime flow is:

`bounded request → authentication/tenant authorization → tenant-rate check → drain/capacity/circuit admission → existing RAG call under deadline and disconnect cancellation → normalized response or safe error → content-free telemetry`

Each control protects a different failure mode:

- the body and query limits bound memory and parsing work;
- the per-process tenant window bounds one tenant's local request rate without
  retaining the raw tenant identifier;
- concurrency four with a zero queue prevents unbounded waiting;
- the five-failure, 30-second circuit stops repeated calls to an unhealthy RAG
  dependency and admits one half-open probe;
- the 25-second request deadline bounds the API operation while API retries
  remain zero, avoiding attempt multiplication with the provider SDK;
- readiness withdrawal prevents new traffic while the process drains or the
  dependency circuit is open; and
- disconnect-aware cancellation prevents abandoned client work from running
  indefinitely.

Graceful shutdown is a state transition, not merely a process signal. The
loopback-only drain endpoint first withdraws readiness and rejects new work,
then allows registered work 20 seconds to finish, cancels remaining work with
a two-second bound, and closes dependencies with another two-second bound. The
Kubernetes `preStop` caller uses 23 seconds inside the existing 30-second
termination grace period. Local tests proved source behavior and manifest
composition; no real pod, load balancer, provider, or multi-replica drain was
run.

The safe `runtime.configuration` event carries four SHA-256 identities for the
model, prompt, embedding artifact, and retrieval configuration. They are
low-cardinality event fields, not metric labels. The event deliberately omits
raw prompts, tenant identifiers, endpoints, provider exceptions, model output,
and secrets.

W8-002's final local evidence passed after preserved formatter, lint, typing,
focused/full-test, Windows temp-drive, validator-literal, feature-count, and
secret-scan remediations. Eight opt-in/live tests remained skipped, four tests
remained deselected, and one third-party Starlette deprecation warning remained.
Deployment, live load, rollback, restore, operational teardown, cloud residue,
billing, and cleanup of the named local test artifacts were NOT RUN.

### Additional pending owner teach-back

7. Explain why payload limits, rate limits, concurrency limits, a circuit
   breaker, and a deadline are complementary rather than interchangeable.
8. Trace the shutdown states from the Kubernetes `preStop` call through
   readiness withdrawal, in-flight completion, bounded cancellation, and
   dependency closure.
9. Explain why a process-local tenant rate limiter is not a global ingress
   quota and what evidence would be needed before calling it one.
10. Explain why API retries are zero while the Bedrock SDK has one total
    attempt, and how layered retries could increase cost and overload.
11. State what the local PASS proves, what the eight skips/four deselections/
    warning preserve, and why none proves production readiness.
12. Distinguish source rollback instructions from an executed deployment
    rollback, restore, teardown, residue check, and billing reconciliation.

As with the earlier questions, answers must come from the owner. This handover
does not infer the teach-back. W8-002 is final-approved within its recorded
local/offline source and contract boundary; all deferred live, lifecycle, cost,
and residue work remains open.

## W8-003 learning handover — the tracked parcel workflow

W8-003 answers what happens when work cannot finish inside one synchronous API
request. The parcel analogy is useful: each workflow is a uniquely identified
shipment; authorization and tenant checks control admission; idempotency stops
duplicate shipment; quota limits the loading bay; approval holds sensitive or
high-cost cargo; retry handles a bounded temporary delay; compensation reverses
a known partial effect; reconciliation handles an unknown outcome; and the
dead-letter destination preserves exact failed work for governed review.

The source flow is:

`strict event → authorization/provider admission → idempotency → quota → approval when required → bounded execution → explicit terminal, compensation, reconciliation, or dead-letter state → hash-linked audit`

Asynchronous inference, long-running ingestion, and model training share the
same control vocabulary but retain different task/workflow timeouts. Model
training always requires approval. Confidential/restricted or high-cost work
also requires approval. Three total attempts, 1- and 2-second delays, eight
cumulative fan-out operations, four global active workflows, and two active
workflows per tenant are fixed source limits. They are not production capacity
claims.

An exact redelivery returns the prior terminal state without dispatching work
again. Reusing an idempotency key for altered input fails closed. A dependency
whose outcome is unknown is not automatically retried because the first call
may already have taken effect. It enters `RECONCILIATION_REQUIRED`, and a later
action must match workflow identity, state revision, resume token, tenant, and
authorization. This is the difference between safe durability and an infinite
agent loop.

W8-003 composes W8-001 artifact authorization/routing and W8-002 provider
circuit ownership; it does not duplicate either. It defines injected protocols
for storage, approval, quota, execution, audit, dead-letter, and compensation,
but tests use deterministic in-memory fakes. EventBridge and Step Functions are
compatibility contracts only. No event, state machine, provider, queue, DLQ,
database, deployment, rollback, teardown, or paid cloud operation ran.

Local TEST-001 passed after preserved formatter, typing, serialization,
focused-test, source-composition, cache-permission, and hook-interpreter
failures were remediated and rerun. The final W8-focused result was 33 passed;
the final repository result was 2,423 passed, 8 skipped, 4 deselected, and one
third-party warning. Those results prove local contract consistency, not live
durability, cross-process quota, IAM, network isolation, service retention,
production SLO, cost, deployment, or operational recovery.

### Additional pending owner teach-back

13. Trace one asynchronous inference request from its strict event through
    authorization, idempotency, quota, approval, execution, and terminal audit.
14. Explain why exact redelivery can return prior state while the same
    idempotency key with changed input must fail closed.
15. Distinguish retryable failure, permanent failure, partial effect, and
    unknown outcome. State why an unknown outcome is not automatically retried.
16. Explain when work is compensated, reconciled, or dead-lettered and what
    identity is required before a resume action is accepted.
17. Explain why task timeout, workflow timeout, attempt count, transition count,
    fan-out, tenant quota, and global concurrency are separate controls.
18. State what the 33 focused tests and complete local suite proved, then name
    the EventBridge, Step Functions, provider, deployment, rollback, teardown,
    residue, performance, and cost facts that remain NOT RUN or deferred.

Answers must come from the owner. W8-003 is final-approved within its recorded
local/offline source, contract, and fake-adapter boundary. This supporting
handover does not infer teach-back completion, live integration, deployment,
cloud behavior, operational recovery, cost validation, or production
readiness.
