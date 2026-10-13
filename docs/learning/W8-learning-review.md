# W8-LEARN-001 — Week 8 production-serving learning handover

## Learning status and boundary

- **Task/week:** W8-LEARN-001 / Week 8.
- **Source task:** W8-001 production serving architecture and adapter decision.
- **Status:** Supporting learning handover reviewed as part of W8-001
  documentation closure. Owner teach-back has **not yet been supplied** and
  remains open.
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
