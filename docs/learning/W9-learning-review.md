# W9-LEARN-001 — Week 9 governed-MLOps learning handover

## Learning status and boundary

- **Task/week:** W9-LEARN-001 / Week 9.
- **Purpose:** complete the Week 9 governed-MLOps teach-back without claiming
  that a model was trained, registered, promoted, deployed, or served.
- **Source tasks:** W9-001 governed SageMaker training contracts; W9-002
  experiment evaluation and lineage contracts; W9-003 governed model registry,
  promotion, and rollback contracts; and W9-004 model supply-chain and CI/CD
  evidence gates.
- **Acceptance target:** the owner can trace one model from immutable inputs,
  through governed experimentation and exact package registration, to the
  secure promotion boundary, while explaining exact identity, separation of
  duties, promotion, rollback, and five interview answers.
- **Current learning status:** **NOT RUN / OWNER-DEFERRED**. No owner-authored
  teach-back, transcript, or W9-LEARN-specific TEST-001 output was supplied for
  this Column M update. The guidance below is a study aid, not evidence that the
  owner delivered or passed the teach-back.
- **Dependency status:** `W7-001-remediation` and `W9-004 / Blocked` are carried
  exactly from the governing approval. W9-001 through W9-004 are
  final-approved within their recorded local/offline documentation boundaries;
  that does not close W9-LEARN-001 or the predecessor live/cloud gaps.
- **Evidence rule:** predecessor PASS results remain facts of their own
  canonical records. They are not converted into a W9-LEARN-001 PASS,
  deployment authority, cloud proof, cost validation, or production readiness.

## Business explanation

Week 9 makes the path from a proposed model change to a promotion decision
reviewable. Model owners can identify exactly what was trained; data and
privacy owners can verify which governed dataset and classification were used;
evaluators can compare like with like; security can require license, artifact,
scanner, provenance, and policy evidence; independent reviewers can approve a
specific package; and platform operators can reject any deployment request
that lacks the same immutable identities.

The value is controlled decision-making, not automation for its own sake. A
good metric cannot promote itself, a mutable label cannot stand in for exact
bytes, and a successful local test cannot authorize a cloud job or deployment.

## Plain-language pharmaceutical analogy

Think of Week 9 as teaching the chain from a controlled pharmaceutical
experiment to an approved sealed batch:

- W9-001 records the exact formula, ingredients, controlled input batch,
  equipment image, procedure, approvals, capacity, and cost envelope before an
  experiment can begin.
- W9-002 records the experiment under the same identities and stores only
  governed measurements and references, not unrestricted patient or source
  material.
- W9-003 assembles a sealed candidate batch with its batch record, quality
  review, lineage, model card, stage, and known-good rollback target.
- W9-004 checks the seal, bill of materials, manufacturing provenance,
  licensing, safety scans, risk treatments, and policy decision before the
  candidate may cross a promotion boundary.

A promising trial result does not let the batch release itself. The exact
sealed batch, evidence, independent approvals, and destination authority must
all agree. A missing identity or failed check stops the chain.

## End-to-end architecture and decision flow

`immutable training inputs → authorization/policy/approval/budget gates →
non-submitting training request → governed experiment evidence → exact model
package → independent review → adjacent promotion decision → supply-chain
reconciliation and policy gate → deployment remains separately authorized`

1. **Establish identity.** Bind model, dataset, code, container, cache, tenant,
   classification, policy, approval, and budget identities before training.
2. **Admit training.** Fail closed on authorization, classification, policy,
   independent approval, budget, PEFT, resource, concurrency, capability, or
   idempotency mismatch. The local contract renders a SageMaker-compatible
   request but does not submit it.
3. **Record the experiment.** Bind dataset, code, prompt, model, embedding,
   retrieval, and evaluation identities. Store privacy-safe parameters,
   aggregate metrics, and artifact references in a process-local record.
4. **Compare honestly.** Compare metrics only when their evaluation context is
   compatible. Metrics inform review; they do not grant release authority.
5. **Register an exact package.** Bind artifact, container, code, training,
   experiment/evaluation, model-card, policy, approval, stage, current-target,
   and known-good identities. Registration is process-local and non-submitting.
6. **Separate duties.** Package review and promotion approval are independent.
   Movement is adjacent only: `CANDIDATE → STAGING → PRODUCTION`.
7. **Reconcile supply-chain evidence.** Match the exact artifact and container
   to source, license, SBOMs, scanners, signed provenance, evaluation, training,
   experiment, policy, tenant, and classification evidence.
8. **Apply the policy gate.** Missing, stale, disagreeing, unlicensed,
   unscanned, unsigned, critically vulnerable, or untreated-high-risk evidence
   fails closed. Registry eligibility still does not authorize deployment.
9. **Preserve recovery evidence.** Exact known-good rollback changes the
   governed target while retaining the failed candidate and hash-linked audit
   evidence. Live rollback, restore, and teardown remain separately governed.

## W9-001 learning module — governed training

The training contract answers: “What exact inputs and authority would make a
training request eligible?” It requires immutable model, dataset, code,
container, and cache identities, followed in order by tenant/classification
authorization, policy, independent approval, budget, PEFT, resource,
concurrency, capability, and idempotency checks.

The approved source-only limits are one active training operation globally and
one per tenant, one instance maximum, zero automatic retries, a 21,600-second
runtime ceiling, a 100-GiB volume ceiling, and a LoRA rank ceiling of 64. PEFT
is disabled by default and a budget remains owner-bound. A deterministic
SageMaker-compatible request can be rendered, but no live adapter, job, model
download, cloud mutation, or paid execution is authorized.

The main lesson is that reproducibility and authorization begin before compute
starts. A model name, “latest” tag, or remembered notebook setting cannot
replace the exact identities and reviewed constraints.

## W9-002 learning module — experiment lineage and evaluation

The experiment contract answers: “Which governed run produced this evidence,
and is comparison valid?” Each run binds exact dataset, code, prompt, model,
embedding, retrieval, and evaluation identities. Records hold redacted
parameters, aggregate metrics, and controlled artifact references; raw
production data is outside the approved boundary.

The process-local tracker permits one active run globally and one per tenant,
retains at most 100 records, bounds a run to 900 seconds, and performs zero
automatic retries. It accepts only synthetic non-production `PUBLIC` or
`INTERNAL` lineage. Disablement, a latest verified redacted export, and exact
purge are distinct lifecycle steps. No MLflow service, backend, registry,
production dataset, cloud operation, deployment, or paid run was exercised.

The main lesson is that metrics are evidence in a compatible context. They are
not self-executing approval rules and cannot bridge missing identity, privacy,
or separation-of-duties controls.

## W9-003 learning module — exact registration, promotion, and rollback

The registry contract answers: “Which exact package is being reviewed, where
may it move, and which known-good target can be restored?” A package binds the
artifact and container to code, training, experiment/evaluation, model card,
policy, approval, stage, current target, and known-good target identities.

The process-local registry permits one active mutation globally and one per
tenant, retains at most 100 packages and 1,000 audit events, bounds a request
to 900 seconds, and performs zero automatic retries. Independent package review
and promotion approval are required. Promotion is adjacent only; an exact
known-good rollback preserves both the failed candidate and the audit trail.
SageMaker-compatible rendering and serving projection do not submit or deploy.

The main lesson is that “approved model” is incomplete. Review must identify
the exact bytes, lineage, policy, stage transition, approvers, current target,
and rollback target.

## W9-004 learning module — supply chain and CI/CD boundary

The supply-chain contract answers: “Can the exact candidate prove what it is,
where it came from, how it was assessed, and whether policy allows registry
admission?” It binds model artifact, container, source, license, evaluation,
training, experiment, SBOM, scanner, provenance, policy, tenant, and
classification identities.

The local workflow permits one candidate workflow per immutable digest, not a
global single-candidate guarantee. It has zero automatic retries, a 60-minute
workflow limit, 900-second OIDC sessions, and evidence freshness of 24 hours.
It limits the candidate artifact to 10 GiB, an SBOM to 10,000 entries, a
scanner report to 50 MiB, and retained run evidence to 100 MiB. Transient
workflow evidence is retained for seven days; canonical evidence is governed
for 180 days.

Hosted runners may receive only `PUBLIC` raw artifacts; evidence may be
`PUBLIC` or `INTERNAL`. The policy requires Apache-2.0 licensing,
`.safetensors`, two SBOM formats, four ordered scanner records, current signed
provenance, zero critical findings, current owner treatment for every high
finding, scanner agreement, and OPA allow. Deployment approval is fixed to
`NOT_AUTHORIZED`.

The main lesson is that a green workflow is only evidence for the decision it
was designed to make. Registry eligibility, production promotion, and
deployment authority remain different decisions.

## Identity, separation of duties, promotion, and rollback

- **Exact identity:** use immutable digests and versioned evidence for model
  bytes, dataset, code, container, evaluation context, package, policy, SBOM,
  scanner output, and provenance. Mutable labels are navigation aids only.
- **Separation of duties:** the producer cannot turn its own metric or build
  result into release authority. Training approval, package review, promotion
  approval, security treatment, and deployment approval remain distinguishable.
- **Promotion:** only the exact reviewed package may move, only to an adjacent
  stage, and only with the required independent approval and matching evidence.
- **Rollback:** restore the exact recorded known-good target, preserve the
  rejected or failed candidate, and append audit evidence. Rollback is not
  deletion, retagging, or a claim that a live restore was tested.
- **Deployment:** no Week 9 source contract grants cloud, endpoint, registry,
  workflow, or production mutation authority.

## Security, privacy, reliability, and cost controls

- **Security:** least privilege, short-lived OIDC, pinned identities, signed
  provenance, license policy, SBOMs, multiple scanners, owner risk treatment,
  OPA, and independent review protect different boundaries.
- **Privacy:** tenant and classification checks precede work; experiment
  evidence is redacted and aggregate; raw production data, credentials,
  unrestricted prompts, and private model material do not belong in evidence.
- **Reliability:** bounded concurrency, runtime, retries, evidence age,
  retention, idempotency, typed failures, exact rollback targets, and
  hash-linked audit prevent silent drift and unbounded repetition.
- **Cost:** W9-001 requires an owner-bound budget and tightly bounded training
  resources. Later stages bound records, request duration, artifacts, reports,
  workflow duration, and retention. No live spend or billing validation ran;
  workstation time, owner effort, storage tails, support, network, tax, energy,
  and delayed billing were not measured and are not represented as zero.

## Failure and recovery model

Identity mismatch, incompatible evaluation, missing authorization, stale or
missing evidence, scanner disagreement, license failure, critical findings,
untreated high findings, provenance failure, or OPA denial blocks the next
decision. It must not trigger an automatic fallback, relabel, retry, or
promotion.

Diagnosis reads facts. Retry repeats an eligible bounded operation.
Remediation changes approved source or evidence. Rollback restores an exact
known-good governed target. Restore rebuilds state. Teardown removes exact
task-owned resources and proves absence. These actions require their own
authority and evidence; none was performed for this learning-only update.

## What predecessor validation proved—and did not prove

| Source task | Preserved local/offline result | Boundary retained |
|---|---|---|
| W9-001 | Across two Pytest selections, all 2,484 collected items were accounted for: 2,473 passed and 11 intentionally skipped. Ruff, MyPy, platform, YAML, changed-scope secret scan, both pre-commit scopes, whitespace, and index checks passed after preserved bounded remediation. | The literal complete-inventory secret scan is **INDETERMINATE** because the owner-controlled Excel lock filename was rejected as `UNSAFE_PATH`. No live training, model download, AWS, deployment, operational rollback/teardown, native-residue, or billing test ran. |
| W9-002 | Across two Pytest selections, all 2,511 collected items were accounted for: 2,500 passed and 11 intentionally skipped. Ruff, MyPy, platform, YAML, exact-manifest secret scan, both pre-commit scopes, whitespace, and staged-path checks passed after formatting/import remediation. | The literal complete-inventory secret scan is **INDETERMINATE** for the same lock-path reason. No MLflow backend, production data, registry, cloud, deployment, promotion, teardown, or paid test ran. |
| W9-003 | The default suite plus its explicit opt-in complement accounted for all 2,529 default-collected items: 2,518 passed and 11 intentionally skipped. Ruff, MyPy, platform, YAML, exact-manifest secret scan, both pre-commit scopes, patch/path/index, and cleanup checks passed after preserved bounded remediation. | The historical complete-inventory secret scan is **INDETERMINATE** for the lock-path reason. No live registry mutation, model download, AWS, deployment, or operational rollback/restore/teardown ran. |
| W9-004 | The default suite recorded 2,530 passed, 8 skipped, 4 deselected, 1 third-party warning, and 10 subtests; the explicit complement recorded 1 passed and 3 intentionally skipped. Ruff, MyPy, platform, YAML/config, actionlint, 196 OPA tests, Checkov (340 passed, 0 failed, 26 configured skips), exact 36-path secret scan, both pre-commit scopes, whitespace, and residue checks passed after preserved remediation. | The literal complete-inventory secret scan is **INDETERMINATE** for the lock-path reason. No hosted workflow, AWS/OIDC/S3 operation, real artifact/scanner run, registry mutation, deployment, rollback/teardown, or paid test ran. The per-digest concurrency design does not prove one global candidate workflow. |

The canonical W9-001 through W9-004 evidence files preserve the exact commands,
outputs, warnings, skips, deselections, unsuccessful attempts, remediations,
identities, residue facts, and final owner decisions. This learning record
summarizes them and does not replace them.

## Consolidated interview guide

### 30-second business explanation

Week 9 makes model change decisions traceable from immutable training inputs to
a secure promotion boundary. It separates training approval, governed
experiment evidence, exact package review, promotion approval, supply-chain
policy, and deployment authority. This lets model owners, data governance,
security, platform engineering, and FinOps make a specific decision without a
good metric or green build promoting itself. The implemented proof is local and
offline; no cloud training, live registry, hosted workflow, or deployment ran.

### Two-minute technical explanation

W9-001 binds immutable model, dataset, code, container, and cache identities,
then applies authorization, policy, approval, budget, PEFT, resource,
concurrency, capability, and idempotency gates before rendering a
non-submitting SageMaker-compatible request. W9-002 carries exact lineage into
a process-local experiment record with redacted parameters, aggregate metrics,
artifact references, and compatible-context comparison. W9-003 registers an
exact process-local package, requires independent review and promotion
approval, permits only adjacent stage movement, and records a known-good
rollback target. W9-004 reconciles the same candidate with license, SBOM,
scanner, signed-provenance, evaluation, training, experiment, and policy
evidence through a manual OIDC workflow design. Any missing or disagreeing fact
fails closed, and deployment remains `NOT_AUTHORIZED`.

### Five-minute architecture explanation

1. **Business risk:** mutable labels, incomparable metrics, self-promotion, or
   incomplete supply-chain evidence can release the wrong model or hide risk.
2. **Source authority:** W9-001 through W9-004 and their ADR/governance sources
   own the facts; this learning record does not supersede them.
3. **Training gate:** exact inputs and authority are established before compute;
   source renders but does not submit a cloud job.
4. **Experiment gate:** lineage and evaluation context travel with privacy-safe
   metrics; comparison is permitted only between compatible contexts.
5. **Registry gate:** exact bytes and lineage form a package; review and
   promotion approvals are independent; movement is adjacent only.
6. **Supply-chain gate:** license, SBOM, scanner, provenance, risk-treatment,
   freshness, and OPA evidence must agree with the candidate.
7. **Trust boundaries:** identity, authorization, tenant, classification,
   approval, evidence, provider, network, registry, promotion, deployment, and
   lifecycle are separate boundaries.
8. **Recovery:** preserve the failed candidate and audit chain while restoring
   the exact known-good target; do not confuse contract tests with a live
   rollback or restore.
9. **Evidence boundary:** local suites passed with recorded warnings, skips,
   deselections, intermediate failures, and remediations; complete-inventory
   secret scans remain historically indeterminate due to the active lock path.
10. **Next decision:** live model, dataset, account, region, IAM, network,
    storage, KMS, budget, retention, cleanup, and deployment authority remain
    owner-controlled and require separate evidence.

## Owner teach-back — five interview answers

These are answer guides, not owner-authored answers. The owner must explain the
subjects independently for the teach-back to be complete.

### 1. What business problem does Week 9 solve, and who benefits?

Answer guidance: Week 9 prevents an attractive model metric or mutable model
label from bypassing identity, data governance, security, cost, review, and
deployment controls. Model owners, data/privacy owners, evaluators, security,
platform operators, release reviewers, and FinOps each receive evidence for
their own decision. Value is a traceable, fail-closed decision chain—not an
unproved claim that production automation exists.

### 2. Trace one model end to end and identify the exact identities.

Answer guidance: begin with model, dataset, code, container, cache, tenant,
classification, policy, approval, budget, and training identities. Carry exact
dataset/code/prompt/model/embedding/retrieval/evaluation context into the
experiment. Register exact artifact/container/training/experiment/model-card/
policy identities. Reconcile source, license, SBOM, scanner, provenance, and
OPA identities before registry eligibility. Explain that deployment authority
is still separate.

### 3. How does separation of duties prevent metrics-driven self-promotion?

Answer guidance: training authorization, experiment recording, package review,
promotion approval, security risk treatment, and deployment approval are
separate decisions. A producer or metric can supply evidence but cannot grant
its own release authority. Independent approvals bind the exact package and
adjacent transition.

### 4. What happens when identity, evaluation, scanning, or policy fails?

Answer guidance: fail closed before the next mutation. Preserve the candidate,
evidence, typed reason, and audit chain. Diagnose without mutation; remediate
only through approval; re-evaluate the exact corrected candidate; and, if an
approved target must be restored, use the exact known-good identity rather
than a mutable label.

### 5. What did Week 9 prove, and what remains unproved?

Answer guidance: local/offline contracts, tests, static checks, schemas,
policies, rendering, and bounded cleanup behavior passed within their source
records. Historical full-inventory secret scans remain INDETERMINATE because
of the owner-controlled Excel lock path. No live SageMaker training, MLflow,
registry mutation, hosted GitHub workflow, AWS/OIDC/S3 operation, deployment,
production rollback/restore/teardown, or paid validation ran.

## Scenario preparation

- **Tenfold training or release demand:** preserve identity, authorization,
  budgets, one-operation bounds, evidence freshness, independent approvals,
  and fail-closed behavior. Do not raise concurrency or cost ceilings without
  measured queue, quota, runtime, reliability, support, and billing evidence.
- **Partially observed effect:** stop automatic retry, preserve the exact
  request/candidate, idempotency key, audit state, and available provider
  evidence; classify the result as reconciliation-required or INDETERMINATE;
  then perform read-only diagnosis under separate authority.
- **Missing authorization or classification:** reject before training,
  experiment access, registration, storage, provider, or promotion work. Emit
  only a safe reason and redacted evidence.
- **Unexpected cost:** stop before new paid work, preserve usage and billing
  evidence, compare against the owner-approved budget and retention tails, and
  require a new decision before changing resources, runtime, concurrency, or
  retry limits.

## STAR narrative

- **Situation:** an enterprise needs to move a candidate model from controlled
  inputs toward release without confusing model quality with authority.
- **Task:** design an explainable chain that preserves identity, lineage,
  independent review, supply-chain evidence, failure states, rollback, and
  cost boundaries.
- **Action:** Week 9 separated governed training, experiment evidence, exact
  registry packages, promotion approval, and supply-chain policy; added
  immutable identities and bounded local contracts; and validated them with
  source-level quality, test, security, policy, and residue checks.
- **Result:** every local decision can be traced and unsafe or incomplete
  candidates fail closed. The honest limitation is equally important: no live
  training, managed tracker, registry, hosted workflow, cloud deployment, or
  paid validation was performed.

## Teach-back acceptance and evidence boundary

- **W9-LEARN-001 TEST-001:** **NOT RUN / OWNER-DEFERRED.** No owner transcript
  or separately authorized learning-task command output was supplied before
  this Column M update. Documentation semantic/hash/boundary checks performed
  during Column M validate these files only and do not become TEST-001.
- **Owner teach-back:** **NOT RUN / OWNER-DEFERRED.** No owner-authored five
  answers, thirty-second/two-minute/five-minute delivery, scenario response, or
  hashable attachment was supplied.
- **Acceptance:** the owner must independently trace one model from inputs to
  the secure promotion boundary and explain exact identity, separation of
  duties, promotion, rollback, the five interview answers, negative cases,
  evidence classifications, and live-versus-local limits.
- **Automation and deployment:** no source, test, configuration, IaC, workflow,
  application, registry, provider, infrastructure, or cloud action was
  performed for W9-LEARN-001.
- **Rollback, restore, teardown, and residue:** no runtime resource was created;
  no live rollback, restore, teardown, native-residue inspection, or cleanup
  was performed. Documentation correction is the rollback path and requires
  the approved documentation workflow. Predecessor-specific residue facts
  remain in their canonical evidence records.
- **Cost:** no paid operation or live price/billing check was performed.
  Unmeasured workstation, owner-time, support, storage, network, tax, energy,
  and delayed-billing costs are not represented as zero.
- **Open gaps:** the literal complete-inventory secret scan remains historically
  **INDETERMINATE** in each predecessor record because the owner-controlled
  Excel lock filename was rejected as `UNSAFE_PATH`. W6 GAP-01 through GAP-04,
  predecessor live/cloud/lifecycle work, the carried dependency labels, this
  task's TEST-001, and the owner teach-back remain open as recorded.
- **Tracker:** the owner alone updates the governing workbook. This Column M
  documentation does not change its state.

## Pending owner-authored teach-back

The owner has not yet supplied the five answers or the short, medium, and
architecture narratives. When supplied, they must be preserved as owner
evidence without silently rewriting the study guide or predecessor results.
Until then, acceptance remains **NOT RUN / OWNER-DEFERRED**.

## Final Owner Approval — W9-LEARN-001

- **Reviewer:** DEFERRED TO COLUMN N.
- **Reviewer role:** DEFERRED TO COLUMN N.
- **Owner decision:** DEFERRED TO COLUMN N.
- **Approval date and time/timezone:** DEFERRED TO COLUMN N.
- **Final closure validity and accepted limitations:** DEFERRED TO COLUMN N.

