# ADR-000 — Source Precedence and Conflict Resolution

## Authority history and current operational review

| Field | Value |
|---|---|
| Status | Approved |
| Decision Owner | Gyan Prakash Rai |
| Approval Date | 16/08/2026 |
| Scope | Governance only; no local, cloud, deployment, rollback, or teardown mutation is approved |

The original decision and later restart review used the tracker versions approved at those times, including v1.1.1 and v1.3.0. Those references remain historical facts; this document does not pretend that a later tracker existed during earlier approvals. For current operations, the owner-approved Enterprise AI Architecture 6-Week Execution Tracker **v1.3.4** controls task sequencing, evidence expectations, approval gates, and owner-maintained status. The historical `Approved` ADR decision remains in force unless the owner explicitly supersedes an identified part of it.

### Current Decision Statement

The governing sources are applied in this order:

1. **Enterprise AI Architecture Source of Truth v1.1** is the highest implementation authority.
2. **Later owner-approved Architecture Decision Records (ADRs)** may supersede only the exact decisions they identify. An ADR is a short record explaining an important architecture decision and its consequences.
3. **Enterprise AI Architecture Coaching Blueprint** supplies supporting technical and learning guidance. It does not silently replace an owner decision.
4. **The current owner-approved Execution Tracker, presently v1.3.4,** controls work sequence, evidence, approval gates, and owner-maintained status. Historical work remains associated with the tracker version governing it at the time.
5. **Owner-approved feature requirements** govern only the feature scope they define.
6. **Generated code and configuration** implement governing decisions; they cannot override them.

If two sources conflict, work stops. The conflict must be described to the owner, including the affected sources and decision. Work resumes only after the owner records a decision; Codex must never silently reconcile the conflict.

### Restart Review Examples

- If generated configuration selects a cloud region that conflicts with Source of Truth v1.1, implementation stops for an owner decision; the configuration does not become authority merely because it exists.
- If a later owner-approved ADR changes one named technology choice, that ADR supersedes only that choice. Unrelated Source of Truth decisions remain binding.
- If a feature requirement asks for work outside the tracker's approved sequence or evidence gate, the tracker controls when the work may proceed while the feature requirement continues to control its approved business scope.

### Approval and reconciliation status

- **PASS:** The ADR received final owner approval and remains the approved source-precedence decision.
- **FAIL:** None reported in the owner-provided approval statement.
- **NOT RUN:** Unit, integration, contract, feature, security automation, deployment, rollback execution, teardown execution, and cloud tests. They are not applicable to this governance-only document change and were not authorized for Codex execution.
- **Pending:** Column N review of this Week 1 evidence reconciliation and the owner-managed tracker update. This pending reconciliation does not revoke the ADR's historical approval.

### Restart Rollback and Teardown

Rollback means restoring the pre-edit version of this file. Teardown requires no runtime action because this ADR creates no application, service, infrastructure, credential, registry object, or cloud resource. The shared `docs/adr` directory must not be deleted because it contains other governance records. Residual risk is limited to an uncommitted documentation revision; there is no cloud resource, external data copy, or continuing platform cost.

### Business and Learning Summary

**Business use case:** Teams need one dependable rule for deciding which instruction governs when architecture documents, feature requirements, delivery tracking, and generated implementation disagree. This prevents inconsistent delivery and makes escalation accountable.

**Technical importance:** Source precedence protects architecture integrity and traceability. It prevents lower-authority implementation artifacts from quietly changing security, privacy, resilience, cost, or platform decisions.

**Layman explanation:** Think of the sources as a rulebook with a known order. Code is the completed work, not the rulebook. When two rules appear to disagree, the team asks the owner instead of guessing.

**Interview talking points:**

- Explain why architecture governance needs an explicit hierarchy of authority.
- Describe how a narrowly scoped ADR can supersede one decision without invalidating the full Source of Truth.
- Explain why generated code cannot become a governance authority.
- Describe the stop-and-escalate process for conflicting requirements.
- Connect precedence to auditability, change control, and accountable technical leadership.

## Decision record

| Field | Value |
|---|---|
| ADR ID | ADR-000 |
| Status | Approved |
| Decision Owner | Gyan Prakash Rai |
| Approval Date | 16/08/2026 |
| Scope | Governance only; no local, cloud, deployment, rollback, or teardown mutation is approved |
| Supersedes | None |

## Context

The Enterprise AI Architecture project uses three authorized planning sources, later owner-approved architecture decisions, owner-approved feature requirements, and generated implementation artifacts. These sources serve different purposes and may describe different schedules, technical detail, or implementation state.

Without an explicit precedence rule, a contributor or automation could choose whichever instruction is most convenient, combine incompatible requirements, or allow generated code to redefine the architecture. That would weaken security controls, approval boundaries, traceability, rollback, and teardown guarantees.

This ADR records how authority is determined. It does not reconcile a specific conflict, approve an implementation, or authorize any local or cloud mutation.

## Decision

The project will apply the following precedence order from highest to lowest:

1. **Enterprise AI Architecture Source of Truth v1.1** is the highest implementation authority.
2. **Later owner-approved ADRs** supersede the Source of Truth only for the exact decision each ADR explicitly identifies. Every other Source of Truth requirement remains authoritative.
3. **Enterprise AI Architecture Coaching Blueprint** supplies supporting technical guidance, component rationale, examples, original prompts, learning material, and implementation detail where it does not conflict with higher authority.
4. **The owner-approved Execution Tracker** controls task sequence, grouped prompts, evidence expectations, owner gates, and owner-maintained status where it does not conflict with higher authority. Tracker v1.1.1 governed the original historical decision; v1.3.0 governed the documented restart review; the current operational authority is owner-approved tracker v1.3.4.
5. **Owner-approved feature requirements** govern the exact approved feature scope where they do not conflict with sources above them.
6. **Generated code and configuration** implement approved decisions but cannot override, reinterpret, or silently replace any governing source.

File timestamps, filenames, generated output, implementation convenience, and tool defaults do not change this order.

## Scope of later ADRs

A later ADR has superseding authority only when all of the following are true:

- The owner has explicitly approved it.
- It names the decision being superseded.
- It identifies the governing source and requirement affected.
- It records rationale, alternatives, trade-offs, consequences, and revisit triggers.
- Its scope is narrow enough to distinguish changed requirements from requirements that remain in force.

A draft, generated, or unapproved ADR has no superseding authority. Implementation evidence may motivate a new decision, but evidence alone does not rewrite the architecture.

## Conflict-resolution procedure

When two instructions appear inconsistent:

1. Stop before editing, testing through mutation, deploying, or changing status.
2. Identify each source by title, version, section, prompt, ADR, or feature identifier.
3. State the conflicting requirements and the affected decision boundary.
4. Apply this precedence order only when one source clearly governs the issue.
5. If the conflict cannot be resolved without interpretation, report it and request an explicit owner decision.
6. Record an approved material change through a new or superseding ADR and update governing documents through their controlled workflows.
7. Resume only within the newly approved boundary.

Conflicts must never be silently reconciled. A contributor must not blend incompatible requirements, choose a lower-authority instruction, or treat an implementation as approval.

## Precedence examples

### Example 1 — Weekly sequence

The Coaching Blueprint contains an original weekly implementation sequence, while Source of Truth v1.1 contains the revised controlled-development and reversible-delivery sequence. Source of Truth v1.1 governs the sequence. Coaching Blueprint technical content remains available after it is re-sequenced under the higher-authority controls.

### Example 2 — Narrow provider change through a later ADR

Source of Truth v1.1 selects Amazon Bedrock as the primary AWS LLM provider. If a later owner-approved ADR explicitly replaces only the primary LLM provider decision with an approved alternative, that ADR governs provider selection. It does not supersede unrelated Source of Truth controls such as authorization-before-retrieval, safe abstention, evidence gates, or teardown requirements.

### Example 3 — Tracker prompt versus cloud-mutation control

If a tracker prompt or verification example appears to imply that Codex may run `terraform apply`, `terraform destroy`, push an image, mutate Kubernetes, or run AWS FIS without a separate owner gate, the Source of Truth prohibition controls. Work stops and the owner must resolve or correct the lower-authority instruction before any mutation.

### Example 4 — Feature requirement versus generated code

If an owner-approved feature requirement says that insufficient evidence must produce an abstention but generated code returns an unsupported answer, the feature requirement governs. The code is defective; its observed behavior does not redefine the requirement.

### Example 5 — Tracker status versus implementation evidence

Generated test output cannot mark a tracker task complete. The tracker is owner-maintained, and its status changes only after actual evidence, independent testing, and the required owner approval. Code, evidence files, and Codex responses remain lower-authority artifacts.

## Alternatives considered

### Treat all documents as equal authority

Rejected because equal authority provides no deterministic answer when schedules, examples, or controls conflict.

### Use the newest file timestamp or highest filename version

Rejected because a timestamp or filename does not prove owner approval, intended scope, or superseding authority. Unauthorized tracker versions and legacy copies must not become authoritative accidentally.

### Treat the current implementation as the source of truth

Rejected because generated or existing code may be incomplete, defective, stale, or outside its approval boundary.

### Automatically merge or reconcile conflicting instructions

Rejected because an automated interpretation could weaken security, privacy, cost, rollback, teardown, or owner-approval controls without an accountable decision.

## Trade-offs

- Deterministic precedence improves auditability, repeatability, and safe delegation.
- Narrow ADR supersession permits evidence-based evolution without discarding unrelated controls.
- Mandatory conflict stops can slow delivery and require owner availability.
- Maintaining aligned sources, ADRs, tracker prompts, and feature requirements adds documentation work.
- Refusing automatic reconciliation favors safety and traceability over implementation speed.

## Consequences

### Positive

- Contributors can identify which requirement governs an implementation decision.
- Generated code cannot silently weaken authorization, approval, rollback, or teardown controls.
- Architecture changes retain an owner, rationale, scope, and audit trail.
- Legacy or unauthorized materials cannot regain authority through convenience or reuse.

### Negative

- Ambiguous conflicts block work until the owner decides.
- A superseding decision may require coordinated updates to the Source of Truth, ADRs, tracker, prompts, tests, and feature documentation.
- Incorrectly broad ADR language could cause unintended supersession and therefore requires careful owner review.

## Revisit triggers

Revisit this decision when:

- A reviewed successor to Source of Truth v1.1 is owner-approved.
- An owner-approved ADR intentionally changes the precedence model.
- The project adopts a new authoritative governance, regulatory, security, or compliance source.
- Evidence shows that an authority boundary is ambiguous or repeatedly causes inconsistent decisions.
- The owner approves a tracker revision that changes execution governance and the governing sources are updated consistently.

Revisiting does not itself change precedence. The change requires an explicit owner-approved superseding decision.

## Security, privacy, cost, and lifecycle impact

- **Security:** Strengthens approval boundaries and prevents lower-authority artifacts from weakening mandatory controls.
- **Privacy and data residency:** No data is processed, copied, or transferred. No production or sensitive content is included.
- **Platform cost:** USD 0; no paid service or cloud resource is used.
- **Release rollback:** Not applicable because this ADR creates no application release.
- **Infrastructure rollback:** Not applicable because this ADR changes no infrastructure.
- **Complete teardown:** Remove this file and the empty `docs/adr/` directory if the proposal is rejected before dependent implementation begins.
- **Residual-resource risk:** None; no service, container, credential, managed resource, or external system is created.

## Approval boundary

This Approved ADR records governance only. It does not approve application or infrastructure changes, Terraform apply or destroy, image push, Kubernetes mutation, AWS FIS, secret creation or rotation, deployment, rollback, teardown, Excel tracker edits, or the next tracker task.

## Week 1 evidence reconciliation — Final Owner Approval

- ADR decision status: **Approved**; decision owner Gyan Prakash Rai; approval date 16/08/2026.
- Current operational tracker authority: **owner-approved tracker v1.3.4**.
- Week 1 reconciliation reviewer: **Gyan Prakash Rai — Project Owner, Learner and Approval Reviewer**.
- Week 1 reconciliation decision: **APPROVED WITH QUALIFICATIONS**; documentation review **APPROVED**.
- Reconciliation approval timestamp: **2026-08-25 21:38:20 SGT (UTC+08:00)**.
- Evidence completeness: **QUALIFIED**; W1-08 remains an **OPEN CONTROL GAP**.
- Approval scope: documentation reconciliation only; the ADR architecture decision, historical owner/date and tracker-version history remain unchanged.
- Final reconciliation status: **APPROVED FOR USER TRACKER UPDATE — WEEKLY-LEARN-001 — WEEK 1 CONTROL FOUNDATION**.
- Tracker update responsibility: **Owner**.
