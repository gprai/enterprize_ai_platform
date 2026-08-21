# Feature Template

Use this template only for an owner-approved feature. Replace every `TODO_USER` value with an explicit owner decision or leave it visibly pending. Never infer a business requirement, security classification, cloud value, cost, or acceptance result.

## Decision Record

| Field | Value |
|---|---|
| Feature ID | TODO_USER |
| Feature name | TODO_USER |
| Status | `Not Started` |
| Business owner | TODO_USER |
| Technical owner | TODO_USER |
| Linked tracker steps | TODO_USER |
| Governing requirement | TODO_USER |
| Decision date | TODO_USER |

Permitted status labels are `Not Started`, `In Progress`, `Blocked`, `Ready for Review`, `Done`, and `Deferred`. A tracker Step ID identifies workflow activity; it must not be used as a feature ID.

## Business Purpose

Describe the business problem, intended outcome, target users, and measurable value in plain language.

- Objective: TODO_USER
- Target users: TODO_USER
- First use case: TODO_USER
- Measurable outcome: TODO_USER

## Architecture Position

Explain where the feature sits in the end-to-end architecture and which components consume or produce its information.

- Upstream dependencies: TODO_USER
- Component or service: TODO_USER
- Downstream consumers: TODO_USER
- Governing ADRs: TODO_USER

An Architecture Decision Record (ADR) explains an important technical decision, its alternatives, and its consequences.

## Scope and Exclusions

### In scope

- TODO_USER

### Out of scope

- TODO_USER

## Files and Managed Resources

### Files to create or modify

- TODO_USER

### Managed resources

| Resource | Provider/region | Required tags | Cost owner | Expiration |
|---|---|---|---|---|
| TODO_USER or `None` | TODO_USER | TODO_USER | TODO_USER | TODO_USER |

A managed resource is infrastructure or a service whose creation, configuration, cost, and removal must be controlled. Never add a cloud resource without explicit owner approval.

## Assumptions, Dependencies, and TODO_USER Decisions

- Assumptions: TODO_USER
- Dependencies and versions: TODO_USER
- Access prerequisites: TODO_USER
- Organization values: TODO_USER
- Unresolved decisions: TODO_USER

## Design, Alternatives, and Trade-offs

### Selected design

TODO_USER

### Alternatives considered

| Alternative | Benefit | Cost or limitation | Decision |
|---|---|---|---|
| TODO_USER | TODO_USER | TODO_USER | TODO_USER |

### Architecture-decision impact

State whether an ADR is required, updated, superseded in a specifically identified part, or unaffected: TODO_USER

## Acceptance Criteria

Every criterion must be measurable and traceable to an owner-approved requirement.

1. TODO_USER

## Test Plan

| Test type | What it proves | Owner command | Expected result | Status |
|---|---|---|---|---|
| Unit | Isolated code behavior | TODO_USER | TODO_USER | `NOT RUN` |
| Integration | Components work together | TODO_USER | TODO_USER | `NOT RUN` |
| Contract | Interfaces and schemas remain compatible | TODO_USER | TODO_USER | `NOT RUN` |
| Feature | Business acceptance criteria | TODO_USER | TODO_USER | `NOT RUN` |
| Smoke | Basic start or health behavior | TODO_USER | TODO_USER | `NOT RUN` |
| Security | Approved security controls | TODO_USER | TODO_USER | `NOT RUN` |
| Rollback | Previous safe state can be restored | TODO_USER | TODO_USER | `NOT RUN` |
| Teardown | Resources and residue are removed | TODO_USER | TODO_USER | `NOT RUN` |

Status meanings:

- **PASS:** Owner-supplied evidence shows the expected result.
- **FAIL:** Owner-supplied evidence shows the expected result was not met.
- **NOT RUN:** No execution evidence was supplied.
- **Pending:** Work or an owner decision remains outstanding.

## Security, Privacy, and Data Residency

- Data classification: TODO_USER
- Authentication and authorization: TODO_USER
- Secret handling: TODO_USER
- Logging and redaction: TODO_USER
- Data locations and residency limits: TODO_USER
- Threats and mitigations: TODO_USER

## Cost Impact

- Estimated recurring cost: TODO_USER
- Estimated one-time cost: TODO_USER
- Cost assumptions and source: TODO_USER
- Budget owner and alert threshold: TODO_USER
- Cost when idle: TODO_USER

## Owner Deployment Plan

Deployment is an owner-executed change that places approved code or configuration into an environment.

- Preconditions and access: TODO_USER
- Exact owner command sequence: TODO_USER
- Expected result: TODO_USER
- Evidence to capture: TODO_USER
- Stop conditions: TODO_USER
- Status: `NOT RUN`

## Rollback Plan

Rollback restores the last known safe application or configuration state.

- Trigger: TODO_USER
- Exact bounded owner steps: TODO_USER
- Data impact: TODO_USER
- Verification: TODO_USER
- Residual risk: TODO_USER
- Status: `NOT RUN`

## Complete Teardown Plan

Teardown removes managed resources and verifies that no chargeable, accessible, or sensitive residue remains.

- Exact resource inventory: TODO_USER
- Dependency order: TODO_USER
- Exact bounded owner steps: TODO_USER
- Cleanliness verification: TODO_USER
- Expected residual resources: TODO_USER or `None`
- Status: `NOT RUN`

## Evidence

- Redacted test-evidence path: TODO_USER
- Deployment-record path: TODO_USER or `NOT APPLICABLE`
- Rollback-record path: TODO_USER or `NOT APPLICABLE`
- Resource-cleanliness path: TODO_USER or `NOT APPLICABLE`
- Cost-evidence path: TODO_USER or `NOT APPLICABLE`
- Evidence limitations: TODO_USER

Evidence must be factual, attributable to owner-supplied output, and free of credentials, tokens, personal data, and unrelated machine-specific information.

## Approval Gates

| Gate | Owner decision/evidence | Date | Status |
|---|---|---|---|
| Pre-Edit Review | TODO_USER | TODO_USER | Pending |
| Column L — Code Edit Approval | TODO_USER | TODO_USER | Pending |
| TEST-001 — Owner execution | TODO_USER | TODO_USER | `NOT RUN` |
| Column M — Document Writing Approval | TODO_USER | TODO_USER | Pending |
| Column N — Final Approval | TODO_USER | TODO_USER | Pending |
| User tracker update | TODO_USER | TODO_USER | Pending |

## Learning and Interview Preparation

### Technical importance

TODO_USER

### Layman explanation

TODO_USER

### Decisions and trade-offs

TODO_USER

### Failure and recovery story

TODO_USER

### Five interview questions with answer points

1. TODO_USER
2. TODO_USER
3. TODO_USER
4. TODO_USER
5. TODO_USER
