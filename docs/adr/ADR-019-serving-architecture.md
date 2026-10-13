# ADR-019 — Production serving architecture and adapter decision

- **Status:** Owner-approved after local/offline TEST-001 and documentation
  review. **FINAL APPROVAL AFTER OWNER TEST — APPROVED** on 2026-10-13 at
  14:01:00 SGT. This does not establish deployment, cloud integration, cost,
  performance, or production readiness.
- **Decision owner:** Gyan Prakash Rai, Project Owner and Final Approval
  Reviewer.
- **Scope:** W8-001 serving design and provider-neutral contracts. This ADR
  provisions no service and grants no deployment, provider-call, rollback,
  restore, teardown, or standing production-mutation authority.

## Context

The platform needs one governed decision for choosing a serving path without
rebuilding the existing API, RAG, LangGraph, authorization, or Bedrock
boundaries. The decision begins with an immutable artifact identity and model
class, then selects an approved or conditional provider through a
provider-neutral interface.

The business analogy is selecting the right secured transport lane for each
type of cargo. The cargo identity and approval are checked first; the default
lane is selected by cargo class; an exceptional lane requires evidence and
specific approval. A lane is not built merely to demonstrate that it exists.

## Decision

Use the following route hierarchy:

| Model class or condition | Serving decision | Required evidence |
|---|---|---|
| Approved foundation model | Amazon Bedrock | Approved artifact/model identity and the existing owner-gated Bedrock boundary in ADR-004 |
| Approved custom or fine-tuned artifact needing managed hosting | SageMaker real-time endpoint | Owner-controlled artifact, immutable digest/version/license, approval reference, separate inference identity, private access, cost ceiling, and separate deployment authority |
| Structured model | Block until W7-004 admission evidence exists; then SageMaker real-time is the AWS-first default | Named structured-ML admission reference plus the custom-artifact controls above |
| Workload requiring platform control, GPU or multi-model optimization, or an explicitly documented latency requirement | EKS-hosted inference | Documented workload evidence and an explicit EKS approval reference; no automatic fallback |

Ray Serve or Triton may be considered only inside a separately reviewed
EKS-hosted proposal when measured orchestration, GPU, batching, multi-model, or
portability requirements justify their operational cost. Neither is selected,
implemented, installed, or tested by W8-001.

Bedrock remains the approved foundation-model path. SageMaker real-time is the
default managed AWS path for justified owner-controlled or fine-tuned
artifacts. EKS is conditional, not a demonstration default. No route silently
falls back to another provider, model, region, or local fake.

## Implemented contract

`ArtifactIdentity` is strict, immutable, extra-field-forbidden, and canonically
serialized as UTF-8 JSON with sorted keys and compact separators. Its fields
bind:

- schema version and model class;
- artifact name, version, SHA-256 digest algorithm and lowercase digest;
- source URI, license, approval state and approval reference;
- tenant scope and classification;
- processing region;
- separate training and inference identity references; and
- an optional superseded artifact digest.

The provider-neutral operation is:

```python
async def infer(self, request: ServingRequest) -> ServingResponse: ...
```

Requests carry request identity, immutable artifact identity, tenant,
classification, explicit authorization state, and a defensively copied JSON
payload. Responses carry request identity, selected provider, artifact digest,
and JSON output. Vendor SDK request/response objects do not belong in this
contract.

Routing and request authorization are separate fail-closed functions. Calling
orchestration must validate authorization before invoking a provider. W8-001
does not yet wire these functions into the existing API or LangGraph runtime,
and it implements no production provider adapter.

## Failure contract

Unapproved or conditionally ineligible artifacts are rejected before route
selection. Wrong tenant, mismatched classification, or a request whose
authorization flag is false is denied before the provider boundary. Stable
normalized error categories cover invalid request, unapproved artifact,
authorization failure, timeout, throttling, unavailable provider, and malformed
response. Public messages contain no provider envelope, credential, tenant
content, prompt, model output, or exception detail.

Provider timeout, access denial, unavailable dependency, and malformed output
must remain operational failures; they must not be represented as a successful
answer or trigger an uncontrolled provider fallback. The deterministic fake is
test-only and is not a degraded production provider.

## Reliability and capacity design

The design artifact `configs/serving/model-serving-routing.yaml` records:

| Control | Design value |
|---|---:|
| Connect timeout | 3 seconds |
| Read timeout | 20 seconds |
| Request timeout | 25 seconds |
| Maximum attempts | 2 |
| Circuit-breaker failure threshold | 5 |
| Circuit open duration | 30 seconds |
| Half-open probes | 1 |
| Maximum concurrent calls | 4 |
| Autoscaling replicas | 2 minimum / 4 maximum |
| Autoscaling CPU target | 70% |

These are design constraints, not an active runtime configuration: the YAML
has no production loader in W8-001. Runtime enforcement, provider-specific
retry ownership, cancellation, autoscaling behavior, load evidence, and live
SLO proof require later implementation and approval. No test result converts
these values into production capacity claims.

## Security, privacy, networking, and identity

- Training and inference identities are separate references. W8-001 does not
  create IAM roles or policies.
- Future live inference must use private access, least-privilege execution
  identity, approved model/artifact resources, and no standing production
  mutation authority.
- Tenant and classification must match the artifact identity before provider
  invocation. Existing authorization, classification, residency, retention,
  and redaction decisions remain authoritative.
- Source URIs reject credential-like material. Credentials, raw prompts,
  tenant content, model output, provider envelopes, and chain-of-thought must
  not be written to evidence or logs.
- The recorded design region is `ap-southeast-1`; the existing approved
  `Global Cross-Region` processing-policy value is retained. Any real provider
  use still requires exact residency, model, account, network, retention, and
  logging approval.

## Cost and lifecycle

The live cost ceiling is `OWNER_BINDING_REQUIRED`, live execution is
`NOT_AUTHORIZED`, and provisioning is `NOT_RUN`. Local deterministic checks
used workstation resources whose cost was not measured; they do not prove a
zero total cost.

No endpoint, pod, model server, load balancer, image, registry artifact, IAM
identity, network path, autoscaling object, cloud log, or paid provider resource
was created by W8-001. Deployment, live rollback, restore, operational
teardown, native cloud-absence verification, and delayed billing validation
remain **NOT RUN**.

The source-level rollback contract retains a prior artifact identity through
`supersedes`. The architecture decision itself may be changed only through a
reviewed successor serving ADR. A future deployment must define exact
last-known-good identities, provider-specific rollback, teardown ordering,
retained evidence, native residue checks, and cost reconciliation before it is
authorized.

## Alternatives rejected or deferred

- Replacing Bedrock as the default foundation-model path: rejected.
- Provisioning Bedrock, SageMaker, and EKS for demonstration: rejected.
- Automatically selecting EKS without workload evidence and approval:
  rejected.
- Treating a fake provider as production fallback: rejected.
- Ray Serve or Triton without a measured EKS workload need: deferred.

## Evidence and limitations

The canonical [W8-001 evidence record](../test-evidence/W8/W8-001.md) records
the implementation identities, local/offline TEST-001 results, intermediate
failures and remediations, skips, deselections, warning, and all NOT RUN live
work. Passing local tests establish source-contract consistency only. The
canonical evidence records the final owner approval and accepted limitations;
all deferred live, lifecycle, performance, identity, network, residency and
cost work remains open.
