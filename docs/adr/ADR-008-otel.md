# ADR-008 — OpenTelemetry as the application observability contract

## Status

Implemented and owner-tested within the W4-003 deterministic local boundary;
Column M owner review and Column N final approval are complete. This ADR
records the approved decision and does not authorize deployment or external
telemetry export.

## Context

API, RAG, retrieval and bounded-agent workflows need operational explanation
without turning telemetry into a copy of protected business content. The
application also needs a vendor-neutral boundary so later operational work can
choose collectors and backends without coupling business components to
CloudWatch, X-Ray, Prometheus, Grafana, Jaeger or another vendor API.

Inbound correlation is untrusted. Telemetry cannot become an authentication or
authorization source, and its failure cannot change a business/security
outcome, retry protected work or leave unbounded resources.

## Decision

Use OpenTelemetry API/SDK `>=1.44,<1.45` behind a narrow application-facing
runtime protocol.

1. Default application composition uses `NullTelemetryRuntime`. OpenTelemetry
   providers and readers are created only by explicit composition or injected
   deterministic tests.
2. Instrument requests manually. Do not use FastAPI auto-instrumentation or
   accept inbound `traceparent`, `tracestate`, baggage, request, correlation or
   forwarded identifiers. Preserve the server-generated request ID and create
   a new local root trace per request scenario.
3. Normalize observations to finite enums, approved codes, bounded version
   identifiers, numeric counts and durations before any processor, buffer,
   reader, log sink or exporter.
4. Apply strict immutable positive allowlists. Prohibit prompt/query/answer,
   retrieved content and identifiers, identity/approval/run data, tool
   arguments/results, credentials, PII, provider envelopes, exception text,
   stack traces and reasoning content.
5. Use fixed in-memory capacities of 512 spans and 512 safe log records with
   drop-oldest behavior and safe drop signaling. Application queue, retry and
   background worker counts remain zero. File/socket spill is prohibited;
   flush and shutdown deadlines are 1 second.
6. Isolate exporter failures behind a content-free safe signal. A telemetry
   failure never fails or permits a business request and never retries RAG,
   retrieval, provider, graph, approval or tool work. Cancellation propagates
   without replacement work.
7. Prove W4-08 with three honest traces—query, agent start and agent decision—
   one per request. The trace set collectively covers actual API,
   authorization, guardrail, RAG/retrieval/embedding/LLM, graph, approval and
   tool stages. Do not fabricate a cross-request trace or activate the deferred
   live AgentEvidenceGateway/RAG adapter.
8. Treat `configs/observability/otel-collector.local.yaml` as configuration
   only. Its OTLP receivers are loopback-only (`127.0.0.1:4317` and
   `127.0.0.1:4318`); traces, metrics and logs use a bounded batch processor
   (1-second timeout, size 64, maximum 64) and local debug exporter. No
   `memory_limiter`, sending queue, external destination or secret is present.

## Alternatives considered

- **Automatic FastAPI instrumentation:** rejected because it broadens the
  captured surface and propagation behavior beyond the approved allowlist.
- **Raw application logging:** rejected because free-form content and
  exception text cannot provide the required pre-sink privacy boundary.
- **Unbounded in-memory exporters/sinks:** rejected because they create
  uncontrolled memory and cardinality risk.
- **Immediate OTLP or cloud export:** deferred because it introduces network,
  trust, credential, residency, retention, cost and operational lifecycle
  decisions owned by later work.
- **One fabricated cross-request trace:** rejected because it would misstate
  the real API/RAG/agent connection topology.

## Rationale and trade-offs

The decision gives developers, SRE and security reviewers correlated safe
stage outcomes while keeping business logic vendor neutral and default-off.
Positive allowlists and finite labels reduce leakage and cardinality risk.
Synchronous bounded processing makes lifecycle and failure behavior easier to
prove locally.

Trade-offs are deliberate: three request traces must be analyzed together;
default-off local evidence provides no live backend, dashboard or alert; and
drop-oldest behavior may discard old observations under pressure. Safe drop
and export-failure counters expose those conditions without content.

## Security, privacy, reliability and cost consequences

- Authentication and authorization remain authoritative and precede protected
  downstream work; telemetry only observes safe outcomes.
- Request/trace/span identifiers are permitted only in traces and safe logs,
  never metrics. Identity and content are prohibited.
- Export failure, timeout or shutdown failure is isolated and bounded.
- Deterministic tests used synthetic inputs and local fakes. No production data
  or real credential/PII was used.
- Provider/cloud cost was USD 0. Local CPU, memory, disk, electricity and owner
  time were real and not monetized as zero.
- External exporter, collector runtime, network, provider/model, Docker,
  AWS/cloud and deployment activity were NOT RUN.

## Rollback and lifecycle

Disabling telemetry restores the W4-001/W4-002 business behavior while
preserving authorization, guardrails, budgets, approval and tool restrictions.
Configuration/test rollback and automated cleanliness passed. Operational
release/deployment/cloud rollback and operational/cloud teardown remain NOT
RUN because no service, collector, container or cloud resource was created.

## Deferred work and revisit conditions

W6-06 owns collector image/version selection, external exporters, CloudWatch,
X-Ray, Prometheus, Grafana, Jaeger, dashboards, alerts, retention, sampling,
SLOs and production operations. Revisit this ADR only through a governed
decision if propagation trust, content policy, capacities, processors,
exporters, residency, retention or production lifecycle requirements change.

## Evidence links

- [W4-003 aggregate evidence](../test-evidence/W4-003.md)
- [W3-09 telemetry evidence](../test-evidence/W3-09-telemetry.txt)
- [W4-08 trace evidence](../test-evidence/W4-08-trace.json)

## Final Owner Approval — W4-003 Closure

- Prompt/task ID: `W4-003` / `ADR-008`
- Reviewer and role: Gyan Prakash Rai, Project Owner and Final Approval Reviewer
- Owner decision and date/timezone: **FINAL APPROVAL AFTER OWNER TEST — APPROVED**;
  `2026-08-30 16:20:21 SGT`
- Final status and documentation review: **APPROVED — ADR-008 CLOSED UNDER
  W4-003 COLUMN N**. Approved as one of all nine manifest documents.
- Code review status: The already approved default-off, manual and bounded
  OpenTelemetry contract is accepted without expanding runtime or deployment
  scope.
- Owner-executed test status: The recorded W3-09, W4-08, regressions, complete
  suites, rollback, teardown and residue checks passed after preserved bounded
  remediations. Open FAIL results: none.
- Warnings, risks, gaps and limitations: All recorded items are accepted with
  no additional silent acceptance, including Starlette/httpx and CRLF
  warnings, drop-oldest trade-offs, local/fake evidence and unproven collector,
  external export, production monitoring, retention, SLO and cloud readiness.
- NOT RUN/INDETERMINATE reconciliation: Every NOT RUN activity remains NOT
  RUN, including 7 skips, 4 deselections, Python 3.11, live integrations,
  collector runtime, deployment and operational/cloud lifecycle work. The
  historical access-denied Gate 1 listener inspection remains a non-test
  INDETERMINATE result; remaining open INDETERMINATE: None.
- Deployment, rollback, teardown and residual resources: No local service,
  production or cloud deployment occurred. Configuration/test rollback and
  automated cleanliness/zero residue passed. Operational deployment/cloud
  rollback and teardown were NOT RUN because no such resource was created.
  Intended repository implementation, tests and documents remain retained.
- Deferred actions and owner: All deferrals remain open; responsible owner is
  Gyan Prakash Rai unless another owner is explicitly recorded.
- Conditions and next-task handover: Preserve every recorded classification,
  warning, limitation and deferral; close all nine documents together; only
  the owner changes Excel/Git; W6-06 and all live/export/deployment activity
  require separate approval and evidence.
- Tracker update responsibility: Owner
