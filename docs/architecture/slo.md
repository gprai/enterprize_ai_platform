# W6-002 SLO and observability architecture

## Business purpose and boundary

The W6-002 observability design makes failures visible without allowing telemetry failure to stop the business request path. It defines deployment-ready contracts for traces, metrics, safe logs, SLO evaluation, alerts, dashboards, and bounded failure response.

This architecture was validated locally. It is not evidence of live AWS/EKS operation, production SLO achievement, alert delivery, or FIS execution. W6-004 owns those live lifecycle activities.

## Producer, connection, and consumer flow

```text
Enterprise AI API and service stages
  -> strict w4-003.telemetry.v1 observations
  -> in-process bounded telemetry runtime
  -> single-worker bounded export queue
  -> loopback OTLP gRPC collector input
  -> W6-004 live binding:
       traces -> AWS X-Ray
       metrics and validated safe logs -> CloudWatch EMF/logs
       recording rules -> alerts and dashboard review
```

The existing local fallback accepts OTLP gRPC on `127.0.0.1:4317` and OTLP HTTP on `127.0.0.1:4318`, batches up to 64 observations, and writes only to the collector debug exporter. The proposed AWS collector accepts loopback gRPC on `127.0.0.1:4317`; its backend export is not active until W6-004 supplies approved identity, endpoints, retention, cost, and destination bindings.

## Schemas and compatibility

- `w4-003.telemetry.v1` remains the content-free public telemetry schema.
- `w6-002.observability.v1` records bounded evidence status, local/native-tool scope, handover target, optional artifact hash, and immutable `cloud_activity=NOT RUN` and `deployment_activity=NOT RUN` defaults.
- `w6-002.slo.v1` defines strict SLO identity, objective, rolling window, minimum population, owner, missing-data status, observations, and evaluation output.
- Unknown fields are rejected. Safe telemetry attributes use approved enumerations for stage, operation, outcome, terminal reason, safe error code, version, tool, signal, and drop reason.

## SLI populations and objectives

The review window is 30 rolling days with at least 100 eligible events. Below that threshold the result is `NO_DATA`, never PASS.

- Excluded: invalid client requests, policy denials, and planned maintenance.
- Bad: dependency failures and dependency timeouts.
- Conditionally good: an insufficient-evidence abstention only when that abstention is contractually correct.

Initial review targets are:

| Objective | Target |
|---|---:|
| Availability | 99.9% |
| API latency p95 | under 4 seconds |
| API latency p99 | under 10 seconds |
| Retrieval latency p99 | under 750 ms |
| Grounded/citation-valid answer or correct abstention | at least 95% |
| Recall@5 | at least 85% |
| Isolation | 100% |
| Safety | 100% |

These are initial review targets, not proven production SLOs. Groundedness, citation validity, recall, isolation, and safety remain release-gate SLIs rather than claims derived from the current Prometheus operational rules.

## Error budget and alerting

The error budget uses a 30-day review window and freezes release progression when exhausted. Availability burn alerts use:

- Fast burn: factor 14.4, 5-minute short window, 1-hour long window, and at least 20 short-window eligible events.
- Slow burn: factor 6.0, 30-minute short window, 6-hour long window, and at least 20 short-window eligible events.

The rule file contains three recording rules and ten alerts, for 13 native-tool-validated rules in total. Alerts cover fast and slow availability burn, p95 and p99 request latency, p99 retrieval latency, exporter failure, queue capacity drop, readiness failure, retry storm, and safety violation.

The accountable owner is Gyan Prakash Rai. The local destination is synthetic. Backup ownership and a live destination are not set. W6-004 must approve and bind the real destination before any alert-delivery claim.

## Bounded concurrency and failure behavior

- Queue capacity: 512 safe log records.
- Batch size: 64.
- Export delay: 1 second.
- Sink export timeout: 1 second.
- Force-flush timeout: 2 seconds.
- Worker shutdown timeout: 2 seconds.
- Worker count: one daemon worker.
- Capacity behavior: drop the oldest queued record and record a capacity drop.
- Export failure behavior: record a telemetry export failure; do not retry the business operation and do not let sink exceptions escape into business flow.
- Shutdown behavior: stop accepting records, perform bounded flush, signal the worker, join within the timeout, and shut down the sink.
- Rollback profile: exporter `none`, no OTLP endpoint, queue capacity 0, background workers 0, and a null telemetry runtime.

The proposed AWS collector separately bounds memory, queueing, retries, batching, and export duration: 128 MiB limit, 32 MiB spike allowance, batch size 64, one-second batch/export timing, queue size 512 with one consumer, and retry elapsed time capped at 30 seconds.

## Security, privacy, residency, and cost

- Logs and metric labels contain only approved low-cardinality metadata. Prompt, answer, evidence, tenant, credential, and narrative content are prohibited.
- Trace and span identifiers must be paired; token counts must be complete and internally consistent; numerical durations must be finite.
- Proposed AWS traffic requires private endpoints and EKS Pod Identity with least privilege. Static AWS credentials are prohibited.
- Proposed AWS Region: `ap-southeast-1`.
- Proposed CloudWatch namespace: `EnterpriseAI/Sandbox`.
- Proposed application log group: `/aws/enterprise-ai-platform/sandbox/application` with 14-day retention.
- Live retention approval remains required; no separate X-Ray retention fact is established by W6-002.
- No live resource may be created without fresh pricing coverage and an explicit owner cost cap. W6-002 has no cloud cost authority.

## Dashboard and operational review

The provider-neutral Grafana dashboard contains eight panels: eligible-request availability, request p95, request p99, retrieval p99, telemetry drops, exporter failures, readiness, and safety violations. It is immutable configuration and was not deployed. CloudWatch dashboard generation and deployment remain W6-004 work.

## Failure rehearsal and FIS boundary

The local plan inventory covers OpenSearch unavailable/timeout, Bedrock timeout/throttle, exporter outage/saturation, readiness failure, and retry storm using fake providers. The focused W6-002 test directly demonstrates that exporter failure does not escape the business flow; the remaining entries are validated plan inputs and existing local regression concerns, not live-provider evidence.

The AWS FIS plan is not executable authority. It is limited to one EKS pod-delete target for at most 300 seconds, requires project/environment tags, includes availability-burn and safety stop alarms, and aborts on any alarm, excess target count, or excess duration. Execution and cost authority belong to W6-004.

## Handover and limitations

- W6-003 must confirm application composition and production of `enterprise_ai_readiness`, `enterprise_ai_dependency_attempts_total`, and `enterprise_ai_safety_violations_total` alongside the established stage metrics.
- W6-004 must bind private AWS endpoints, Pod Identity/IAM, X-Ray, CloudWatch, retention, alert delivery, dashboards, cost controls, and any approved FIS experiment.
- W6-004 must provide live tests, operational rollback, complete teardown, native AWS/Kubernetes residue checks, and delayed billing/cost verification.
- Until those tasks complete, deployment, live integration, production SLO achievement, operational rollback, and cloud teardown remain **NOT RUN**.

## Final Owner Approval

- Prompt/task ID: `W6-002`.
- Reviewer: **Gyan Prakash Rai**.
- Reviewer role: **Project Owner and Final Approval Reviewer**.
- Owner decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED**.
- Approval date and time/timezone: **2026-10-02 01:06:00 SGT**.
- Final status: **APPROVED FOR USER TRACKER UPDATE — W6-002** within the documented local deployment-readiness boundary.
- Code review status: **APPROVED** for the bounded W6-002 implementation; the architecture remains a locally validated design and W6-004 input, not live-cloud evidence.
- Documentation review status: **APPROVED** as one of the five documents closed together under Column N.
- Owner-executed test status: Local schema, exporter, SLO, rule, security, rollback-contract, teardown, quality, regression, and identity checks passed as recorded in `docs/test-evidence/W6/W6-002.md`; skips, deselections, warning, and historical failures remain preserved.
- Accepted warnings, risks, gaps, and limitations: All Column M items are accepted without silently accepting any additional item. Initial targets are not proven production SLOs; the live alert destination, backup owner, private endpoints, Pod Identity/IAM, final retention, pricing, cost cap, AWS integrations, and production traffic evidence remain absent.
- NOT RUN and INDETERMINATE: Live AWS/EKS export, dashboard and alert operation, FIS execution, production SLO proof, operational rollback, and cloud teardown remain **NOT RUN**. Remaining open INDETERMINATE activities: **None**.
- Deployment facts: Configuration and synthetic local composition were validated; no observability or application resource was deployed.
- Rollback facts: The local no-exporter/no-worker profile passed; operational application, Kubernetes, infrastructure, and cloud rollback remain NOT RUN.
- Teardown and residual-resource facts: Local worker shutdown and zero-residue verification passed. Promtool 3.5.0 is intentionally retained. No W6-002 cloud resource was created, and cloud teardown remains NOT RUN.
- Deferred actions and owner: W6-003 owns integrated application-readiness composition. W6-004 owns all live AWS bindings, tests, rollback, teardown, residue, and cost verification. Responsible owner: **Gyan Prakash Rai**, unless separately assigned.
- Conditions: Preserve all statuses and limitations; do not interpret local, synthetic, fake, injected, configuration, or native-tool evidence as production or cloud readiness; only the owner updates Excel or mutates Git.
- Next-task handover: The owner may update the W6-002 tracker row and initiate W6-003 separately. This approval grants no execution authority for W6-004.
- Tracker update responsibility: Owner.

## W6-004 live lifecycle addendum

W6-004 subsequently bound this design to the synthetic AWS/EKS sandbox. The
final validated application image was
`sha256:efaafe47204afbd4a092f675f3a60fc3575abad288e89e8f73692b053d22dd55`,
deployed through `stage5-recovery-009` and validated by `stage6-live-009`.
X-Ray, CloudWatch metrics/logs and SNS were exercised, and the bounded FIS
experiment `EXP4kVuudab1bLqwGN` deleted exactly one application pod with the
availability-burn and safety alarms configured as stop conditions.

This live evidence does not convert the initial review targets into proven
production SLOs. Application rollback remained
`PASS_WITH_TELEMETRY_GAP` because the alarm metrics had no datapoints and the
alarms were `INSUFFICIENT_DATA`. Infrastructure rollback remained
`PASS_WITH_TELEMETRY_GAP` because its bounded Bedrock request could not be
correlated to a model-invocation log event. The complete project-owned resource
teardown passed, while overall lifecycle closure remains
`INDETERMINATE_PENDING_KMS_AND_BILLING_LAG`.

The W6-002 architecture and owner approval above remain historical facts. This
addendum records later W6-004 execution; it does not rewrite the original local
validation boundary or claim production readiness.
