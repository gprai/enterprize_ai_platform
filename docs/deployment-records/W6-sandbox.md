# W6-004 AWS/EKS sandbox lifecycle

## Business outcome

The project deployed the synthetic enterprise AI sandbox into account
`526338061652` in `ap-southeast-1`, verified the integrated application and
its security and observability controls, exercised bounded resilience and
rollback, and subsequently removed the project-owned resources.

The sandbox proof is **PASS within its recorded non-production scope**. It is
not production readiness and does not override the remaining billing and KMS
tails.

## Final live composition

- EKS application: two ready replicas of application digest
  `sha256:efaafe47204afbd4a092f675f3a60fc3575abad288e89e8f73692b053d22dd55`.
- Collector digest:
  `sha256:d0a012252142c0999982fc34cddc88e2f9ce8c6b2bdf2c53e8e489a49dfbac31`.
- Release package: `stage5-recovery-009`.
- Stage 6 package: `stage6-live-009`.
- Bedrock model: `global.amazon.nova-2-lite-v1:0`.
- OpenSearch index: `enterprise_ai_sandbox` with synthetic records only.
- Workload identity: EKS Pod Identity; no static AWS credentials.
- Telemetry: X-Ray, CloudWatch metrics/logs and SNS within the approved
  synthetic sandbox boundary.

## Live validation result

Stage 6 is recorded as **PASS**. Health, authentication denials, tenant denial,
retrieval, citation, abstention, Bedrock invocation, OpenSearch/S3/KMS/model
denials, telemetry, HPA and PDB behavior were exercised. The separately
preserved transcript records one grounded synthetic question and one
nonexistent-fact abstention; it is not a transcript of every lifecycle call.

The historical W3 golden set was not rerun live. Live golden-set testing is
**NOT RUN**.

## Resilience

Stage 7 FIS experiment `EXP4kVuudab1bLqwGN` completed. It deleted exactly one
application pod and used the availability-burn and safety alarms as stop
conditions. Replacement and application recovery passed.

## Security and privacy

- Only synthetic non-production data was approved.
- Runtime OpenSearch write, unrelated S3/KMS and unapproved Bedrock model
  attempts were denied.
- The approved model was the global Nova 2 Lite inference profile; the
  regional `amazon.nova-lite-v1:0` foundation model remained unapproved.
- No static credentials were retained in images, manifests or evidence.
- Complete prompt/response retention was enabled only for the bounded
  synthetic transcript exercise and was disabled afterwards.

## Limitations

- Application and infrastructure rollback both have telemetry gaps.
- Accepted High vulnerabilities remain waived for the bounded MVP lifecycle.
- Synthetic authentication is not production identity readiness.
- Initial SLO objectives were not proven over a production-size population.
- Final billing and KMS deletion remain open.

## Final Owner Approval

- Reviewer, decision and timestamp: **PENDING COLUMN N**.
- Current status: **LIVE SANDBOX PROOF COMPLETE; FINAL CLOSURE PENDING**.
- Tracker update responsibility: **Owner**.
