# W6-004 complete teardown record

## Result

The project-owned resource teardown is **PASS**. Overall W6-004 closure
remains **INDETERMINATE_PENDING_KMS_AND_BILLING_LAG** because two KMS keys
have not reached physical deletion and Cost Explorer requires delayed checks.

## Required order and outcome

| Stage | Exact scope | Outcome |
|---|---|---|
| 1 | Kubernetes application Deployment and `enterprise-ai-sandbox` namespace | **PASS** — no workload or namespace residue |
| 2 | Synthetic OpenSearch index `enterprise_ai_sandbox` and three documents | **PASS** — exact index absent |
| 3 | Ten versioned S3 objects under `bedrock-model-invocations/` | **PASS** — archived, hash-verified and exact versions deleted |
| 4 | Nine exact ECR image digests | **PASS** — zero remaining images; repository later removed by Terraform |
| 5 | Platform Terraform resources | **PASS** — 0 remaining managed instances |
| 6 | Thirty-six exact platform-state versions and one DynamoDB checksum item | **PASS** — state and lock residue zero |
| 7 | Bootstrap Terraform resources | **PASS** — 11 managed instances destroyed; bucket, lock table and alias absent |

## Key plan and result identities

- Kubernetes destroy-plan SHA-256:
  `af0bf055a6005e651a1c806f5b79b86dc46e05504e06a4f421552083ef7db234`.
- OpenSearch retry plan SHA-256:
  `38eed7d4b9d3141715702664858d84f2ad7f043583c1abdefd4d553482f9de7c`.
- S3 archive manifest SHA-256:
  `e09c9772a23a8f14e78f8d9370d01850613df4d09201f47aff103aa2bf965319`.
- ECR destroy-plan SHA-256:
  `a938e55380c32ae102dd9ce6ed746352d5103e0907f8ce384fee7298e8c31716`.
- Platform saved destroy-plan SHA-256:
  `aefbf532c60f82ccc0577ca6e545118730f707c2cb653668a2614cb5db122a22`.
- Bootstrap saved destroy-plan SHA-256:
  `1aef0bcf890d621e96083e2d93af5507b1d5fe79a08c3066520e67241ce24e14`.

## Failure and recovery history

The final PASS did not erase intermediate failures:

- Kubernetes preconditions were first expressed with an unsupported kubectl
  flag. The zero-mutation failure was corrected. A later Deployment deletion
  temporarily left one terminating pod; reconciliation proved pod absence
  before the separately authorized namespace deletion.
- The first OpenSearch attempt contained a false PASS. It was invalidated;
  original trust was restored and a fresh exact-index retry succeeded.
- The first S3 archive attempt lacked `s3:GetObjectVersion`. No object was
  deleted. A bounded temporary policy enabled exact-version archival, after
  which trust and policy were restored before deletion.
- Platform plan orchestration encountered Windows argument and Terraform
  resource-block/instance-count defects. The final saved destroy plan was
  recovered by exact hash and passed normalization and OPA evaluation.
- State cleanup partially completed before its deadline. The recorded resume
  deleted only the remaining DynamoDB checksum item and verified zero state
  entries.
- The initial final-residue result incorrectly treated stale Resource Groups
  Tagging API entries and a deleted ENI as live cost-bearing residue. Direct
  EC2 API checks proved zero live residue, and a new reconciled result was
  appended without rewriting the original failure.

## Exclusions

Shared and service-linked resources were not adopted or deleted. Broad S3,
registry, IAM or account-wide deletion was prohibited. Historical evidence
outside the project-owned cloud resources was retained.

## Expected tails

- Platform KMS key `41b46eac-902c-4d53-bb09-2f4a183fa268`:
  `PendingDeletion` until approximately `2026-10-17T00:34:51.498000+08:00`.
- Bootstrap KMS key `d869548f-8792-441a-a77a-3028d693e7cd`:
  `PendingDeletion` until approximately `2026-10-17T00:57:48.306000+08:00`.
- Billing: `INDETERMINATE_UNTIL_24_48_72_HOUR_CHECKS`.

## Final Owner Approval

- Reviewer, decision and timestamp: **PENDING COLUMN N**.
- Tracker update responsibility: **Owner**.
