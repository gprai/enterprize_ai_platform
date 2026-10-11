# W6-004 issue and remediation register

## Purpose

This register records the material issues encountered during the W6-004
synthetic AWS/EKS lifecycle, how each issue was diagnosed, the bounded
correction that was used, and any preventive work still recommended. It is a
learning and governance record, not execution authority.

The register preserves failed, partial and superseded attempts. A later PASS
proves only the corrected operation; it does not erase the earlier failure.
Current lifecycle status remains
**INDETERMINATE_PENDING_KMS_AND_BILLING_LAG** until the delayed billing checks,
physical KMS deletion checks and Column N owner decision are complete.

## Classification

| Classification | Meaning |
|---|---|
| `RESOLVED` | The issue was corrected and the affected bounded operation passed. |
| `RESOLVED_WITH_LIMITATION` | Functional recovery passed, but a documented limitation remains. |
| `SUPERSEDED` | The failed artifact or attempt was replaced by a new identity and was not reused. |
| `OPEN_FOLLOW_UP` | Further evidence or remediation is still required. |

## Executive summary

The principal technical failures were not a single platform defect. They fell
into five families:

1. Application dependency readiness, time budgets and cloud permissions.
2. Validation coverage and telemetry correlation.
3. PowerShell, AWS CLI, Docker, kubectl and Terraform orchestration defects.
4. Rollout, rollback and teardown reconciliation timing.
5. Evidence interpretation, including false PASS prevention and native
   resource reconciliation.

The final successful path used immutable image identities, fresh operation
packages, exact saved Terraform plans, append-only evidence, explicit owner
gates and direct service APIs for final absence verification.

## Application, retrieval and model issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| APP-01 | Stage 6 synthetic retrieval and abstention returned HTTP 504 `vector_store_timeout`. | Liveness and readiness did not prove that the embedding and vector path could complete within the outer retrieval budget. The one-second operation budget was too small for cold initialization and retrieval. | Added bounded embedding warm-up before readiness, prevented readiness on warm-up failure, increased the bounded retrieval operation budget while preserving the 30-second API deadline and one-second individual OpenSearch transport timeout, added tests, and completed a new image lifecycle. | `RESOLVED` in the final image and Stage 6 PASS. | Keep dependency warm-up and end-to-end retrieval tests in release gates. Alert separately on cold-start initialization and dependency latency. |
| APP-02 | A later Stage 6 run returned HTTP 503 `vector_store_unavailable` even though direct OpenSearch reads and KNN queries worked. | Runtime OpenSearch fine-grained access control did not include all permissions required by the application adapter. | Added the exact runtime FGAC permissions, verified direct adapter retrieval, and preserved the declarative OpenSearch configuration so the live repair would survive reconciliation. | `RESOLVED`. | Test the application adapter with the runtime role, not only admin/direct OpenSearch probes. Keep FGAC configuration under source control and security tests. |
| APP-03 | Approved Nova 2 Lite invocation returned `AccessDeniedException`. | The runtime IAM role lacked the required Bedrock `InvokeModel` permission for the approved global inference profile. | Added bounded IAM statements for the approved inference profile, updated policy contracts and tests, generated and applied a one-resource saved Terraform plan, then reran the direct probe. | `RESOLVED`; approved model returned HTTP 200. | Maintain exact model and inference-profile ARN tests. Require direct allow and unapproved-model deny probes after IAM changes. |
| APP-04 | An unapproved-model denial initially returned HTTP 400 `ValidationException` instead of an IAM denial. | The test used an invalid model identifier, so Bedrock rejected the identifier before IAM authorization could be proven. | Selected a real catalogued but unapproved model, `amazon.nova-lite-v1:0`, and verified both IAM simulation and a live HTTP 403 `AccessDeniedException`. | `RESOLVED`. | Denial fixtures must be valid provider resources that are intentionally outside the allow policy. Validate catalog existence before the denial attempt. |
| APP-05 | OpenSearch write-denial probes failed with `RequestsAWSV4SignerAuth.__call__()` argument errors and an invalid `N/A` status conversion. | A Requests-specific signer was used with the urllib3 OpenSearch transport, and the exception path assumed every error carried a numeric HTTP status. | Used the signer/transport combination supported by the installed OpenSearch client and handled non-HTTP connection errors without numeric conversion. | `RESOLVED`; runtime bulk write returned HTTP 403 and no document was created. | Add a tested probe helper that pins the client, connection class and signer combination. Treat transport failure separately from an authorization denial. |
| APP-06 | OpenSearch diagnostics sometimes reported a missing endpoint. | VPC domains expose the endpoint through `DomainStatus.Endpoints.vpc`; scripts assumed `DomainStatus.Endpoint` or only an application environment variable. | Added endpoint discovery that supports the VPC endpoint map and passed the resolved host explicitly to probes. | `RESOLVED`. | Centralize domain endpoint discovery and cover public and VPC domain response shapes in tests. |
| APP-07 | Early validation proved health and authentication but left five controls as `NO_DATA`. | The initial Stage 6 Job was designed to report separate owner-run probes for runtime write denial, unrelated S3/KMS denial, unapproved model denial, telemetry reconciliation, and HPA/PDB recovery. This scope was not made explicit enough before execution. | Implemented and ran the separate bounded security, telemetry and recovery exercises, then created a final combined Stage 6 result. | `RESOLVED_WITH_LIMITATION`; Stage 6 passed, but the design caused avoidable confusion and multiple operations. | Define the complete control matrix before creating a Stage 6 package. Make required external sub-exercises first-class dependencies of the final result. Never silently accept `NO_DATA`. |
| APP-08 | A long-running in-pod denial probe appeared stuck and was interrupted. | Multiple network-denial attempts had long SDK/connect timeout behavior and were executed as one stdin-driven process without per-check progress or hard subprocess deadlines. | Terminated the stalled process, split probes, added bounded timeouts and progress output, and reran the controls. | `RESOLVED`. | Give each external call a hard deadline, emit check-start/check-end events, and run independent checks as separate bounded processes. |

## Image, registry and supply-chain issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| IMG-01 | Trivy could not scan an OCI layout path and reported an invalid Windows path ending in `E\index.json`. | The OCI-layout invocation and Windows path handling did not match the scanner's expected archive/layout input. | Scanned the supported image/archive representation and preserved the resulting Trivy and Grype JSON reports. | `RESOLVED`. | Add a Windows scanner compatibility check and use one documented artifact format for Syft, Trivy and Grype. |
| IMG-02 | Local image identity validation confused the OCI manifest digest with the OCI configuration digest. | Docker inspection output was interpreted as a configuration digest although it was the loaded manifest identity. | Distinguished manifest, configuration and archive digests explicitly and accepted only the expected identity type. | `RESOLVED`. | Use named typed fields and prohibit generic variables such as `imageDigest` when more than one OCI digest is in scope. |
| IMG-03 | ECR helper validation repeatedly failed: missing helper configuration, an empty helper error, a UTF-8 BOM in the native protocol request, and use of unsupported `ProcessStartInfo.ArgumentList`. | The command mixed Docker credential-helper configuration, manual protocol testing and Windows PowerShell/.NET assumptions. | Used a dedicated Docker configuration, native ECR helper protocol without a BOM, and Windows PowerShell-compatible process arguments. Verified the exact manifest after push. | `RESOLVED`; immutable pushes returned exact digest matches. | Provide a versioned, tested ECR publication script. Test on Windows PowerShell 5.1 and PowerShell 7. Avoid manual helper protocol construction unless it is covered by byte-level tests. |
| IMG-04 | High vulnerabilities and a Chainguard PURL namespace warning remained in the final image. | Available dependency/base-image state contained governed High findings; the scanner also warned that some OS PURLs did not match the detected Chainguard namespace. | Enforced zero Critical and zero secret findings, retained both scanner reports, documented counts, and obtained an explicit bounded MVP waiver. | `RESOLVED_WITH_LIMITATION`; findings were accepted, not fixed. | Rebuild against refreshed base/dependencies, rerun both scanners, compare deltas, and retire the waiver when patched versions are available. Investigate scanner coverage for Chainguard packages. |
| IMG-05 | ECR deletion planning first claimed a required deployed digest was absent from preservation evidence, then failed while summing a missing `size_bytes` property. | Preservation sources had different shapes and PowerShell scalar/array normalization was incomplete. | Reconciled preservation evidence, normalized image objects and sizes, then generated an exact nine-digest deletion plan. | `RESOLVED`. | Define and validate a preservation-evidence schema before teardown. Add empty, scalar and array fixtures. |

## Kubernetes deployment, resilience and rollback issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| K8S-01 | A successful rollout was initially treated as failed because three pods were observed when two were expected. | `kubectl rollout status` completed while an old pod was still terminating. | Reconciled active versus terminating pods and waited until exactly two active ready pods remained on the expected digest. | `RESOLVED`. | Evaluate owner references, deletion timestamps and ready conditions separately. Allow a bounded termination grace period after rollout completion. |
| K8S-02 | Server-side dry-run reported ownership conflicts on the Deployment image and CPU limit. | A different field manager owned the fields; CPU values `1` and `1000m` were semantically equal but textually different. | Used the intended existing field manager and verified semantic CPU quantity equality before the real apply. | `RESOLVED`. | Keep one authoritative field manager per release package and compare Kubernetes quantities semantically. Do not infer that dry-run conflicts changed live state. |
| K8S-03 | Strict-mode filters failed when `deletionTimestamp` or `ipBlock` was absent. | PowerShell property access assumed optional Kubernetes JSON fields always existed. | Used `PSObject.Properties[...]` checks and nullable normalization before filtering. | `RESOLVED`. | Route all Kubernetes JSON through shape-normalization helpers and test absent optional properties. |
| K8S-04 | Stage 6 Job existence checks raised terminating errors for an expected NotFound result. | Native stderr from `kubectl get job` interacted with `$ErrorActionPreference = 'Stop'`; expected absence was not treated as a valid state. | Captured exit code and stderr explicitly and classified NotFound as absence before creation. | `RESOLVED`. | Use a native-command wrapper that separates expected absence from command failure. |
| K8S-05 | An HPA observation loop appeared stuck and was interrupted. | The loop provided no progress output and allowed a long bounded wait. A later printout also reused the final two-replica value as the maximum. | Reran with periodic observations, recorded desired/current replicas, and separately proved scale-out to three and recovery to two. | `RESOLVED`. | Emit progress every observation, track `maxObservedReplicas` independently, and print the planned maximum wait before entering a loop. |
| K8S-06 | The first teardown command used unsupported `kubectl delete --preconditions`. | The installed kubectl version did not support that flag for the command form used. | Verified object UIDs separately, performed dry-runs, then used exact names and reconciled post-delete identity. | `RESOLVED`. | Check `kubectl version` and command help when generating scripts. Use API-supported UID preconditions through a typed client when strict atomic preconditions are required. |
| K8S-07 | Deployment deletion left one application pod temporarily, causing a partial-destroy freeze. | Pod termination lagged the Deployment deletion request. | Preserved partial-destroy evidence, ran read-only reconciliation, waited for zero pod residue, then separately deleted the namespace. | `RESOLVED`. | Use bounded wait/reconciliation between controller deletion and namespace deletion. Preserve partial state rather than retrying blindly. |
| K8S-08 | Application rollback initially used inline JSON patches that were unreliable in PowerShell. | Quoting and encoding made inline patch payloads fragile. | Used validated UTF-8 patch files with `--patch-file`, dry-ran both directions, and verified exact running digests. | `RESOLVED`. | Standardize patch-file generation with no BOM, JSON parsing and SHA-256 verification before use. |

## Terraform, policy and state issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| TF-01 | OPA rejected a valid one-resource IAM plan because Terraform represented singleton values as arrays. | Policy code assumed one JSON shape for Terraform provider-normalized IAM fields. | Updated OPA normalization and tests to accept scalar and singleton-array forms without broadening the permitted resource/action scope. | `RESOLVED`. | Maintain Terraform JSON-shape fixtures across provider versions and test policy normalization separately from policy intent. |
| TF-02 | Terraform commands were composed with `-chdir` and subcommands as one malformed argument, or with extra arguments. | PowerShell dynamic argument construction collapsed token boundaries. | Passed `-chdir=<path>` as the Terraform global argument and every subcommand/flag as a separate array element. | `RESOLVED`. | Use one tested Terraform invocation helper and assert the final argument array before execution. |
| TF-03 | Different Terraform binaries/versions and an invalid zero-byte post-state artifact caused confusion during rollback work. | Commands did not consistently bind the approved Terraform 1.16.1 executable and state output was captured incorrectly. | Bound the exact executable, removed the invalid local artifact, and regenerated/verified state evidence. | `RESOLVED`. | Record executable path and version in every plan/apply result. Reject zero-byte state or plan artifacts before proceeding. |
| TF-04 | State evidence access failed when scripts assumed `lineage`, `serial` or `NextToken` properties always existed. | Output shape differed between Terraform commands and optional AWS responses; strict mode surfaced the assumptions. | Used the correct raw state source and property-existence checks. | `RESOLVED`. | Validate command-specific schemas and avoid reusing parsers across `state pull`, `show -json` and AWS response types. |
| TF-05 | Platform destroy validation expected 82 managed resources but Terraform reported 59. | One count represented resource blocks; the other represented expanded managed instances/addresses. | Recorded and validated all three concepts separately: 59 managed blocks, 82 managed instances and 82 manifest addresses. | `RESOLVED`. | Name every count by semantic type and include module/count/for_each fixtures. |
| TF-06 | Destroy-plan validation said the OpenSearch domain was missing. | The validator compared resource identities at the wrong plan JSON level/shape. | Recovered the saved destroy plan by exact hash, normalized it correctly and passed OPA with zero findings. | `RESOLVED`. | Validate flattened module addresses from `resource_changes`; add mandatory-resource tests against a known plan fixture. |
| TF-07 | Bootstrap state was empty even though the bucket, lock table and KMS resources existed. | Bootstrap resources had drifted out of the active state while native resources remained. | Built a recoverable local bootstrap state candidate, reconciled the exact 11-resource set, applied a refresh-only plan with zero AWS changes, and verified zero post-refresh drift. | `RESOLVED`. | Periodically reconcile bootstrap state identity and retain a tested state-recovery runbook. Never proceed to platform teardown with an empty bootstrap state. |
| TF-08 | A refresh-only apply succeeded but post-checking failed because the script expected `lineage` in the wrong JSON object. | Plan JSON and state JSON were conflated. | Read lineage and serial from the updated state file and recorded the refresh-only mutation separately from AWS mutation. | `RESOLVED`. | Separate plan metadata, state metadata and apply output models. Test all post-apply assertions before owner execution. |
| TF-09 | The backend emitted a deprecation warning for `dynamodb_table`. | The S3 backend locking configuration uses a parameter deprecated in favor of native lock files. | Warning was retained; it did not invalidate the bounded lifecycle. | `OPEN_FOLLOW_UP`. | Migrate to `use_lockfile` in a separately planned backend change, test migration and recovery, and retire DynamoDB locking only after controlled validation. |

## PowerShell, CLI and evidence-processing issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| OPS-01 | `elseif` and `else` were pasted after the preceding `if` block had already executed. | PowerShell requires the full conditional chain in one parsed statement. | Supplied complete atomic script blocks/files rather than fragments. | `RESOLVED`. | Distribute commands as parse-validated `.ps1` files for multi-branch workflows. |
| OPS-02 | `.Trim()` was called on a null configured account value. | Nullable configuration was treated as mandatory without a gate. | Added null/empty checks before normalization and compared only validated values. | `RESOLVED`. | Enable strict mode in tests and include missing-environment/configuration fixtures. |
| OPS-03 | `[ref]` was used with an undeclared variable. | Windows PowerShell requires the referenced variable to exist before `TryParse`. | Initialized the variable before passing it by reference. | `RESOLVED`. | Prefer explicit parse helpers that return a value or structured failure. |
| OPS-04 | `ProcessStartInfo.ArgumentList` was unavailable. | The host used Windows PowerShell/.NET Framework, where that API is not present. | Used compatible argument construction and verified native invocation behavior. | `RESOLVED`. | Declare the supported shell/runtime and run compatibility tests on Windows PowerShell 5.1. |
| OPS-05 | `[SHA256]::HashData` was unavailable. | The static API is not available in Windows PowerShell's .NET Framework. | Used `SHA256.Create().ComputeHash(...)` or `Get-FileHash`. | `RESOLVED`. | Keep compatibility helpers for hashing, UTF-8 no-BOM writes and process execution. |
| OPS-06 | Scalar results did not expose `.Count`, and missing properties caused strict-mode failures. | PowerShell unrolls single-item collections and strict mode rejects absent members. | Wrapped collection-producing expressions in `@(...)` and inspected properties before access. | `RESOLVED`. | Require array normalization at every external JSON/file boundary and test zero/one/many cases. |
| OPS-07 | AWS CLI `file:///E:/...` parameter loading failed, and Cost Explorer JSON quoting was corrupted. | Windows URI/path handling and nested quoting crossed PowerShell/AWS CLI parsing boundaries. | Passed validated JSON content through compatible argument forms and used AWS CLI shorthand where appropriate. | `RESOLVED`. | Prefer generated JSON files plus a tested path-normalization helper, or SDK calls for complex payloads. Validate exact bytes and parsed JSON before execution. |
| OPS-08 | CloudWatch metric SEARCH queries returned zero result objects despite catalogued metrics. | Escaped expression text and broad dynamic SEARCH queries were unreliable for the desired evidence shape; expected dimensions also differed from assumptions. | Inventoried exact metric series and queried concrete namespace/metric/dimension combinations. Preserved `NO_DATA` where no datapoint existed. | `RESOLVED_WITH_LIMITATION`; collection worked, but rollback telemetry remained partial. | Generate metric queries from live inventory and validate dimension contracts at emission time. |
| OPS-09 | UTF-8 box-drawing characters appeared as `Γò╖` and similar text. | Console/code-page and process-output encodings were inconsistent. | Set code page 65001 and UTF-8 input/output encodings. | `RESOLVED`. | Set encoding at script entry and prefer machine-readable `-json`/`-no-color` outputs for evidence. |
| OPS-10 | Some wrappers printed a final `...RESULT=PASS` after a command had failed, or an `else` was pasted as a separate statement. | Result printing was not structurally tied to the process exit code and blocks were executed piecemeal. | Captured exit codes immediately and emitted PASS only inside the same validated success path. | `RESOLVED`. | One script should own execution, classification and exit. Add a test that injected failures cannot print PASS. |
| OPS-11 | `ModuleNotFoundError: No module named 'tools'` occurred during source-template validation. | The Python script was launched without the repository root on the module search path. | Ran the validator from the repository context/module form with the correct import root. | `RESOLVED`. | Package internal tools or use `python -m ...`; verify imports in clean-shell tests. |

## Teardown and residue issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| TD-01 | The first OpenSearch teardown attempt was incorrectly recorded as PASS even though the exact index deletion had not run. | Cleanup/reconciliation succeeded, but mutation count was zero and the result logic conflated restored temporary access with index deletion. | Appended a false-PASS invalidation, proved trust/pod cleanup, created a fresh retry plan, then deleted the exact index and three documents. | `RESOLVED`. | PASS requires a positive deletion acknowledgement plus post-delete absence and a nonzero expected mutation count. |
| TD-02 | OpenSearch teardown required temporary IAM trust and a connectivity pod after the application namespace had been removed. | The private VPC endpoint was not reachable from the owner workstation. | Used short-lived bounded trust and a temporary in-cluster pod, deleted the exact index, removed the pod and restored the original trust. | `RESOLVED_WITH_LIMITATION`. | Provide a pre-approved private administrative path for teardown or perform exact index cleanup before deleting the application namespace, while retaining least privilege. |
| TD-03 | S3 archive failed because the assumed runtime role lacked `s3:GetObjectVersion`. | Current-object read permission did not grant exact historical version access. | Stopped before deletion, added a temporary exact-resource `GetObjectVersion` policy, archived and hashed all ten versions, restored trust, removed the policy and deleted only the inventoried version IDs. | `RESOLVED`. | Include exact version-read requirements in the teardown access plan and test them before the archive window. |
| TD-04 | S3 retry planning initially invoked `aws` without a command and later failed on a scalar `.Count`. | A helper parameter named `Args` conflicted with PowerShell's automatic `$args` semantics, followed by incomplete collection normalization. | Renamed the parameter, normalized arrays and amended the existing script rather than proliferating retry files. | `RESOLVED`. | Use descriptive parameter names, PSScriptAnalyzer rules and zero/one/many fixtures. Amend versioned scripts with hashes instead of creating one file per trivial correction. |
| TD-05 | State cleanup partially completed before the operation deadline. | Exact S3 version deletion completed, but the remaining DynamoDB checksum deletion required a recorded resume. | Preserved partial evidence, issued a bounded resume tied to the same exact plan, deleted only the remaining checksum item and verified zero residue. | `RESOLVED`. | Estimate mutation-window duration, checkpoint each exact target and design resumable idempotent phases before execution. |
| TD-06 | Immediate residue verification reported 15 tagged resources and one cost-bearing resource after Terraform destruction. | Resource Groups Tagging API entries were stale and one ENI record was already absent in EC2. | Queried native EC2 APIs, proved zero live resources and appended a reconciled result while retaining the initial FAIL. | `RESOLVED`. | Treat tagging APIs as discovery hints, not final existence proof. Final residue classification must use each service's native API. |
| TD-07 | KMS keys remained after teardown. | AWS KMS enforces scheduled deletion; immediate physical removal is not available. | Recorded both keys as expected `PendingDeletion` residuals with exact deletion dates. | `OPEN_FOLLOW_UP`. | Run native KMS absence checks after both scheduled deletion timestamps and preserve the result before final closure. |
| TD-08 | Immediate Cost Explorer result was USD 0 but final cost remained indeterminate. | AWS billing records can arrive after resource deletion. | Scheduled 24-, 48- and 72-hour read-only billing checks and retained the USD 20 lifecycle ceiling. | `OPEN_FOLLOW_UP`. | Complete all scheduled checks, reconcile late charges and retain `INDETERMINATE` until the final window closes. |

## Governance and decision issues

| ID | Observed issue | Root cause or diagnosis | Applied solution | Outcome | Future prevention |
|---|---|---|---|---|---|
| GOV-01 | The owner reasonably assumed Stage 6 tested every listed control, while five were emitted as `NO_DATA`. | The split between the Job and separate exercises was not presented as an owner decision before execution. | Stopped treating `NO_DATA` as acceptable closure and completed the additional exercises. | `RESOLVED`. | Present the complete test matrix, execution location and expected classifications for owner review before mutation. |
| GOV-02 | Repeated command corrections reduced confidence and consumed owner time. | Commands were composed incrementally without enough offline parsing, compatibility and fixture validation. | Shifted toward saved scripts, syntax checks, SHA-256 identities, exact command arguments and preflight gates. | `RESOLVED_WITH_LIMITATION`. | Productize recurring lifecycle scripts, add Pester tests and run them in a Windows PowerShell 5.1 compatibility job before owner handoff. |
| GOV-03 | Earlier failed Jobs, packages and plans risked accidental reuse. | Immutable identities remain visible even after failure and can look operationally convenient. | Created fresh Stage 5/6 identities, fresh saved plans and explicit consumed/superseded evidence. | `RESOLVED`. | Encode one-time consumption and expiry in artifact schemas and reject reused operation identities automatically. |
| GOV-04 | Temporary model invocation logging could capture unrelated calls. | Bedrock invocation logging is account/Region scoped. | Enabled it only for a short synthetic window, used synthetic prompts, preserved required evidence and disabled logging afterwards. | `RESOLVED_WITH_LIMITATION`. | Prefer workload-scoped transcript capture and request-ID correlation. Require a time-bound owner decision before any future provider-level payload logging. |

## Required future remediation backlog

The following work is recommended after W6-004 closure and requires its own
scope and approval:

1. Productize the PowerShell lifecycle tooling with Pester tests covering
   Windows PowerShell 5.1, PowerShell 7, zero/one/many JSON shapes, optional
   properties, native stderr and argument boundaries.
2. Add one authoritative command runner for AWS CLI, kubectl, Docker and
   Terraform that captures stdout, stderr, exit code, tool version and elapsed
   time without permitting a failed command to emit PASS.
3. Migrate the Terraform S3 backend from deprecated `dynamodb_table` locking
   to `use_lockfile` through a separately reviewed recovery-tested plan.
4. Add live golden-set evaluation, production-like identity testing and
   statistically meaningful SLO windows before any production-readiness claim.
5. Close accepted image High findings and the Chainguard scanner-coverage
   warning through a new build/scan cycle when fixes are available.
6. Improve Bedrock request-ID propagation and model-invocation-log correlation
   without retaining real prompt/response payloads.
7. Generate CloudWatch metrics with stable, documented dimensions and include
   a pre-rollback datapoint/alarms readiness gate.
8. Complete the scheduled billing checks, post-deletion KMS checks and Column N
   owner decision without changing historical classifications.

## Related records

- [W6-004 lifecycle evidence](../test-evidence/W6-004.md)
- [W6-004 learning review](../learning/W6-learning-review.md)
- [W6-004 application rollback](../rollback-records/W6-application.md)
- [W6-004 infrastructure rollback](../rollback-records/W6-infrastructure.md)
- [W6-004 teardown record](../deployment-records/W6-destroy-plan.md)
- [W6-004 lifecycle runbook](../deployment-records/W6-lifecycle-runbook.md)
- [W6-004 gap analysis](W6-004-gap-analysis.md)

## Final Owner Approval

- Documentation status: **PREPARED FOR OWNER REVIEW**.
- Lifecycle status: **INDETERMINATE_PENDING_KMS_AND_BILLING_LAG**.
- Production readiness: **NOT ESTABLISHED**.
- Column N: **PENDING**.
- Tracker update responsibility: **Owner**.
