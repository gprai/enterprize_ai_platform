# W3 cited-RAG rollback record

## Document control

| Field | Recorded value |
|---|---|
| Prompt/task ID | `W3-ROLLBACK-001` |
| Tracker step | `W3-11` |
| Implementation label | `W3-004` |
| Evidence owner and command executor | Gyan Prakash Rai |
| Evidence scope | Owner-executed, deterministic local rollback drill |
| Column M status | Owner reviewed; complete documentation closed under Column N |
| Final approval status | FINAL APPROVAL AFTER OWNER TEST — APPROVED |

## Business outcome

The owner demonstrated that the cited-RAG evaluation identity can be changed from the approved known-good state to a controlled synthetic regression and then atomically restored. The drill detected the exact expected Q1 and Q2 citation regression, prevented that regressed state from being release eligible, restored the approved identity, reproduced absolute and baseline-comparison PASS, retained a redacted rollback record externally, and removed all repository-local drill residue.

This is local deterministic recovery evidence. It is not evidence of deployment, production traffic switching, live-model recovery, cloud rollback or disaster recovery.

## Controlled identities

| Identity | SHA-256 | Result |
|---|---|---|
| Known-good identity | `cbf38703443dc1af3eda4e9cf8713ed8707329be557631388b113d113d6422b6` | Validated and restored |
| Synthetic-regression identity | `2472debac2e32c1bf77d37144c92cd3fae455ee97f71a5d3ba984b0cf931efb2` | Validated and used only for the controlled drill |
| Approved W3-002 baseline | `4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f` | Protected and unchanged |
| Candidate report | `f259784666c180145c4dbb0f4757fbac2505eba059c6ee06510c6906cb3546cf` | Protected and unchanged |
| Repeat report | `d35c1ee13a54cda78e7514a84cd9af6e6086236a4095f7824f52cdbc46d2da1a` | Protected and unchanged |
| Golden dataset | `809aac88f84dd44aeb96c676f3bad229164a0767c6fc9d0ebeeb01b6823c06c2` | Protected and unchanged |
| Evaluation configuration | `4564b1935c1c072281f90a63c1ac80315709e35e6aab8e0803d0a9abf5c189df` | Protected and unchanged |
| RAG configuration | `5cb62932bbc0a0c11e494912bdcc5b4b48bd4195e3ca58bda2df27227070b27e` | Protected and unchanged |

## Owner-executed lifecycle results

| Stage | Result | Evidence |
|---|---|---|
| Identity validation | PASS | Both immutable identities validated. |
| Initialize State N | PASS | Known-good activated at generation 1. |
| Activate State N+1 | PASS | Synthetic regression activated at generation 2. |
| Detect controlled regression | PASS | Evaluation correctly produced absolute, baseline-comparison and overall `FAIL`; `release_eligible=false`. |
| Q1 and Q2 fail-closed behavior | PASS | Both returned `ABSTAINED` with `invalid_generated_citation`, one provider call, zero returned citations and retained valid usage. |
| Atomic rollback | PASS | Known-good restored at generation 3. |
| Restored evaluation | PASS | Absolute, baseline-comparison and overall statuses were `PASS`; `release_eligible=true` within the deterministic local baseline scope. |
| Finalize rollback record | PASS | Redacted final record reported `final_status=PASS`, zero unexpected residue, no network activity and USD 0 provider cost. |
| Pre-archive cleanliness | PASS | Four approved runtime artifacts and zero unexpected residue. |
| External archive | PASS | Four byte-identical artifacts copied outside the repository and verified by SHA-256. |
| Repository-local cleanup | PASS | Approved artifact count 0 and status `ZERO_RESIDUE`. |
| Independent zero-residue check | PASS | Local runtime absent; cache or temporary residue count 0. |

The regression report SHA-256 is `d5a73ee86133f157a15018eb58d76cb681c1ab7a1a5ae04673363eeb5229b5f5`. The restored report SHA-256 is `2ad028bb0ff74dc41a0911ddf00227d39f8eef6d7db953d88b6223d3132123b8`.

## External evidence archive and residual resources

The owner-controlled external archive is `E:\AI\Enterprise_AI_Doc_Retrieval\reports\w3-004`. It is outside the repository and contains exactly:

| Artifact | SHA-256 |
|---|---|
| `active.json` | `8c43a947577857c8b308aa99b2cbc1cc8a4e7507ba12c0fc3e420f7d22612d78` |
| `regression.json` | `d5a73ee86133f157a15018eb58d76cb681c1ab7a1a5ae04673363eeb5229b5f5` |
| `restored.json` | `2ad028bb0ff74dc41a0911ddf00227d39f8eef6d7db953d88b6223d3132123b8` |
| `rollback-record.json` | `d92a16556f8a2e725b9a5a98b376bd5ec471a96761a4d3cbf6b3843818c34741` |

The owner will retain this external evidence for 180 days and then owns its deletion. The external Python virtual environment, approved W3-002 baseline, candidate report and repeat report remain intentionally retained. The repository-local `reports/w3-004` runtime is absent. No service, container, model, credential, cloud resource, cache, bytecode or drill temporary file remains from this drill.

## Deployment, rollback and teardown boundaries

- Local or production deployment: **NOT RUN**.
- Local deterministic identity rollback: **PASS**.
- Application/source, deployment, live-provider and cloud rollback: **NOT RUN**.
- Repository-local drill teardown and zero-residue verification: **PASS**.
- Docker, service and cloud teardown: **NOT RUN** because none was started or created for this drill.
- Network, AWS, Bedrock, vendor guardrail, live-model and paid-provider activity: **NOT RUN**; the finalized record reports network activity `false` and provider cost USD 0.

## Warnings, risks, evidence gaps and limitations

- The evidence is deterministic, synthetic and local; it does not prove production recovery time, recovery point, availability, capacity, latency or live-model behavior.
- `release_eligible=true` after restoration means the approved local evaluation contract passed; it is not production release approval.
- The Starlette/FastAPI TestClient deprecation warning remains unresolved and its remediation was **NOT RUN**.
- Seven owner-controlled tests were skipped and four opt-in tests were deselected; they remain **NOT RUN**.
- Historical Ruff, MyPy and security-test failures were corrected and passed on rerun; they are not erased by the final PASS.
- One initial report-inspection field was INDETERMINATE because the command read the wrong JSON level; the corrected owner check returned `ABSOLUTE=FAIL`. Remaining open INDETERMINATE activities: none.
- One initial archive-inventory display operation failed because Windows PowerShell lacked `Join-String`; the compatible rerun passed and did not change state.
- No build, package, pre-commit, vulnerability scan, software bill of materials or production compliance validation was supplied for this task.

## Deferred actions and ownership

- Gyan Prakash Rai owns the 180-day external archive retention and later deletion.
- Live-provider, AWS/Bedrock, performance, production security/privacy/residency, deployment and cloud lifecycle validation require separate approval and evidence.
- Final documentation approval, tracker reconciliation and Git staging/commit/push remain owner-controlled.

## Final Owner Approval

- Prompt/task ID: `W3-ROLLBACK-001`
- Reviewer: Gyan Prakash Rai
- Reviewer role: Project Owner and Final Approval Reviewer
- Owner decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
- Approval date and time/timezone: `2026-08-27 17:31:21 SGT`
- Final status: **APPROVED FOR USER TRACKER UPDATE — W3-ROLLBACK-001**
- Code review status: **APPROVED** for the bounded, owner-tested W3-004 implementation; no production or cloud approval is implied.
- Documentation review status: **APPROVED**; all four W3-ROLLBACK-001 Column M documents are closed together.
- Owner-executed test status: **PASS within the recorded deterministic local scope**. Final Ruff, strict MyPy, focused and ordinary suites, platform validation, controlled regression, atomic restoration, archive verification and zero-residue checks passed. Historical FAIL and INDETERMINATE results remain recorded.
- Accepted warnings, risks, evidence gaps and limitations: all items recorded in the approved W3-ROLLBACK-001 Column M manifest are accepted; no additional item is silently accepted. Local/synthetic scope, the Starlette/FastAPI warning, skipped and deselected work, unperformed scans and production/live-system limitations remain visible.
- NOT RUN and INDETERMINATE: all recorded NOT RUN activities remain NOT RUN and none is converted to PASS. Every historical INDETERMINATE result remains preserved. Remaining open INDETERMINATE activities: None.
- Deployment: local, cloud and production deployment remain **NOT RUN**.
- Rollback: local deterministic identity rollback **PASS**; application/source, deployment, live-provider and cloud rollback remain **NOT RUN**.
- Teardown: repository-local drill cleanup and independent zero-residue verification **PASS**. Docker, service and cloud teardown remain **NOT RUN** because no such resource was started or created.
- Residual resources: repository-local `reports/w3-004` is removed. The four-file owner-controlled external archive is retained for 180 days; the approved W3-002 baseline and reports and external Python virtual environment remain retained. No service, container, model, credential, cloud resource, cache, bytecode or drill temporary file remains from the drill.
- Deferred actions and responsible owner: all recorded deferrals remain open under Gyan Prakash Rai unless another owner is explicitly recorded. Gyan Prakash Rai owns archive retention and later deletion, future live/production validation, tracker reconciliation and Git mutation.
- Conditions: preserve every PASS, FAIL, NOT RUN, INDETERMINATE, warning, risk, limitation, deferral and residual-resource fact; infer no production or cloud readiness from local, fake, mocked, injected or synthetic evidence; only the owner updates Excel or mutates Git.
- Next-task handover: future work may rely on the approved deterministic local rollback contract and protected W3-002 identities. Deployment, live-provider recovery, production performance/security/privacy/residency and cloud lifecycle require separate approval and evidence.
- Tracker update responsibility: Owner
- Column N reconciliation: this document, `docs/test-evidence/W3-004.md`, `docs/test-evidence/W3-11-rag-rollback.txt` and `docs/test-evidence/README.md` closed together; no partial closure.
