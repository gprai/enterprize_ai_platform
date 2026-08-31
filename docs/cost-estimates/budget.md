# W4-002 execution and cost budget

## Business purpose

The W4-002 budget prevents loops, retry storms, unbounded queues and unapproved provider spend. It is a hard local control contract, not a production capacity plan or service-level objective.

## Approved limits

| Control | Exact limit |
|---|---:|
| Maximum graph steps | 8 |
| Maximum tool calls | 1 |
| Maximum provider attempts | 1 |
| Maximum total tokens | 4,096 |
| Graph retries | 0 |
| Agent deadline | 25 seconds |
| Maximum serialized state | 16,384 bytes |
| Maximum concurrent agent runs | 1 |
| Agent queue capacity | 0 |
| Combined API admission maximum | 4 |

The agent deadline remains nested inside the existing 30-second W4-001 API deadline. Admission is atomic and non-waiting. Capacity is released in `finally` on success, safe terminal, exception, timeout and cancellation. Timeout or cancellation prevents new gateway, approval or tool work and creates no replacement background work.

## Cost boundary

- W4-002 paid-provider ceiling: **USD 0**.
- W4-002 maximum paid-evaluation spend: **USD 0**.
- Daily alert threshold: any non-zero paid spend.
- Owner-recorded provider/cloud cost: **USD 0**.

Local CPU, memory, disk, owner time and workstation cost were real but were not monetized and are not represented as zero. Deterministic fake timings and local concurrency tests must not be converted into production latency, throughput, capacity, SLO or cost claims.

## Tested behavior

The combined graph/tool/budget scope passed 19 tests. Budget tests covered step, provider-attempt, tool-call, token, serialized-state and deadline termination; zero retries; atomic one-run admission; cancellation; and capacity release. Complete TEST-001 passed with Ruff PASS, MyPy PASS across 95 files, focused tests PASS, 613 ordinary tests passed, platform validation PASS and zero residue PASS.

Historical failures remain visible: one Ruff diagnostic, four MyPy errors across two files, two focused-test failures in separate runs and two stale-consumer failures in the initial ordinary suite. Separately approved remediation and every required rerun passed. Seven skipped and four deselected tests remain NOT RUN. One Starlette warning is accepted. Open INDETERMINATE results: none.

## Limitations and lifecycle

Real provider/model behavior, token accounting from a live model, paid evaluation, network latency, production contention, capacity, availability, deployment readiness and cloud cost were NOT RUN and remain unproven. W4-09 and W4-10 were NOT RUN at W4-002 closure and were later completed under separate approvals and their original feature owners. The later [W4-10 local load evidence](../test-evidence/W4-10-load.json) is informational and is not a production SLO.

No network, Qdrant, tokenizer, provider/model, cloud or deployment activity occurred. Configuration rollback by disabling both agent flags passed automated testing. Operational release/deployment rollback and operational teardown remain NOT RUN. Temporary local stores and caches reached zero residue; intended source and test files remain retained.

### Final Owner Approval — W4-002

- Prompt/task ID: `W4-002`
- Reviewer exact name: Gyan Prakash Rai
- Reviewer role: Project Owner and Final Approval Reviewer
- Exact approval decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
- Approval date and time/timezone: `2026-08-29 14:50:21 SGT`
- Final status: **APPROVED FOR USER TRACKER UPDATE — W4-002**
- Code review status: Approved within the bounded, owner-tested W4-002 implementation boundary of 22 CREATE, 20 UPDATE and 0 DELETE paths. This approval does not establish production or cloud readiness.
- Documentation review status: Approved. All 11 documents in the W4-002 Column M manifest are closed together.
- Owner-executed test status: **PASS with one accepted warning** within the deterministic local and fake-only scope. Ruff passed; MyPy passed across 95 source files; focused functional, security, rollback and cleanliness tests passed; the complete ordinary suite finished with 613 passed, 7 skipped and 4 deselected; platform validation, configuration rollback, automated rollback, cleanliness, zero unexpected runtime residue, final whitespace and final path-boundary checks passed. The 7 skipped and 4 deselected tests remain NOT RUN.
- Accepted warnings, risks, evidence gaps and scope limitations: All items recorded in the approved W4-002 Column M manifest are accepted; no additional item is silently accepted. This includes one Starlette `httpx` TestClient deprecation warning, deterministic local/fake-only evidence, pseudonymous hashes, Python 3.11 not being executed, and unproven production identity, live provider/model/vector integration, performance, capacity, SLO, deployment and cloud readiness. Provider/cloud cost was USD 0; local owner and workstation costs were not monetized.
- Historical FAIL facts and successful remediation: Preserved. The initial Ruff run had one S105 diagnostic; the initial MyPy run had four errors across two files; separate focused runs had one rollback-test failure and one protected-regression failure; and the initial ordinary suite had two stale-consumer failures. Each received separately owner-approved bounded remediation and a passing rerun. Open FAIL results: none.
- NOT RUN and INDETERMINATE activities: All NOT RUN activities remain NOT RUN and none is converted to PASS. This includes the 7 skipped tests, 4 deselected tests, W4-09, W4-10, Python 3.11 execution, live model/Qdrant/tokenizer/network/cloud integrations, service or production deployment, and operational lifecycle work. Every historical INDETERMINATE result remains preserved; remaining open INDETERMINATE activities: None.
- Deployment facts: Local service startup, local deployment, production deployment and cloud deployment were NOT RUN; no service, container or cloud resource was created.
- Configuration-rollback and operational-rollback facts: Configuration rollback for both agent flags and automated rollback tests passed. Operational release, deployment and cloud rollback were NOT RUN.
- Cleanup, teardown and residual-resource facts: Automated cleanliness and zero unexpected runtime residue checks passed. Operational service, container and cloud teardown were NOT RUN because no such resources were created. The approved long-lived SQLite path was not created; temporary database, journal, WAL, shared-memory and lock artifacts reached zero residue. Intended implementation, test and documentation artifacts remain retained project resources.
- Deferred actions and responsible owners: All deferred actions recorded in the W4-002 manifest remain open. Responsible owner: Gyan Prakash Rai, unless another owner is explicitly recorded for an individual action. W4-09 remains deferred until W4-08; W4-10 remains owned by API-001 and NOT RUN; live integrations, telemetry, Python 3.11 execution, production validation, deployment and cloud lifecycle work require separate approval and evidence.
- Conditions attached to approval: Preserve all PASS, FAIL, NOT RUN, INDETERMINATE, warning, risk, limitation, deferred-work and residual-resource facts; close every W4-002 Column M manifest document together; only the owner updates Excel and performs Git mutation; do not infer production or cloud readiness from local, fake, mocked or injected evidence.
- Next-task handover: The locally tested W4-03 through W4-07 contracts may be relied on only within their recorded evidence boundary. W4-08/W4-09, W4-10 and all live, production, deployment or cloud work remain governed future activities requiring separate approval and evidence.
- Tracker update responsibility: Owner

Column N closed this document together with all 11 documents in the W4-002 Column M manifest; no partial closure occurred.
