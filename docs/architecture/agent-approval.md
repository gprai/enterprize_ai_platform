# W4-002 agent approval architecture

## Business purpose

Consequential actions must require trusted, durable human approval. This architecture ensures that authentication, operation authorization and human approval remain separate controls and that a model proposal never grants authority.

Only an artificial mock write is implemented. There is no real external write action, production approval service or production identity integration.

## Trusted boundary and roles

Transport JSON cannot provide tenant, subject, role, authorization, approver status or request ID. The API consumes the existing trusted `AuthContext` and authorizes before controller, graph, gateway, approval-store or tool activity.

- Read requester: trusted same-tenant `READER`.
- Mock-write requester: trusted same-tenant `ADMIN`.
- Approver: trusted same-tenant `REVIEWER` and a different subject from the requester.
- `ADMIN` does not imply `REVIEWER`.
- No role grants cross-tenant authority.

The graph’s `authorize` node revalidates the immutable authorization reference as defense in depth. Denial occurs before evidence, persistence or tool side effects.

## Start, decide and execute flow

1. **Start:** the server creates UUIDv4 request and run identifiers. Trusted authority is validated before the bounded graph starts.
2. **Propose:** the immutable registry validates the exact tool name, version and strict arguments. The only mock write is `mock_set_service_mode` v1.0 with `{"mode":"maintenance"}`.
3. **Persist pending approval:** the application store creates a server-generated UUIDv4 approval ID and binds the request, run, tenant, requester, authorization reference, exact tool/version and canonical argument fingerprint. Approval TTL is ten minutes.
4. **Human decision:** a different same-tenant `REVIEWER` submits the exact approval ID, UUID idempotency key and approved tool contract. The server rejects changed arguments, changed tool identity, self-approval, cross-tenant approval and unauthorized roles.
5. **Approve and claim:** expected revision and expected status checks atomically transition `pending` → `approved` → `executing`. Only one concurrent claimant can succeed.
6. **Execute:** the mock tool returns a simulated local outcome only. It creates no service, configuration, external, production or cloud mutation.
7. **Finish:** success records `consumed` and a safe result reference. Any uncertain failure after claim records `execution_unknown`; no retry or repeated action is allowed.

## Approval binding and lifecycle

The canonical fingerprint covers the request context, requester reference, exact tool version, normalized arguments and idempotency identity. Object-key reordering preserves the fingerprint; altered values do not. Identity values are hashed and pseudonymous, not anonymous.

Approved lifecycle states are `pending`, `approved`, `rejected`, `expired`, `cancelled`, `executing`, `consumed` and `execution_unknown`. Rejection and expiry are terminal. Missing, altered, replayed, consumed, cross-tenant, self-approved or unauthorized records fail closed. Cancellation propagates, starts no replacement work and releases capacity in `finally`.

## Safe outcomes and disclosure controls

The API returns only approved safe outcomes and references. It does not return raw prompt, evidence, answer, tool output, state, credentials, PII, exception text, provider envelope, stack trace or chain-of-thought. Store corruption, version mismatch or unavailability maps to a safe unavailable result. Replay and approval conflicts map to the approved conflict result.

## Owner evidence

The focused approval/API/security scope passed 46 tests with the accepted Starlette warning. Persistence, schema and redaction tests passed 17 tests. Rollback and cleanliness tests passed after the historical rollback failure was remediated. The complete ordinary rerun passed 613 tests, with 7 skipped and 4 deselected remaining NOT RUN.

Historical TEST-001 failures remain visible: one Ruff diagnostic, four MyPy errors across two files, a rollback-test failure, a protected-regression failure and two complete-suite stale-consumer failures. All had separately approved remediation and passing reruns. Open FAIL and INDETERMINATE results: none.

## Security, limitations, cost and lifecycle

Ordinary tests used deterministic fakes, synthetic inputs and temporary local stores. No live identity, external approval service, real write, network, model/provider, Qdrant, cloud or deployment activity occurred. Provider/cloud cost was USD 0; local CPU, disk, memory, owner time and workstation cost were not monetized.

The evidence does not prove production identity, production data governance, real write safety, provider behavior, performance, availability, deployment or cloud readiness. Python 3.11 execution remains NOT RUN. W4-09 and W4-10 remain NOT RUN.

Disabling both flags is configuration rollback and passed automated testing. Purging terminal records is cleanup. Operational release/deployment rollback and operational teardown are NOT RUN. Temporary store artifacts reached zero residue; the intended implementation and test files remain retained.

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
- Accepted warnings, risks, evidence gaps and scope limitations: All items recorded in the approved W4-002 Column M manifest are accepted; no additional item is silently accepted. This includes one Starlette `httpx` TestClient deprecation warning, deterministic local/fake-only evidence, pseudonymous hashes, Python 3.11 not being executed, and unproven production identity, live provider/model/vector integration, performance, capacity, SLO, deployment and cloud readiness.
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
