# ADR-005 — Bounded LangGraph orchestration

## Status

Records an approved W4-002 decision. Implementation, local owner testing and
W4-002 Column N documentation approval are complete. This ADR does not newly
approve deployment, production use, live providers or cloud activity.

## Business context

The platform needs controlled agent behavior that can retrieve evidence, propose an allowlisted action and pause for human approval without turning model output into authority. The owner requires visible workflow stages, bounded resource use, deterministic failure behavior, privacy-safe persistence and configuration rollback to the approved W4-001 API surface.

## Decision

Use LangGraph 1.2.11 to express an explicit nine-node workflow:

`validate_input` → `authorize` → `retrieve` → `grade_evidence` → `answer` → `propose_tool` → `await_human_approval` → `execute_tool` → `safe_terminal` → `END`.

The graph uses `context_schema`, not deprecated `config_schema`. It compiles without a LangGraph checkpointer and without a LangGraph retry policy. Raw query text, trusted `AuthContext` and injected services remain run-scoped. Durable approval and business-control state belongs to a separate application-owned standard-library SQLite store.

The graph orchestrates steps; it does not authenticate callers, grant authorization or approve actions. Authentication and operation authorization occur before controller invocation. Trusted code revalidates authority in the graph and approval flow. A model proposal cannot create tenant, role, approver or execution authority.

## Boundaries and dependencies

- `AgentEvidenceGateway` is provider-neutral, injected and fake-only in ordinary tests. The protected W2/W3 RAG, retrieval, authorization, citation, guardrail, evaluation and provider contracts are not copied or redefined.
- The default evidence gateway fails closed. A live adapter is deferred.
- The immutable tool registry contains only `get_service_status` v1.0 and `mock_set_service_mode` v1.0.
- Application persistence uses schema `w4-002.agent-store.v1` at the approved external runtime path `E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3` when separately activated.
- `langgraph-checkpoint-sqlite`, `aiosqlite` and other new dependencies were not added.
- `agent_enabled=false` and `agent_mock_write_enabled=false` preserve the safe default.

## Drivers

- Make agent behavior reviewable as a workflow rather than an autonomous black box.
- Fail closed before retrieval or action when identity, authority, approval, storage or budgets are invalid.
- Prevent loops, retries, replay, double execution and unbounded queues.
- Keep raw protected content out of durable state.
- Preserve W4-001 `/v1/query` and disabled `/v1/agent` behavior.
- Keep provider/cloud cost at USD 0 for W4-002.

## Alternatives considered

1. **Unrestricted agent loop:** rejected because it obscures decision flow and cannot satisfy the exact step, retry, tool and concurrency bounds.
2. **Custom orchestration without LangGraph:** not selected because the approved decision calls for a typed, inspectable LangGraph graph and Mermaid parity.
3. **LangGraph checkpointer or SQLite plugin:** rejected for this boundary because durable approval is application business state and no additional dependency was approved.
4. **In-memory approval only:** rejected because restart-safe, one-time approval decisions require durable local state.
5. **External approval service or real write tool:** deferred because production identity, network, service ownership and operational risk were outside W4-002.
6. **Copy the W3 RAG pipeline into the agent:** rejected because it would split an approved producer-consumer contract and weaken source ownership.

## Consequences and trade-offs

Benefits include explicit nodes and edges, deterministic tests, safe terminal outcomes, bounded admission and clear separation between orchestration, authorization and persistence. The trade-offs are a larger typed control surface, an application-owned SQLite lifecycle, pseudonymous control records and no live integration evidence. Hashes reduce direct exposure but remain pseudonymous rather than anonymous.

The fixed linear graph relies on node-level safe termination and prevents cycles. Exact limits are eight steps, one tool call, one provider attempt, 4,096 tokens, zero retries, 25 seconds, 16,384 serialized bytes, one concurrent run, zero queue and four combined API admissions. The 25-second deadline remains inside the 30-second API deadline.

## Failure behavior and reversibility

Unknown versions, corrupt records, altered fingerprints, cross-tenant or self-approval, replay, consumed approvals, exceeded budgets, timeout and unavailable storage fail closed with safe outcomes or approved API errors. Atomic compare-and-swap permits one transition from approved to executing. No retry is allowed after that transition; uncertain completion becomes `execution_unknown`.

Configuration rollback disables both agent flags and restores the W4-001 disabled-agent surface while keeping `/v1/query` unchanged. Record purge is cleanup, not release rollback. Operational deployment, release rollback, deployment rollback, teardown and cloud lifecycle activity remain NOT RUN.

## Evidence and limitations

Owner TEST-001 finished PASS: Ruff PASS; MyPy PASS across 95 files; focused functional, security, rollback and cleanliness tests PASS; ordinary suite 613 passed with 7 skipped and 4 deselected; platform validation, whitespace, path-boundary and zero-residue checks PASS. One Starlette `httpx` TestClient deprecation warning is accepted.

Historical failures remain visible: one initial Ruff diagnostic, four MyPy errors across two files, two failed tests across separate focused runs, and two stale-consumer failures in the initial ordinary suite. Separately approved remediations and every required rerun passed. Open INDETERMINATE results: none.

No network, live identity, Qdrant, tokenizer, provider/model, deployment or cloud activity occurred. Provider/cloud cost was USD 0; local workstation and owner costs were not monetized. Python 3.11 execution, production performance, capacity, security/compliance, deployment and cloud readiness remain unproven. At W4-002 closure, W4-09 and W4-10 were NOT RUN; they were later completed under separate approvals and their original `AGENT-001` and `API-001` ownership, as recorded in [W4-09 evidence](../test-evidence/W4/W4-09-failures.txt) and [W4-10 evidence](../test-evidence/W4/W4-10-load.json).

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
