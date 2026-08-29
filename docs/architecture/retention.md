# W4-002 agent state retention and cleanup

## Business purpose

Agent checkpoints and approval records must support safe one-time decisions without becoming a store for prompts, evidence, answers, secrets or personal data. This policy records the bounded W4-002 local persistence decision and its tested cleanup behavior.

It is not a production data-governance, backup, disaster-recovery, deployment or telemetry policy.

## Store identity and location

- Store technology: Python standard-library SQLite owned by the application.
- Store schema identity: `w4-002.agent-store.v1`.
- State schema identity: `w4-002.agent-state.v1`.
- Graph identity: `w4-002.graph.v1`.
- Approved external runtime path: `E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3`.
- Approval TTL: ten minutes.
- Terminal local-record retention: 24 hours.

No LangGraph checkpointer, `langgraph-checkpoint-sqlite` or `aiosqlite` boundary was added. Runtime database, journal, WAL, shared-memory and lock files remain outside the repository.

## Persisted allowlist

Durable state is strict, frozen, extra-forbidden and size bounded. It permits only versions and revisions; server UUIDv4 request/run/approval references; hashed tenant, subject, requester, approver and authorization references; node, outcome and terminal reason; bounded SHA-256 evidence references; exact allowlisted tool identity and argument fingerprint; approval status and expiry; step/tool/provider/retry/token/elapsed counters; hashed idempotency identity; bounded redacted audit decisions; safe result references; and stable safe error codes.

At most five evidence-reference hashes and eight audit decisions are stored. Serialized state is limited to 16,384 bytes. The hashes are pseudonymous, not anonymous, and remain personal-data references when linkable.

## Excluded content

The store excludes raw query, prompt, retrieved evidence or chunks, generated answer, tool output, credentials, headers, secrets, PII, tenant content, provider envelopes, exception text, stack traces and chain-of-thought. No such content is authorized for persistence or documentation evidence.

## Canonical serialization and validation

Canonical bytes use UTF-8, sorted object keys, compact JSON separators, `ensure_ascii=False`, `allow_nan=False`, stable enum strings, aware timestamps normalized to UTC and exactly one trailing newline. SHA-256 is calculated over those exact canonical bytes.

Duplicate keys, non-finite values, invalid UTF-8, unknown fields, invalid versions, noncanonical bytes, inconsistent lifecycle fields and oversized records fail closed. Store metadata must match `w4-002.agent-store.v1`; corruption or unavailability returns a safe state-unavailable outcome rather than raw database content.

## Retention, expiry and purge

Pending approvals expire after ten minutes. Rejected, expired, cancelled, consumed and execution-unknown records are terminal. Terminal records are eligible for removal after 24 hours through an explicit bounded purge. A purge handles no more than 1,000 records per call. Purge is cleanup, not approval invalidation, configuration rollback, release rollback or operational teardown.

The 24-hour runtime policy does not authorize test residue. Ordinary owner tests used isolated temporary stores and removed the database plus associated journal, WAL, shared-memory and lock artifacts.

## Evidence and current resource state

Persistence/schema/redaction testing passed 17 tests. Automated cleanliness passed 2 tests. Final zero-residue verification and path-boundary verification passed. The approved long-lived runtime database was not created or operationally exercised. Intended source and test files remain retained project artifacts; unexpected runtime residue is zero.

Historical failures elsewhere in TEST-001 remain part of this document’s context: one Ruff diagnostic, four MyPy errors across two files, two focused-test failures in separate runs and two stale-consumer failures in the initial ordinary suite. Every bounded remediation and required rerun passed. The final ordinary suite recorded 613 passed, 7 skipped and 4 deselected; the skipped/deselected work remains NOT RUN. One Starlette warning is accepted. Open INDETERMINATE results: none.

## Limitations, cost and lifecycle distinctions

No backup, restore, migration, production purge scheduler, legal retention review, production privacy assessment, live-service startup, deployment or operational teardown was tested. No network, provider/model, cloud or paid activity occurred; provider/cloud cost was USD 0, while local workstation and owner costs were not monetized.

Configuration rollback disables the agent flags; it does not delete retained records. Record purge is cleanup. Operational release rollback, deployment rollback, deployment and operational/cloud teardown remain NOT RUN because no service, container or cloud resource was created.

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
