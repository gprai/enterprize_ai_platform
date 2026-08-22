# Test Evidence

This directory explains how the `enterprise-ai-platform` project records owner-executed test results for business and technical review.

## Business purpose

Test evidence gives the owner a reliable record of what was checked before approving work. It prevents a successful local test from being confused with a deployment, a cloud test, or final business acceptance.

## Result meanings

- **PASS** means the owner ran the stated check and the supplied transcript showed the expected successful result.
- **FAIL** means the owner ran the check and the supplied transcript showed at least one failure.
- **NOT RUN** means the check was deliberately not executed or was outside the approved scope.
- **INDETERMINATE** means the supplied facts cannot prove whether an event occurred.
- **Pending** means an approval or owner decision is still required.

An **evidence metadata record** is a small JSON summary containing the command description, timestamp, Git state, environment, result, and report path. It is not the full test transcript. A **redacted** record excludes secrets and document content.

## Owner-controlled evidence process

1. Codex writes only approved automated test code.
2. The owner executes installation, testing, cleanup, deployment, rollback, and teardown commands.
3. The owner supplies the resulting transcript.
4. Codex records only facts supported by that transcript after Column M Document Writing Approval.
5. Column N Final Approval remains a separate owner decision.

The evidence recorder prints JSON to standard output, also called **stdout**, and does not create a report file. Narrative evidence files in this directory require separate Column M approval.

## Security and privacy rules

- Never record credentials, API keys, bearer tokens, private document content, prompts containing private data, or unrestricted absolute report paths.
- AWS and paid tests remain opt-in and require explicit owner approval.
- A local PASS does not prove production readiness, deployment success, data-residency compliance, or live integration availability.
- Failures and skipped work must remain visible; they must not be silently converted into a PASS.

## Evidence records

- [W1-003](W1-003.md) — local testing structure, deterministic providers, opt-in markers, redacted stdout metadata, and cleanliness controls.
- [W1-004](W1-004.md) — owner-gated lifecycle controls, offline planning, fail-closed cleanliness verification, remediation history, and owner-executed validation.

# W1-003 final approval

W1-003 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from Gyan Prakash Rai on 2026-08-22. Its approved baseline is the owner-tested repository testing and evidence foundation recorded in `docs/test-evidence/W1-003.md`.

Column N authorizes only bounded closure of documentation already approved under Column M. After documentation closure, the owner—not Codex—updates the Excel tracker.

This approval does not mean that AWS or paid tests, live integrations, deployment, rollback execution, or cloud teardown were completed; those activities remain **NOT RUN** because they were outside W1-003. The accepted Starlette/TestClient warning, two deferred W1-001 Ruff findings, retained external virtual environment, and indeterminate initial DeepEval telemetry or update-check activity remain recorded limitations.

## W1-004 final approval

W1-004 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from G P Rai on 2026-08-22. Its approved baseline is the owner-tested, owner-gated lifecycle foundation recorded in `docs/test-evidence/W1-004.md`. The approved local testing scope passed after the documented teardown and Ruff remediations. The offline plan-intent check passed and explicitly reported that Terraform plan was **NOT RUN**.

AWS cleanliness remains **INDETERMINATE** because the required AWS inventory provider was unavailable; exit code `3` is the approved fail-closed result for that condition. AWS and paid tests, live integrations, deployment, rollback execution, Terraform apply/destroy, and cloud teardown remain **NOT RUN** and were not converted into successful outcomes by final approval. The retained external virtual environment and non-blocking Starlette/TestClient warning remain accepted limitations.

The next task may rely on W1-004's approved local lifecycle contracts, deterministic test foundation, provider-free Terraform roots, and fail-closed offline behavior. It must obtain separate approval before relying on live AWS state, deployment success, rollback execution, or cloud cleanliness. The owner updates the Excel tracker after this bounded documentation closure.
