# Week 1 owner learning review

## Learning status

- Learning task: `WEEKLY-LEARN-001`
- Week: `1`
- Owner: `G P Rai`
- Teach-back date: `2026-08-23`
- Teach-back result: **PASS**
- Code or runtime action: **NOT RUN — teaching and documentation only**

## Business outcome

Week 1 reduced the risk of developing the wrong feature, using unapproved data, creating uncontrolled cloud resources, or claiming success without evidence. The week established governance, business requirements, repository contracts, configuration boundaries, automated tests, evidence conventions, and owner-gated lifecycle controls before retrieval or cloud deployment work begins.

This sequence matters commercially because correcting an architectural or governance mistake before deployment is cheaper, safer, and easier to audit than remediating an uncontrolled production system.

## End-to-end architecture learned

The Week 1 decision flow is:

`Governing authority → approved MVP → repository and configuration contracts → automated quality gates → platformctl lifecycle controls → owner evidence and approval`

1. **Governing authority:** Source of Truth v1.1 has the highest implementation authority. Later owner-approved ADRs supersede only explicitly identified decisions. Conflicts stop for an owner decision.
2. **Approved MVP:** `MVP-001` defines the target users, first use case, representative questions, scope, abstention behavior, security expectations, dependencies, and owner decisions.
3. **Repository contract:** the repository structure and feature matrix make approved project identity, status, ownership, environment, and validation rules machine-checkable.
4. **Configuration boundary:** approved local values are separated from unresolved AWS or OpenSearch inputs. Unresolved runtime values fail validation rather than being silently invented.
5. **Automated quality gates:** unit, integration, contract, feature, smoke, security, and teardown tests provide different kinds of evidence. AWS and paid tests are opt-in.
6. **Lifecycle control:** `platformctl` sits between the owner and infrastructure tooling. It validates intent and approval requirements before a potentially mutating operation can reach Terraform or AWS.
7. **Evidence and approval:** results remain explicitly labelled `PASS`, `FAIL`, `NOT RUN`, or `INDETERMINATE`; final acceptance belongs to the owner.

## Week 1 decisions understood

- Canonical logical project name: `enterprise-ai-platform`.
- Owner-controlled execution: Codex writes approved artifacts; the owner executes tests, services, deployment, rollback, teardown, registry, and cloud commands.
- Default environment: `sandbox`.
- Canonical feature context: `MVP-001` with the restarted status initially set to `Not Started`.
- AWS region: `ap-southeast-1`.
- Local embedding model: `sentence-transformers/all-MiniLM-L6-v2`.
- Local Qdrant endpoint: `http://127.0.0.1:6333` with no API key required for the approved local configuration.
- OpenSearch remains `TODO_USER`; no live endpoint or access was approved.
- AWS and paid tests are deselected by default.
- Provider-free, resource-free Terraform roots establish structure without deploying cloud resources.
- `verify-clean` fails closed with exit code `3` when AWS inventory is unavailable.
- The external virtual environment is intentionally retained outside the repository for later owner work.

## Decisions and trade-offs

| Decision | Benefit | Trade-off |
|---|---|---|
| Require explicit approval gates | Reduces accidental and unauthorized mutation | Adds deliberate owner steps and slows execution |
| Use deterministic fake AWS providers | Fast, repeatable, private, and cost-free tests | Cannot prove live AWS behavior or cleanliness |
| Keep Terraform provider-free and resource-free in Week 1 | Establishes safe structure with no credentials or cloud cost | Does not validate a real provider, backend, plan, or resource |
| Require environment and target inputs | Makes operational intent reviewable | Adds command verbosity |
| Return exit code `3` for unavailable AWS inventory | Prevents a false cleanliness PASS | Leaves cloud cleanliness INDETERMINATE until separately approved live inspection |
| Keep development tooling in an external virtual environment | Avoids repository-local environment residue | Retains local disk usage and requires environment-path awareness |

## Failure, recovery, rollback, and teardown story

Week 1 deliberately preserved failures instead of rewriting them as successful outcomes:

1. Missing development dependencies required creation and use of an isolated external virtual environment.
2. DeepEval's automatically loaded Pytest plugin required targeted suppression so default local testing did not trigger unwanted plugin behavior.
3. Older teardown tests became stale after the approved Terraform skeleton and W1-003 evidence documents were introduced. The owner updated only those lifecycle assumptions so the tests required the exact new baseline and continued to reject unexpected files.
4. Ruff found import-order and Python 3.11 enum-modernization issues. The owner made bounded corrections and ran behavior-sensitive regression tests.
5. An incomplete `platformctl plan` invocation failed safely because its required environment and target arguments were absent. The corrected read-only intent check then passed and explicitly stated that Terraform plan was **NOT RUN**.
6. Final W1-004 local validation passed 128 tests; two AWS/paid tests remained deselected and one non-blocking Starlette/TestClient warning remained visible.
7. AWS cleanliness remained **INDETERMINATE** because the live inventory provider was unavailable. Exit code `3` correctly prevented a false clean-cloud claim.

No live deployment occurred. Application rollback, Terraform plan/apply/destroy, and cloud teardown were therefore **NOT RUN**. Local repository cleanliness and teardown tests passed within their tested scope. The external virtual environment was intentionally retained.

## Owner teach-back assessment

The owner correctly explained that Week 1 reduced the risks of building the wrong feature, using unapproved data, creating uncontrolled cloud resources, and claiming unsupported success. The owner also correctly explained the mocked-provider trade-off and why fail-closed exit code `3` is safer than reporting a cleanliness PASS.

The architecture answer was strengthened as follows: `platformctl` is not merely a lifecycle command collection; it is the policy-enforcing control layer between the owner and Terraform/AWS.

The owner demonstrated the failure-and-recovery story by identifying the missing dependencies, external environment, DeepEval plugin behavior, and stale teardown expectations. The completed interview version also connects those events to Ruff remediation, final regression results, the absence of deployment, and the distinction between local cleanup and live cloud cleanliness.

## Interview preparation

1. **What business risk did Week 1 reduce?**  
   It reduced the chance of building the wrong capability, processing unapproved data, mutating cloud resources without control, or approving work without evidence.

2. **Where does `platformctl` sit in the architecture?**  
   It sits between the owner and Terraform/AWS as an owner-gated policy and lifecycle control layer.

3. **Why is exit code `3` safer than a cleanliness PASS?**  
   It communicates that cloud state could not be proved and prevents an unavailable inventory provider from being mistaken for an empty AWS account.

4. **What is the mocked-provider trade-off?**  
   Mocking provides deterministic, private, cost-free testing, but it cannot prove live provider permissions, API behavior, or resource state.

5. **What is the Week 1 rollback story?**  
   No application or infrastructure deployment occurred, so live rollback was not applicable. Recovery consisted of bounded local corrections followed by focused and complete regression tests; local teardown passed and cloud teardown remained NOT RUN.

## Remaining limitations

- AWS and paid tests: **NOT RUN**.
- Live integrations and services: **NOT RUN**.
- Terraform plan/apply/destroy: **NOT RUN**.
- Deployment and application rollback: **NOT RUN**.
- Cloud teardown: **NOT RUN**.
- AWS cleanliness: **INDETERMINATE**.
- Starlette/TestClient deprecation warning: accepted, non-blocking, and deferred.
- External virtual environment: intentionally retained with accepted local disk usage.
- Fresh-environment development dependency installation should be reconciled because the current `pyproject.toml` no longer contains the previously used `dev` dependency group.

## Learning conclusion

`WEEKLY-LEARN-001` is **COMPLETE**. The owner can explain the Week 1 business outcome, architecture position, decisions, trade-offs, failure and recovery history, and the difference between local evidence and live-cloud proof.
