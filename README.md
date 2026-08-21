# Enterprise AI Platform

`enterprise-ai-platform` is the canonical logical name for this owner-led learning project. The existing local folder and GitHub repository keep their current names; W1-001 does not authorize a rename.

## Business Purpose

This repository provides a governed starting point for learning how an enterprise AI platform moves from a business requirement to architecture, implementation, owner testing, evidence, approval, and controlled operation.

The Week 1 skeleton creates the structure and safety checks needed before application capabilities are added. Retrieval-augmented generation (RAG)—a technique that gives an AI model relevant source material before it answers—is intentionally out of scope for W1-001.

## Current Status

- **PASS:** The owner ran all 20 approved automated tests successfully.
- **PASS:** The owner ran the read-only repository validator successfully.
- **FAIL:** None reported in the owner-supplied transcript.
- **NOT RUN:** Deployment, cloud mutation, rollback execution, and resource teardown execution. W1-001 creates no deployed service or cloud resource.
- **Pending:** Owner review of the W1-001 documentation, Column N Final Approval, and the owner-managed tracker update.

Code-stage success does not mean W1-001 is complete. Completion requires the remaining owner approvals.

## Owner-Controlled Workflow

1. **Main Prompt and plan:** Codex inspects the approved scope read-only and prepares a pre-edit plan.
2. **Owner Pre-Edit Review:** The owner resolves missing decisions and approves the plan.
3. **Column L — Code Edit Approval:** Codex writes only approved code, configuration, schemas, infrastructure-as-code, and automated tests. Codex does not execute them.
4. **TEST-001 — Independent owner testing:** The owner runs one command at a time, reviews the result, and supplies the transcript.
5. **Column M — Document Writing Approval:** Codex writes only approved narrative documentation and factual, redacted evidence from the owner transcript.
6. **Owner documentation review:** The owner checks the code diff, test results, documentation, rollback and cleanliness outcome, and learning summary.
7. **Column N — Final Approval:** The owner makes the final decision. No additional change is implied by that approval.
8. **User tracker update:** Only the owner updates the Excel tracker.

A failure stops the workflow. Codex diagnoses owner-supplied evidence but does not execute remediation. Any source change requires a new bounded approval.

## Repository Map

| Path | Purpose |
|---|---|
| `docs/architecture` | Architecture descriptions and diagrams approved through the documentation gate. |
| `docs/adr` | Architecture Decision Records (ADRs), which explain important technical decisions and their consequences. |
| `docs/features` | Business-first feature requirements and the reusable feature template. |
| `docs/test-evidence` | Redacted evidence from owner-executed tests. |
| `docs/deployment-records` | Factual records of owner-executed deployments, including `NOT RUN` where applicable. |
| `docs/rollback-records` | Factual records of rollback decisions and results. |
| `docs/cost-estimates` | Approved cost assumptions and later factual cost evidence. |
| `docs/resource-cleanliness` | Evidence that managed resources were removed or that no resources were created. |
| `tools/platformctl` | A local, read-only Python validation tool. |
| `infra/bootstrap` | Reserved structure for future approved platform bootstrap infrastructure. |
| `infra/modules` | Reserved structure for reusable infrastructure modules. |
| `infra/environments/sandbox` | Reserved structure for the owner-approved sandbox environment. |
| `tests` | Automated unit, integration, feature, smoke, security, and teardown checks. |
| `policies` | Reserved structure for future approved policy-as-code. |
| `feature-matrix.yaml` | Machine-readable mapping of approved features, statuses, and linked tracker steps. |

Infrastructure-as-code (IaC) means infrastructure described in version-controlled files rather than created manually. W1-001 creates the directory structure but no IaC resource definitions.

## Read-Only Validation

Prerequisite: Python 3.11 or later. The approved validator uses only the Python standard library and requires no package installation, credentials, network connection, or cloud account.

```powershell
python -B -m tools.platformctl validate
```

`-B` prevents Python bytecode-cache files from being written. A successful code-stage check reports:

```text
CODE-STAGE VALIDATION PASS: approved repository contract is present
```

The Makefile supplies equivalent local validation and test targets for environments with GNU Make. Python commands remain the canonical Windows path.

## Security, Privacy, and Cost Boundary

- No credentials or plaintext secrets belong in this repository.
- W1-001 performs no network or cloud operation.
- W1-001 processes no personal, customer, regulated, or sample-document data.
- W1-001 has no data-residency impact.
- Estimated platform cost for this local skeleton is USD 0.
- The repository expiration policy supplied by the owner is `31/12/2026` using `DD/MM/YYYY` format.

## Failure, Rollback, and Teardown

If a validation or test fails, the owner stops and supplies the full redacted output. Codex may diagnose it but cannot change source without a new Code Edit Approval.

Rollback for W1-001 means removing only files created by W1-001 after the owner explicitly chooses rollback. Existing governance records, ADRs, feature documents, the Excel tracker, and `.git` must remain. Broad commands such as `git clean`, repository reset, or recursive workspace deletion are not approved.

Teardown requires no application, service, container, registry, Terraform, or cloud action because none was created. Local and cloud teardown execution therefore remains `NOT RUN`.

## Learning Summary

**Business use case:** A team receives a controlled, repeatable starting point for AI delivery instead of assembling governance, testing, and evidence conventions after development has begun.

**Technical importance:** The skeleton turns owner decisions into an executable local contract. It detects missing structure, unapproved feature states, unsafe tool capabilities, plaintext-secret patterns, and managed-resource residue.

**Layman explanation:** This is the labeled workspace, inventory sheet, and safety checklist prepared before the AI system is built.

**Key trade-offs:** Standard-library Python reduces dependency and supply-chain risk. JSON-compatible YAML is stricter than general YAML but avoids installing a YAML package. Empty directories use approved `.gitkeep` metadata so Git can preserve the structure.

**Interview talking points:** Explain why governance comes before RAG, how executable repository contracts prevent configuration drift, why feature IDs differ from delivery-step IDs, how owner-executed testing preserves separation of duties, and why rollback must be bounded to explicitly created artifacts.
