# Week 5 Learning Review — Governed AWS Lifecycle

## Document status

- Prompt/task: `W5-004` and learning checkpoint `W5-13`
- Scope: reviewed AWS sandbox lifecycle and its governance controls
- Runtime commands or tests executed by this learning task: none
- Final owner approval: **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
- Approval time: `2026-09-16 16:37:21 SGT` (`UTC+08:00`)
- Production eligibility: **BLOCKED**
- Tracker update responsibility: Owner

This learning review explains the W5-004 synthetic, non-sensitive,
non-production lifecycle. It does not claim production readiness, actual billing
proof, an EKS deployment, live Bedrock use, model validation, or reusable
Terraform plans.

---

## 1. What was reviewed and executed

Week 5 treated Terraform plans as immutable, point-in-time deployment
artifacts—not as a general permission to change AWS later. The lifecycle used
separate saved plans and separate owner approvals for each phase:

| Phase | Result | Key fact |
| --- | --- | --- |
| Forward platform plan and apply | PASS | `saved-plan-015`: 5 creates, 25 updates |
| Post-apply verification | PASS, except cost gate waived | PA-02 through PA-15 PASS; PA-16 `WAIVED/ACCEPTED_RISK — NOT PASS` |
| Targeted rollback | PASS | `saved-plan-016` removed only the OpenSearch domain and four managed log groups |
| Full platform destroy | PASS | `saved-destroy-017` removed 37 remaining platform resources |
| Bootstrap/state destroy | PASS | `saved-bootstrap-destroy-018` removed 11 bootstrap resources after platform verification |

The forward plan was reviewed at its own identity:

- Saved-plan SHA-256:
  `d69eaf64751b004ff37d42147e5f61ffbdd987d0a9b1982edffb2f0c16223788`
- Plan JSON SHA-256:
  `5bba05bcd1405528299a30b9518efc0300f0313814b26082f1ad7ed6f5f9a7be`
- Account/Region/principal:
  `526338061652` / `ap-southeast-1` /
  `arn:aws:iam::526338061652:user/finopsinfra`

The platform and bootstrap Terraform states were verified empty after their
respective destroy operations. Two customer-managed KMS keys remain in the
expected seven-day `PendingDeletion` state; that is a retained billing and
verification tail, not a PASS result for cost eligibility.

## 2. Reviewed plans: why exact saved plans matter

Terraform configuration is a recipe. A saved plan is the evaluated recipe
against a specific state, variable set, provider version, account, and point in
time. Applying `terraform apply` against source files again can produce a
different action set; applying a saved plan applies only the actions already
reviewed.

The reviewed-plan process bound the following together:

1. Saved-plan bytes and SHA-256.
2. `terraform show -json` output and SHA-256.
3. Input-variable and backend-file hashes.
4. Terraform, provider-lock, source, OPA-policy, and OPA-executable identities.
5. State lineage, serial, and content identity.
6. AWS account, Region, and caller principal.
7. An owner deadline and the action inventory.

Before an apply, identity and state compatibility were rechecked. A plan could
not be silently rebound to later source or state. This is especially important
after the CloudWatch Logs/KMS correction: the corrected source did not rewrite
history or pretend that an earlier plan had been made from different source
bytes.

## 3. OIDC and least-privilege identity

The lifecycle separated human ownership from workload identity.

- The approved owner operated through the direct IAM principal
  `arn:aws:iam::526338061652:user/finopsinfra` for the explicitly authorized
  review and Terraform operations.
- Workload roles were defined separately for runtime, ingestion, OpenSearch
  administration, and GitHub OIDC.
- GitHub OIDC used the trusted
  `token.actions.githubusercontent.com` provider, audience `sts.amazonaws.com`,
  and a repository/environment subject constraint.
- Runtime and ingestion permissions were bounded to the named Kubernetes
  service-account and namespace conditions rather than to static access keys.

OIDC replaces long-lived CI credentials with short-lived credentials issued only
when the trusted issuer, audience, repository, and environment claims match.
It does not remove the need for scoped IAM policies, code review, plan review,
or owner approval.

## 4. Policy gates and fail-closed review

OPA was used as a plan-bound policy gate. Its job was not to estimate cost or
make an owner decision. Its job was to reject plan input that did not match the
repository's allowed lifecycle change shapes, ownership metadata, expiry rules,
and sensitive-data handling.

For the accepted forward and destroy reviews, OPA passed with zero findings. A
policy failure stopped execution rather than permitting a best-effort apply.
When a lifecycle operation had a documented review exception, it was preserved
as `WAIVED/ACCEPTED_RISK — NOT PASS`; it was never rewritten as an OPA or
repository-cost PASS.

The KMS remediation was deliberately narrow. It removed only `kms:ViaService`
from the exact `AllowExactOpenSearchLogEncryption` statement after the
CloudWatch Logs compatibility failure. It retained:

- the regional CloudWatch Logs service principal;
- seven permitted KMS actions;
- the key resource scope; and
- four exact OpenSearch log-group encryption-context ARNs.

Focused OPA tests covered the valid before/after shape and rejected broader
principal, action, ARN, condition, statement, and duplicate-action changes.

## 5. Immutable artifacts and evidence

An immutable artifact is evidence that must not be overwritten merely because a
later review, state refresh, or source correction occurs. W5 used unique,
exclusive operation roots and review-attempt directories to preserve prior
evidence, including failed or rejected attempts.

For each accepted phase, the evidence package retained the saved plan, plan
JSON, inventories, normalized policy input, OPA output, review metadata, state
identity, and approval binding. Historical artifacts were not renamed,
replaced, or reused for another lifecycle phase.

This gives an auditor a reconstructable answer to: *what exactly was reviewed,
who approved it, what state existed, and what action set was executed?*

## 6. Rollback, teardown, and safe ordering

Rollback and teardown are related but different:

- **Rollback** returns a selected component to an earlier desired condition.
  The W5 targeted rollback removed only the five OpenSearch resources introduced
  by the forward plan. It preserved the previously existing log-delivery
  resource policy and the 25 forward-plan updates.
- **Teardown** removes the platform once verification is complete. The full
  destroy removed the remaining platform resources, then native AWS orphan
  verification confirmed absence.
- **Bootstrap teardown** comes last because the state bucket, state KMS key,
  and DynamoDB lock are needed to manage and prove the platform destroy.

The teardown sequence therefore was:

```text
forward apply -> post-apply verification -> targeted rollback ->
platform destroy plan/review/apply -> native orphan verification ->
bootstrap destroy plan/review/apply -> final residue verification
```

The versioned state object was separately reviewed and explicitly cleaned before
bootstrap bucket deletion. No wildcard deletion was authorized. The final
remaining tails are the two KMS keys scheduled for deletion, which require a
later absence check after their AWS deletion dates.

## 7. Cost interpretation

The Infracost advisory result was `$195.184/month`, with an approximate
four-hour fixed subtotal of `$1.07`. This did not demonstrate a full lifecycle
cost below USD 3 because ECR, S3, interface-endpoint data, CloudWatch Logs,
KMS requests, delayed billing, and retained tails were not fully priced or
measured. Therefore:

```text
Cost eligibility: WAIVED/ACCEPTED_RISK — NOT PASS
USD_3_BOUNDED: false
Production eligibility: BLOCKED
```

The lesson is that monthly estimates can support a risk discussion but cannot
replace lifecycle-specific cost evidence or actual billing data.

## 8. Three interview answers

### Q1. How did you make Terraform deployment safe for a learning environment?

**Answer:** I used immutable saved plans, SHA-256 identities, plan JSON,
state-lineage/serial checks, account/Region/principal checks, OPA policy review,
and separate owner approval for every apply. The apply command used the exact
reviewed plan rather than regenerating a plan from source. The lifecycle also
used synthetic inputs, a short operating period, explicit stop conditions, and
separate destroy planning. That is stronger than simply running `terraform
apply` from a developer workstation, but it is still not a production approval.

### Q2. Why use OIDC for GitHub rather than long-lived AWS access keys?

**Answer:** OIDC lets AWS issue short-lived credentials only when a trusted
GitHub token satisfies the issuer, audience, repository, and environment
conditions in the role trust policy. There is no static key to distribute,
rotate, accidentally commit, or keep after a workflow ends. OIDC is one layer:
the role policy must still be least-privilege, and plan/policy/owner gates must
still approve the requested infrastructure action.

### Q3. What is the difference between rollback and teardown in this exercise?

**Answer:** Rollback was a precisely targeted recovery action: it deleted the
five newly created OpenSearch resources while preserving existing policy and
the other platform updates. Teardown was a separate, complete lifecycle phase:
it removed all remaining platform resources and then bootstrap/state resources
only after platform and orphan verification. Calling a full destroy a rollback
would hide scope and recovery assumptions; calling a targeted rollback a full
teardown would leave resources and costs behind.

## 9. Remaining handover conditions

- The final current source state still needs a recorded complete all-suite green
  rerun after the final KMS/OPA changes; the isolated protected-identity retry
  passed, but that is not a replacement for the complete suite.
- Delayed billing reconciliation and both KMS-tail absence checks remain owner
  follow-ups.
- W6-12 remains `NOT RUN`. Any EKS deployment requires fresh configuration,
  plan, policy, cost, evidence, and owner approval; no Week 5 plan is reusable.

## Final Owner Approval

- Prompt/task ID: `W5-004`.
- Reviewer: Gyan Prakash Rai, Project Owner and Final Approval Reviewer.
- Owner decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED** on
  `2026-09-16 16:37:21 SGT`.
- Documentation status: this learning review records the approved evidence and
  preserves its limitations without changing runtime, cloud, repository, or
  tracker state.
- Tracker update responsibility: Owner.
