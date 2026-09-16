# W5-004 teardown-plan and execution record

## Why teardown was sequenced

Terraform destroy removes resources tracked in state, but it cannot alone prove that AWS retained no project resources. W5-004 therefore reviewed a saved destroy plan, checked empty/non-blocking S3 and ECR conditions, applied the exact plan, performed native orphan discovery, and destroyed bootstrap/state resources only after platform destruction was verified.

## Platform destroy plan and result

`saved-destroy-017` was a full, non-targeted platform destroy plan. It contained 0 creates, 0 updates, 37 deletes, 0 replacements, and 0 imports.

- destroy-plan SHA-256: `f0bd42594a4c75657dfd54908000d243b2658c2424412d10a2b79037ecbc041b`;
- destroy-plan JSON SHA-256: `628b2ac998f5f696f28fd636018bd737ed2f49b3ab9d0c1f47420a55c6d0b2e5`;
- OPA result: PASS, zero findings; and
- post-destroy platform state: empty, lineage `7465ed2e-a39c-afdd-f172-5792d3ec2f85`, serial `13`.

The plan covered remaining platform IAM, KMS alias/key, networking, endpoints, ECR, storage, owner-expiry sentinel, and the retained OpenSearch Logs resource policy. It excluded bootstrap/state resources, the already rolled-back OpenSearch domain/log groups, unrelated resources, and the externally managed OpenSearch service-linked role.

## Bootstrap-last destroy plan and result

After platform destroy and native orphan verification passed, `saved-bootstrap-destroy-018` was reviewed and applied with 0 creates, 0 updates, 11 deletes, 0 replacements, and 0 imports.

- bootstrap destroy-plan SHA-256: `33444386bb526bd7d9c07548d7d744fe30a308cb8a0cc37b4fca48691c0c6663`;
- bootstrap destroy-plan JSON SHA-256: `d2de1f3bb3b9143a3c5c8ad6e13ae9ceddab276b86d6f5f8c241f4c2491bb534`;
- final bootstrap state: empty, lineage `c446f9a2-77d4-9954-20fa-523205d86a8a`, serial `31`.

The approved cleanup removed the state bucket after exactly 13 versioned state objects were separately authorized and deleted. The bootstrap destroy then removed the state bucket, DynamoDB lock table, KMS alias/key, bucket controls, and owner-expiry sentinel. It did not reuse a platform plan or perform direct unplanned deletion.

## Expected residuals and cost tails

Both customer-managed KMS keys entered `PendingDeletion` with seven-day tails. The platform key is scheduled for `2026-09-23T12:14:16.738+08:00`; the bootstrap-state key is scheduled for `2026-09-23T15:40:48.581+08:00`. They are expected retained tails, not proof of physical deletion.

Cost remains `WAIVED/ACCEPTED_RISK — NOT PASS`; the exact destroy plan had no plan-bound advisory price, billing was not queried, and delayed tail charges remain unverified.

## Fields pending Column N

- Confirm the distinction between planned destruction, applied destruction, and later native verification.
- Preserve bootstrap-last sequencing and separate owner approvals.
- Keep future KMS absence verification and delayed billing reconciliation assigned to the owner.

## Final Owner Approval

 - Prompt/task ID: `W5-004`.
 - Reviewer: Gyan Prakash Rai, Project Owner and Final Approval Reviewer.
 - Owner decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED** on `2026-09-16 16:37:21 SGT`.
 - Final status: the documented platform-first and bootstrap-last teardown sequence is approved as complete within W5-004 scope.
 - Code and documentation review status: documentation closure is approved; this does not make the uncommitted source tree release-ready or authorize source/Git changes.
 - Owner-executed test status: exact saved-plan destroy/apply and native verification results remain as recorded.
 - Warnings, risks, gaps, and scope limitations: all Column M risks are accepted. Cost remains `WAIVED/ACCEPTED_RISK — NOT PASS`; delayed billing and physical KMS deletion are unproven.
 - NOT RUN and INDETERMINATE: all recorded NOT RUN activities remain NOT RUN; no historical INDETERMINATE result is converted to PASS; open INDETERMINATE activities: none.
 - Deployment, rollback, teardown, and residuals: teardown completed; target rollback was separately verified; platform and bootstrap resources were removed within scope; two KMS keys remain expected `PendingDeletion` tails.
 - Deferred actions and owner: verify both KMS keys absent after their recorded times and reconcile delayed billing; owner is Gyan Prakash Rai unless separately reassigned.
 - Conditions: do not recreate resources, reuse plans, or claim zero physical residue before future KMS absence verification.
 - Next-task handover: W6-12 remains `NOT RUN` and must begin from fresh discovery and approvals.
 - Tracker update responsibility: Owner.
