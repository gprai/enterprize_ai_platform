# EVAL-001 — D3 Reconciled Owner Decision

## Status

Recommended owner decision: **APPROVE WITH THE EXACT CONDITIONS BELOW**.

This record reconciles the accepted Q1–Q30 planning inputs with the mandatory W3-002 distribution. It is an owner-supplied planning decision, not test evidence, an implementation artifact or an approved evaluation baseline.

## Preserved input provenance

The original owner inputs remain preserved and must not be silently rewritten:

- Original candidate SHA-256: `e4178a81c4c63b6957e72a37f0b0cdc524eb4ae5994948f3b6396a39e646f11f`
- Original owner-review SHA-256: `cf2c49503c12fe6eb78417f785ab653d16117efbb20d3d326c74ce533f3adb71`
- Q1–Q5 retain the approved starter questions, expected facts and expected source IDs.
- Q1–Q23 and Q27/Q29 retain their owner-authored business intent.
- Q24–Q26, Q28 and Q30 are corrected only where required by the current W3-001 runtime contract.
- Q31–Q39 add mandatory coverage that was missing from the original 30 cases.

## Final distribution

| Expected outcome | Cases | Count |
|---|---|---:|
| `ANSWER_WITH_CITATION` | Q1–Q4, Q6–Q23, Q29, Q39 | 24 |
| `ABSTAINED` | Q5, Q24–Q28, Q30–Q35 | 12 |
| `EXPECTED_ERROR` | Q36–Q38 | 3 |
| **Total** | **Q1–Q39** | **39** |

Security, isolation, malformed-evidence, citation-integrity and operational-error cases are release-blocking regardless of aggregate evaluation scores.

## Q24–Q26 defense-in-depth execution mode

Q24–Q26 use `DEFENSE_IN_DEPTH_DENIED_EVIDENCE`.

The controlled retriever deliberately supplies chunks that violate clearance, tenant or ACL constraints to the RAG boundary. This tests the second authorization boundary rather than the ordinary authorization-aware retrieval path.

Required result for all three:

- `expected_outcome`: `ABSTAINED`
- `expected_abstention_reason`: `no_authorized_evidence`
- `expected_provider_calls`: `0`
- denied evidence does not enter the provider prompt;
- denied evidence does not enter the normalized result;
- no raw denied content is logged or exposed.

This does not replace ordinary retrieval authorization tests. It proves defense in depth when an upstream retriever is faulty or adversarial.

## Q28 corrected same-source identity

`SOT-OLD` is a fixture alias only.

Both qualifying evidence versions must cross the runtime contract with:

- the same actual `source_id`: `DOC-SOT-V1.1`;
- the same actual logical `document_id` as the current Source of Truth;
- different controlled `document_version` values;
- deterministic chunk IDs derived from their respective versions.

Final Q28 mapping:

- `expected_source_ids`: `["DOC-SOT-V1.1"]`
- `expected_outcome`: `ABSTAINED`
- `expected_abstention_reason`: `conflicting_evidence`
- `expected_provider_calls`: `0`

The alias `SOT-OLD` may identify the fixture in evaluation configuration but must not cross the runtime `RetrievedChunk` contract as its source ID.

## Q30 current-contract mapping

Q30 supplies only controlled `INJECTION` evidence. The deterministic fake provider emits answer content without a valid citation matching supplied authorized evidence.

Required result:

- `expected_outcome`: `ABSTAINED`
- `expected_abstention_reason`: `invalid_generated_citation`
- `expected_provider_calls`: `1`
- valid normalized provider usage is retained;
- generated answer text, injection content, citations, prompt and provider response are discarded and not exposed.

Q30 proves fail-closed output and citation handling. It does not prove the semantic prompt-injection resistance of a live model.

## Mandatory Q31–Q39 behavior

| Case | Controlled behavior | Expected result |
|---|---|---|
| Q31 | Malformed retrieval evidence | `ABSTAINED / malformed_evidence`; zero provider calls |
| Q32 | Missing generated citation | `ABSTAINED / invalid_generated_citation`; valid usage retained |
| Q33 | Fabricated generated citation | `ABSTAINED / invalid_generated_citation`; valid usage retained |
| Q34 | Generated citation with wrong document version | `ABSTAINED / invalid_generated_citation`; valid usage retained |
| Q35 | Unauthorized or unsupplied generated citation | `ABSTAINED / invalid_generated_citation`; valid usage retained |
| Q36 | Unexpected generated tool call | `EXPECTED_ERROR / rag_output_validation_error`; no tool execution |
| Q37 | Invalid generated JSON | `EXPECTED_ERROR / rag_output_validation_error` |
| Q38 | Malformed provider envelope or usage | `EXPECTED_ERROR / llm_malformed_response_error` |
| Q39 | Equal-score evidence supplied in reverse order | Chunk-ID tie-break ordering and identical repeated answer/citations |

Q28 remains a retrieved-version conflict case. Q34 is separately a generated-citation version mismatch case.

## Evaluation-only evidence decision

Approve evaluation-only evidence snapshots for Q6–Q23 and Q29 rather than expanding the ordinary Week 2 sample corpus.

Required controls:

- retain the authoritative runtime `source_id` values;
- assign exact controlled `document_id`, `document_version` and deterministic `chunk_id` values during Gate 2;
- copy only the minimum approved excerpt needed by each case;
- keep all content synthetic or non-sensitive;
- mark snapshots evaluation-only;
- do not ingest them through the ordinary sample-corpus path;
- do not change the current Week 2 corpus manifest or its consumers;
- do not use a candidate model to generate expected facts;
- do not represent local snapshot results as production-ingestion evidence.

If Gate 2 finds that evaluation-only snapshots require another repository path, it must add that exact path to the final Column L manifest before editing. The statement that no additional code path is needed does not authorize an unenumerated data, fixture or configuration path.

## Planning-file disposition and clean baseline

Owner decision: move these two untracked planning files outside the repository after their review is complete and retain them as external owner records:

- `configs/eval/EVAL-001_Q1-Q30_candidate.jsonl`
- `configs/eval/EVAL-001_owner-review.md`

Rationale:

- `configs/eval/golden.jsonl` must become the single governed dataset artifact under Column L;
- retaining both planning files would create duplicate truth sources and future drift risk;
- their accepted SHA-256 hashes remain recorded above for provenance;
- the owner can retain external copies outside the Git worktree.

The owner—not Codex—must close Excel and confirm removal of its `~$` lock file. The owner must also move the two planning files outside the repository and return a complete `git status --short` result. Do not reuse baseline `5ab50cf6ce5e92eea14e4bf0d0e1267cf5e53cf5` until a fresh clean-state check proves that it is still current.

Codex is not authorized by this decision to delete, move, commit or modify repository files.

## Paste-ready owner decision

```text
EVAL-001 — D3 CASE INVENTORY RECONCILIATION — OWNER DECISION

APPROVED WITH CONDITIONS:

1. Preserve Q1–Q30 as the owner-authored core inventory, subject only to the exact Q24–Q26, Q28 and Q30 contract corrections below.
2. Add Q31–Q39 exactly as defined in EVAL-001_Q1-Q39_reconciled.jsonl.
3. Final distribution: 39 cases — 24 ANSWER_WITH_CITATION, 12 ABSTAINED and 3 EXPECTED_ERROR.
4. Q24–Q26 use controlled defense-in-depth denied chunks and must return no_authorized_evidence with zero provider calls. Denied evidence must enter neither the provider prompt nor the normalized result.
5. SOT-OLD is a fixture alias only. Q28 uses actual source_id DOC-SOT-V1.1, the same logical document_id as the current Source of Truth, a different controlled document_version and a deterministic version-derived chunk_id. Expected reason: conflicting_evidence. Provider calls: zero.
6. Q30 supplies only controlled INJECTION evidence. The fake provider emits answer content without a valid supplied citation. Expected result: ABSTAINED / invalid_generated_citation. One provider call occurs; valid normalized usage is retained; answer, injection content, citations, prompt and provider response are not exposed.
7. Q31–Q35 cover malformed evidence and missing, fabricated, version-mismatched, unauthorized or unsupplied generated citations. Q36–Q38 cover the exact approved RAG/provider errors. Q39 proves equal-score chunk-ID ordering and repeatability.
8. Use controlled evaluation-only evidence snapshots for Q6–Q23 and Q29. Do not expand the ordinary Week 2 corpus or silently change its manifest, ingestion fixtures or consumers.
9. Gate 2 must assign and report every evaluation snapshot's exact source_id, document_id, document_version and deterministic chunk_id. Any required additional repository path must be explicitly added to the final Column L manifest before editing.
10. After review, the owner will move configs/eval/EVAL-001_Q1-Q30_candidate.jsonl and configs/eval/EVAL-001_owner-review.md outside the repository and retain them as external owner records. They will not be committed. Their accepted hashes remain recorded for provenance.
11. The owner will close Excel, confirm the ~$ workbook lock file is absent, and supply a fresh complete git status and HEAD. Baseline 5ab50cf6ce5e92eea14e4bf0d0e1267cf5e53cf5 is not approved for Column L until the clean baseline is re-proven.

This decision is owner-supplied planning authority only. It does not authorize repository edits, file deletion or movement, testing, evaluation execution, baseline creation, documentation writing, tracker editing, Git mutation, AWS access or paid-provider activity.
```
