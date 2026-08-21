# ADR-001 — RAG Before Model Fine-Tuning

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Use retrieval-augmented generation for current or proprietary knowledge. Consider
fine-tuning only after versioned evaluation shows a stable behavior, style, or task
gap that retrieval and prompting cannot resolve.

## Rationale and trade-offs

RAG keeps sources current, supports citations and deletion, and is cheaper to
reverse. It makes retrieval quality critical and adds indexing operations. A
fine-tune-first or prompt-only design was rejected because neither provides the
same current, cited knowledge boundary.

## Consequences and revisit trigger

Retrieval, citation, abstention, and evaluation are release gates. Revisit only
when measured evidence demonstrates a persistent gap. No training or deployment is
approved by this ADR.
