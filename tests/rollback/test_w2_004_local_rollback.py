"""Rollback proof for the non-mutating W2-004 regression override."""

from __future__ import annotations

import asyncio
import json

from tests.feature.test_local_retrieval import (
    COLLECTION_NAME,
    ROOT,
    chunk_inventory,
    create_runtime,
    expected_source_ids,
    ingest_all,
    require_phase,
    validate_isolation_and_quarantine,
    validate_queries,
)

from enterprise_ai_platform.ingestion.models import load_starter_fixture


def test_regression_override_changes_only_the_test_scoped_expectation() -> None:
    questions = load_starter_fixture(ROOT / "configs/eval/w2-starter.jsonl")
    first = questions[0]
    before = first.model_dump(mode="json")

    assert expected_source_ids(first, None) == first.expected_source_ids
    assert expected_source_ids(first, "DOC-RESTRICTED-TEST") == (
        "DOC-RESTRICTED-TEST",
    )
    assert first.model_dump(mode="json") == before

def test_real_rollback_revalidates_the_known_good_state() -> None:
    require_phase("rollback")

    async def scenario() -> None:
        runtime = create_runtime()
        try:
            if not await runtime.client.collection_exists(COLLECTION_NAME):
                raise AssertionError("the approved W2-004 collection is absent")
            assert await runtime.store.healthcheck(timeout_seconds=60.0)
            await runtime.store.create_or_validate_collection(runtime.specification)
            before_ids, before_count = await chunk_inventory(runtime)
            await ingest_all(runtime)
            after_ids, after_count = await chunk_inventory(runtime)
            assert before_ids == after_ids
            assert before_count == after_count
            report = await validate_queries(runtime, regression_override=None)
            await validate_isolation_and_quarantine(runtime)
            print(
                json.dumps(
                    {
                        "phase": "rollback",
                        "status": "PASS",
                        "chunk_point_count": len(after_ids),
                        "total_point_count": after_count,
                        "questions": report,
                    },
                    sort_keys=True,
                )
            )
        finally:
            await runtime.client.close()

    asyncio.run(scenario())
