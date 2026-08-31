"""Sequential secure-ingestion orchestration and explicit fake-only CLI."""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from time import perf_counter
from typing import Never

from enterprise_ai_platform.embeddings.base import (
    Embedder,
    EmbeddingContract,
    EmbeddingVector,
    assert_embedding_contract,
)
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingContractMismatchError,
    EmbeddingError,
    EmbeddingProviderFailure,
)
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.authorization import (
    require_active_context,
    require_ingestion_authorized,
)
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreError,
)
from enterprise_ai_platform.retrieval.models import (
    ApprovedException,
    AuthContext,
    Chunk,
    Classification,
    CollectionSpec,
    Document,
    IngestionStatus,
    PiiStatus,
    Role,
    deterministic_chunk_id,
)
from enterprise_ai_platform.retrieval.vector_store import VectorStore

from .chunking import chunk_text
from .errors import (
    IngestionAuthorizationError,
    IngestionCancelledError,
    IngestionConfigurationError,
    IngestionContractError,
    IngestionError,
    IngestionProviderError,
    IngestionRollbackIndeterminateError,
    IngestionSourceError,
)
from .identity import content_hash_for, document_id_for, document_version_for
from .loaders import load_source
from .models import (
    DOCUMENT_DEADLINE_SECONDS,
    EMBEDDING_BATCH_SIZE,
    MAX_APPLICATION_ATTEMPTS,
    MAX_RETRY_JITTER_SECONDS,
    RETRY_BASE_SECONDS,
    VECTOR_OPERATION_TIMEOUT_SECONDS,
    CorpusDocument,
    CorpusManifest,
    IngestionManifest,
    IngestionManifestRecord,
    IngestionOutcome,
    IngestionRecordStatus,
    PiiPolicy,
    load_corpus_manifest,
    load_pii_policy,
)
from .pii import PiiAnalyzer, SyntheticPiiAnalyzer, apply_pii_policy
from .tokenizer import DeterministicTestTokenizer, IngestionTokenizer

_COLLECTION_NAME = "w2_003_ingestion"


def _default_jitter() -> float:
    return secrets.randbelow(51) / 1000


class IngestionPipeline:
    """Process one document at a time through every approved trust boundary."""

    def __init__(
        self,
        *,
        embedder: Embedder,
        vector_store: VectorStore,
        tokenizer: IngestionTokenizer,
        pii_analyzer: PiiAnalyzer,
        collection_spec: CollectionSpec,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = _default_jitter,
        clock: Callable[[], float] = perf_counter,
    ) -> None:
        expected = EmbeddingContract(
            model_id=collection_spec.embedding_model_id,
            model_revision=collection_spec.embedding_revision,
            dimension=collection_spec.dimension,
            normalized=collection_spec.normalized,
            metric=collection_spec.metric.value,
        )
        try:
            assert_embedding_contract(embedder, expected)
        except EmbeddingContractMismatchError:
            raise IngestionContractError from None
        self._embedder = embedder
        self._vector_store = vector_store
        self._tokenizer = tokenizer
        self._pii_analyzer = pii_analyzer
        self._collection_spec = collection_spec
        self._sleep = sleep
        self._jitter = jitter
        self._clock = clock

    async def ingest(
        self,
        *,
        manifest: CorpusManifest,
        source_root: Path,
        pii_policy: PiiPolicy,
        tenant_id: str,
        auth_context: AuthContext,
        approved_exceptions: Mapping[str, ApprovedException] | None = None,
    ) -> IngestionOutcome:
        """Ingest the explicitly selected tenant and return a redacted manifest."""

        try:
            require_active_context(auth_context)
        except VectorStoreAuthorizationError:
            raise IngestionAuthorizationError from None
        if auth_context.tenant_id != tenant_id or Role.INGESTOR not in auth_context.roles:
            raise IngestionAuthorizationError
        selected = tuple(source for source in manifest.documents if source.tenant_id == tenant_id)
        if not selected:
            raise IngestionConfigurationError

        started = self._clock()
        records: list[IngestionManifestRecord] = []
        exit_codes: list[int] = []
        exceptions = approved_exceptions or {}
        for source in selected:
            record, exit_code = await self._ingest_one(
                source=source,
                source_root=source_root,
                pii_policy=pii_policy,
                auth_context=auth_context,
                approved_exception=exceptions.get(source.source_id),
            )
            records.append(record)
            exit_codes.append(exit_code)
            if exit_code in {5, 130}:
                break

        exit_code = self._highest_exit_code(exit_codes)
        duration_ms = max(0, round((self._clock() - started) * 1000))
        manifest_result = self._build_manifest(
            dataset_name=manifest.dataset_name,
            tenant_id=tenant_id,
            records=tuple(records),
            duration_ms=duration_ms,
            exit_code=exit_code,
        )
        return IngestionOutcome(manifest=manifest_result, exit_code=exit_code)

    async def _ingest_one(
        self,
        *,
        source: CorpusDocument,
        source_root: Path,
        pii_policy: PiiPolicy,
        auth_context: AuthContext,
        approved_exception: ApprovedException | None,
    ) -> tuple[IngestionManifestRecord, int]:
        document_id = document_id_for(source.tenant_id, source.source_id)
        document_version: str | None = None
        content_hash: str | None = None
        pii_status: PiiStatus | None = None
        upsert_started = False
        try:
            async with asyncio.timeout(DOCUMENT_DEADLINE_SECONDS):
                loaded = load_source(source_root, source)
                content_hash = content_hash_for(loaded.original_bytes)
                document_version = document_version_for(document_id, content_hash)
                findings = await self._pii_analyzer.analyze(loaded.normalized_text)
                decision = apply_pii_policy(
                    loaded.normalized_text,
                    findings,
                    pii_policy,
                    approved_exception=approved_exception,
                )
                pii_status = decision.status
                if pii_status is PiiStatus.QUARANTINED:
                    return (
                        self._record(
                            source,
                            IngestionRecordStatus.QUARANTINED,
                            pii_status=pii_status,
                            document_id=document_id,
                            document_version=document_version,
                            content_hash=content_hash,
                            error_code="pii_high_risk_quarantined",
                        ),
                        3,
                    )

                exception = (
                    approved_exception if pii_status is PiiStatus.APPROVED_EXCEPTION else None
                )
                document = Document(
                    tenant_id=source.tenant_id,
                    source_id=source.source_id,
                    media_type=source.media_type,
                    document_id=document_id,
                    document_version=document_version,
                    classification=source.classification,
                    allowed_roles=frozenset(source.allowed_roles),
                    allowed_groups=frozenset(source.allowed_groups),
                    data_owner=source.data_owner,
                    content_hash=content_hash,
                    pii_status=pii_status,
                    ingestion_status=IngestionStatus.INDEXED,
                    approved_exception=exception,
                    content=decision.processed_text,
                )
                try:
                    require_ingestion_authorized(
                        document,
                        auth_context,
                        detected_entity_types=decision.entity_types,
                    )
                except VectorStoreAuthorizationError:
                    raise IngestionAuthorizationError from None

                text_chunks = chunk_text(document.content, self._tokenizer)
                embeddings = await self._embed_chunks(
                    [text_chunk.text for text_chunk in text_chunks]
                )
                if len(embeddings) != len(text_chunks):
                    raise IngestionContractError
                chunks = tuple(
                    Chunk(
                        **document.model_dump(exclude={"content"}),
                        chunk_id=deterministic_chunk_id(
                            tenant_id=document.tenant_id,
                            document_id=document.document_id,
                            document_version=document.document_version,
                            content_hash=document.content_hash,
                            chunk_index=text_chunk.chunk_index,
                        ),
                        chunk_index=text_chunk.chunk_index,
                        text=text_chunk.text,
                        embedding=embedding,
                    )
                    for text_chunk, embedding in zip(
                        text_chunks,
                        embeddings,
                        strict=True,
                    )
                )
                await self._vector_store.create_or_validate_collection(
                    self._collection_spec,
                    timeout_seconds=VECTOR_OPERATION_TIMEOUT_SECONDS,
                )
                upsert_started = True
                await self._vector_store.upsert_chunks(
                    self._collection_spec,
                    chunks,
                    auth_context,
                    timeout_seconds=VECTOR_OPERATION_TIMEOUT_SECONDS,
                )
                return (
                    self._record(
                        source,
                        IngestionRecordStatus.INDEXED,
                        pii_status=pii_status,
                        document_id=document_id,
                        document_version=document_version,
                        content_hash=content_hash,
                        chunk_count=len(chunks),
                    ),
                    0,
                )
        except IngestionSourceError as error:
            return (
                self._record(
                    source,
                    IngestionRecordStatus.QUARANTINED,
                    pii_status=pii_status,
                    document_id=document_id,
                    document_version=document_version,
                    content_hash=content_hash,
                    error_code=error.code,
                ),
                error.exit_code,
            )
        except IngestionAuthorizationError as error:
            return (
                self._record(
                    source,
                    IngestionRecordStatus.REJECTED,
                    pii_status=pii_status,
                    document_id=document_id,
                    document_version=document_version,
                    content_hash=content_hash,
                    error_code=error.code,
                ),
                error.exit_code,
            )
        except VectorStoreAuthorizationError:
            authorization_error = IngestionAuthorizationError()
            return (
                self._record(
                    source,
                    IngestionRecordStatus.REJECTED,
                    pii_status=pii_status,
                    document_id=document_id,
                    document_version=document_version,
                    content_hash=content_hash,
                    error_code=authorization_error.code,
                ),
                authorization_error.exit_code,
            )
        except asyncio.CancelledError:
            return await self._after_uncertain_failure(
                source=source,
                auth_context=auth_context,
                document_id=document_id,
                document_version=document_version,
                content_hash=content_hash,
                pii_status=pii_status,
                upsert_started=upsert_started,
                cancelled=True,
            )
        except TimeoutError:
            return await self._after_uncertain_failure(
                source=source,
                auth_context=auth_context,
                document_id=document_id,
                document_version=document_version,
                content_hash=content_hash,
                pii_status=pii_status,
                upsert_started=upsert_started,
                cancelled=False,
            )
        except (EmbeddingError, VectorStoreError, IngestionContractError):
            return await self._after_uncertain_failure(
                source=source,
                auth_context=auth_context,
                document_id=document_id,
                document_version=document_version,
                content_hash=content_hash,
                pii_status=pii_status,
                upsert_started=upsert_started,
                cancelled=False,
            )
        except Exception:
            return await self._after_uncertain_failure(
                source=source,
                auth_context=auth_context,
                document_id=document_id,
                document_version=document_version,
                content_hash=content_hash,
                pii_status=pii_status,
                upsert_started=upsert_started,
                cancelled=False,
            )

    async def _embed_chunks(
        self,
        texts: list[str],
    ) -> tuple[EmbeddingVector, ...]:
        vectors: list[EmbeddingVector] = []
        for offset in range(0, len(texts), EMBEDDING_BATCH_SIZE):
            batch = texts[offset : offset + EMBEDDING_BATCH_SIZE]
            vectors.extend(await self._embed_with_retry(batch))
        return tuple(vectors)

    async def _embed_with_retry(
        self,
        texts: list[str],
    ) -> tuple[EmbeddingVector, ...]:
        for attempt in range(MAX_APPLICATION_ATTEMPTS):
            try:
                return await self._embedder.embed_documents(texts)
            except EmbeddingProviderFailure:
                if attempt + 1 == MAX_APPLICATION_ATTEMPTS:
                    raise
                jitter = self._jitter()
                if not 0.0 <= jitter <= MAX_RETRY_JITTER_SECONDS:
                    raise IngestionConfigurationError from None
                await self._sleep(RETRY_BASE_SECONDS + jitter)
        raise IngestionProviderError

    async def _after_uncertain_failure(
        self,
        *,
        source: CorpusDocument,
        auth_context: AuthContext,
        document_id: str,
        document_version: str | None,
        content_hash: str | None,
        pii_status: PiiStatus | None,
        upsert_started: bool,
        cancelled: bool,
    ) -> tuple[IngestionManifestRecord, int]:
        error: IngestionError = IngestionCancelledError() if cancelled else IngestionProviderError()
        status = IngestionRecordStatus.CANCELLED if cancelled else IngestionRecordStatus.FAILED
        if not upsert_started or document_version is None:
            return (
                self._record(
                    source,
                    status,
                    pii_status=pii_status,
                    document_id=document_id,
                    document_version=document_version,
                    content_hash=content_hash,
                    error_code=error.code,
                ),
                error.exit_code,
            )
        if not await self._compensate(
            document_id,
            document_version,
            auth_context,
        ):
            rollback_error = IngestionRollbackIndeterminateError()
            return (
                self._record(
                    source,
                    IngestionRecordStatus.ROLLBACK_INDETERMINATE,
                    pii_status=pii_status,
                    document_id=document_id,
                    document_version=document_version,
                    content_hash=content_hash,
                    error_code=rollback_error.code,
                ),
                rollback_error.exit_code,
            )
        compensated_status = (
            IngestionRecordStatus.CANCELLED if cancelled else IngestionRecordStatus.COMPENSATED
        )
        return (
            self._record(
                source,
                compensated_status,
                pii_status=pii_status,
                document_id=document_id,
                document_version=document_version,
                content_hash=content_hash,
                error_code=error.code,
            ),
            error.exit_code,
        )

    async def _compensate(
        self,
        document_id: str,
        document_version: str,
        auth_context: AuthContext,
    ) -> bool:
        try:
            async with asyncio.timeout(VECTOR_OPERATION_TIMEOUT_SECONDS):
                await asyncio.shield(
                    self._vector_store.delete_by_document_version(
                        self._collection_spec,
                        document_id,
                        document_version,
                        auth_context,
                        timeout_seconds=VECTOR_OPERATION_TIMEOUT_SECONDS,
                    )
                )
        except (Exception, asyncio.CancelledError):
            return False
        return True

    def _record(
        self,
        source: CorpusDocument,
        status: IngestionRecordStatus,
        *,
        pii_status: PiiStatus | None = None,
        document_id: str | None = None,
        document_version: str | None = None,
        content_hash: str | None = None,
        chunk_count: int = 0,
        error_code: str | None = None,
    ) -> IngestionManifestRecord:
        return IngestionManifestRecord(
            source_path=source.source_path,
            source_id=source.source_id,
            tenant_id=source.tenant_id,
            media_type=source.media_type,
            status=status,
            pii_status=pii_status,
            document_id=document_id,
            document_version=document_version,
            content_hash=content_hash,
            chunk_count=chunk_count,
            error_code=error_code,
        )

    def _build_manifest(
        self,
        *,
        dataset_name: str,
        tenant_id: str,
        records: tuple[IngestionManifestRecord, ...],
        duration_ms: int,
        exit_code: int,
    ) -> IngestionManifest:
        return IngestionManifest(
            dataset_name=dataset_name,
            tenant_id=tenant_id,
            model_id=self._embedder.model_id,
            model_revision=self._embedder.model_revision,
            embedding_dimension=self._embedder.dimension,
            normalized_embeddings=self._embedder.normalized,
            tokenizer_id=self._tokenizer.tokenizer_id,
            tokenizer_revision=self._tokenizer.tokenizer_revision,
            selected_count=len(records),
            indexed_count=sum(record.status is IngestionRecordStatus.INDEXED for record in records),
            quarantined_count=sum(
                record.status
                in {
                    IngestionRecordStatus.QUARANTINED,
                    IngestionRecordStatus.REJECTED,
                }
                for record in records
            ),
            failed_count=sum(
                record.status
                in {
                    IngestionRecordStatus.FAILED,
                    IngestionRecordStatus.CANCELLED,
                    IngestionRecordStatus.ROLLBACK_INDETERMINATE,
                }
                for record in records
            ),
            compensated_count=sum(
                record.status is IngestionRecordStatus.COMPENSATED for record in records
            ),
            duration_ms=duration_ms,
            exit_code=exit_code,
            records=records,
        )

    @staticmethod
    def _highest_exit_code(exit_codes: Sequence[int]) -> int:
        for candidate in (5, 130, 4, 3):
            if candidate in exit_codes:
                return candidate
        return 0


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise IngestionConfigurationError


def build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="enterprise-ai-ingestion")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ingest_parser = subparsers.add_parser("ingest")
    ingest_parser.add_argument("--corpus-manifest", required=True, type=Path)
    ingest_parser.add_argument("--pii-policy", required=True, type=Path)
    ingest_parser.add_argument("--source-root", required=True, type=Path)
    ingest_parser.add_argument("--tenant-id", required=True)
    ingest_parser.add_argument("--embedder-provider", required=True, choices=("fake",))
    ingest_parser.add_argument("--vector-store-provider", required=True, choices=("fake",))
    ingest_parser.add_argument("--pii-provider", required=True, choices=("deterministic",))
    return parser


def _empty_error_manifest(exit_code: int) -> IngestionManifest:
    return IngestionManifest(
        dataset_name="unavailable",
        tenant_id="unavailable",
        tokenizer_id="unavailable",
        tokenizer_revision="unavailable",
        selected_count=0,
        indexed_count=0,
        quarantined_count=0,
        failed_count=0,
        compensated_count=0,
        duration_ms=0,
        exit_code=exit_code,
        records=(),
    )


async def _run(args: argparse.Namespace) -> IngestionOutcome:
    manifest = load_corpus_manifest(args.corpus_manifest)
    policy = load_pii_policy(args.pii_policy)
    embedder = FakeEmbeddingProvider()
    vector_store = InMemoryVectorStore()
    tokenizer = DeterministicTestTokenizer()
    pii_analyzer = SyntheticPiiAnalyzer()
    pipeline = IngestionPipeline(
        embedder=embedder,
        vector_store=vector_store,
        tokenizer=tokenizer,
        pii_analyzer=pii_analyzer,
        collection_spec=CollectionSpec(name=_COLLECTION_NAME),
    )
    auth_context = AuthContext(
        subject_id="w2-003-owner-cli",
        tenant_id=args.tenant_id,
        roles=frozenset({Role.INGESTOR}),
        clearance=Classification.RESTRICTED,
    )
    return await pipeline.ingest(
        manifest=manifest,
        source_root=args.source_root,
        pii_policy=policy,
        tenant_id=args.tenant_id,
        auth_context=auth_context,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        outcome = asyncio.run(_run(args))
        print(outcome.manifest.model_dump_json())
        if outcome.exit_code:
            print("Ingestion completed with a redacted non-success status.", file=sys.stderr)
        return outcome.exit_code
    except IngestionError as error:
        manifest = _empty_error_manifest(error.exit_code)
        print(manifest.model_dump_json())
        print(error.public_message, file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        cancellation_error = IngestionCancelledError()
        manifest = _empty_error_manifest(cancellation_error.exit_code)
        print(manifest.model_dump_json())
        print(cancellation_error.public_message, file=sys.stderr)
        return cancellation_error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
