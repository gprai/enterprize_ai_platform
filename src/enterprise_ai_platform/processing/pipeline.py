"""Bounded processing, checkpoint, resume, and replay orchestration."""

from __future__ import annotations

import asyncio
import hashlib
from collections import Counter
from io import BytesIO
from typing import Protocol

from pypdf import PdfReader

from enterprise_ai_platform.ingestion.governance import (
    EmbeddingEligibility,
    canonical_sha256,
)
from enterprise_ai_platform.ingestion.normalization import decode_and_normalize, normalize_text

from .contracts import (
    BatchResult,
    DocumentDecision,
    DocumentRequest,
    MetricName,
    PreparedDocument,
    ProcessingBatchRequest,
    ProcessingCheckpoint,
    ProcessingConfig,
    ProcessingState,
    QualityReport,
    QualityStatus,
    ReplaySourceIdentity,
)
from .quality import CompatibleQualityEngine


class ProcessingError(RuntimeError):
    """Safe processing failure with a content-free reason code."""

    def __init__(self, safe_reason_code: str, *, retryable: bool = False) -> None:
        super().__init__(safe_reason_code)
        self.safe_reason_code = safe_reason_code
        self.retryable = retryable


class ReplaySourceProvider(Protocol):
    async def read(self, source: ReplaySourceIdentity) -> bytes: ...


class PiiVerifier(Protocol):
    async def verify(self, document: DocumentRequest, normalized_text: str) -> bool: ...


class ValidatedIndexer(Protocol):
    async def index(self, document: PreparedDocument) -> object: ...


class CheckpointStore(Protocol):
    def get(self, batch_id: str, document_id: str) -> ProcessingCheckpoint | None: ...
    def compare_and_set(
        self, expected: ProcessingCheckpoint | None, checkpoint: ProcessingCheckpoint
    ) -> None: ...


class QualityReportSink(Protocol):
    def write(self, report_identity: str, report: QualityReport) -> None: ...


class ProcessingRequestResolver(Protocol):
    def resolve(self, eligibility: EmbeddingEligibility) -> ProcessingBatchRequest: ...


class DeterministicExtractor:
    """Extract bounded text without provider or network access."""

    def extract(self, source: ReplaySourceIdentity, value: bytes) -> str:
        if len(value) != source.byte_count or len(value) > 5_242_880:
            raise ProcessingError("SOURCE_SIZE_MISMATCH")
        if hashlib.sha256(value).hexdigest() != source.content_sha256:
            raise ProcessingError("CONTENT_HASH_MISMATCH")
        if source.media_type in {"text/plain", "text/markdown"}:
            if b"\x00" in value or value.startswith(b"%PDF-"):
                raise ProcessingError("FILE_FORMAT_INVALID")
            try:
                return decode_and_normalize(value)
            except Exception:
                raise ProcessingError("ENCODING_OR_CONTENT_INVALID") from None
        if not value.startswith(b"%PDF-"):
            raise ProcessingError("FILE_FORMAT_INVALID")
        try:
            reader = PdfReader(BytesIO(value), strict=True)
            if reader.is_encrypted or len(reader.pages) > 50:
                raise ProcessingError("PDF_INVALID")
            parts: list[str] = []
            characters = 0
            for page in reader.pages:
                page_text = page.extract_text() or ""
                characters += len(page_text)
                if characters > 2_000_000:
                    raise ProcessingError("PDF_TOO_LARGE")
                parts.append(page_text)
            normalized = normalize_text("\n".join(parts))
            if not normalized.strip():
                raise ProcessingError("PDF_EMPTY")
            return normalized
        except ProcessingError:
            raise
        except Exception:
            raise ProcessingError("PDF_CORRUPT") from None


class ProcessingCoordinator:
    """Process one tenant's bounded batch sequentially and deterministically."""

    def __init__(
        self,
        *,
        config: ProcessingConfig,
        source_provider: ReplaySourceProvider,
        pii_verifier: PiiVerifier,
        indexer: ValidatedIndexer,
        checkpoint_store: CheckpointStore,
        report_sink: QualityReportSink,
        extractor: DeterministicExtractor | None = None,
    ) -> None:
        self._config = config
        self._source_provider = source_provider
        self._pii_verifier = pii_verifier
        self._indexer = indexer
        self._checkpoint_store = checkpoint_store
        self._report_sink = report_sink
        self._extractor = extractor or DeterministicExtractor()
        self._quality = CompatibleQualityEngine(config)

    async def _prepare(self, document: DocumentRequest) -> PreparedDocument:
        last_error: ProcessingError | None = None
        for attempt in range(self._config.processing.maximum_attempts):
            try:
                async with asyncio.timeout(self._config.processing.document_deadline_seconds):
                    value = await self._source_provider.read(document.source)
                    normalized = self._extractor.extract(document.source, value)
                return PreparedDocument(
                    document_id=document.document_id,
                    eligibility=document.eligibility,
                    source_identity_sha256=document.source.identity,
                    normalized_text=normalized,
                    normalized_content_sha256=hashlib.sha256(
                        normalized.encode("utf-8")
                    ).hexdigest(),
                    partition=document.partition,
                )
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                last_error = ProcessingError("EXTRACTION_DEADLINE_EXCEEDED", retryable=True)
            except ProcessingError as exc:
                last_error = exc
            except Exception:
                last_error = ProcessingError("SOURCE_PROVIDER_FAILURE", retryable=True)
            if last_error is not None and (not last_error.retryable or attempt == 1):
                raise last_error
        raise ProcessingError("EXTRACTION_RETRY_EXHAUSTED")

    async def process_batch(self, batch: ProcessingBatchRequest) -> BatchResult:
        try:
            async with asyncio.timeout(self._config.replay.maximum_duration_seconds):
                return await self._process_batch(batch)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise ProcessingError("REPLAY_DEADLINE_EXCEEDED") from None

    async def _process_batch(self, batch: ProcessingBatchRequest) -> BatchResult:
        if batch.policy_configuration_sha256 != self._config.identity:
            raise ProcessingError("POLICY_CONFIGURATION_MISMATCH")

        prepared: list[PreparedDocument] = []
        decisions: dict[str, DocumentDecision] = {}
        metrics: Counter[MetricName] = Counter()
        seen: dict[str, str] = {}
        resumed: set[str] = set()
        conflicts = self._quality.duplicate_conflicts(batch)

        for document in batch.documents:
            prior_checkpoint = self._checkpoint_store.get(batch.batch_id, document.document_id)
            if prior_checkpoint is not None:
                resumed.add(document.document_id)
                decisions[document.document_id] = DocumentDecision(
                    document_id=document.document_id,
                    state=prior_checkpoint.terminal_state,
                    state_history=(ProcessingState.RECEIVED, prior_checkpoint.terminal_state),
                    safe_reason_code="CHECKPOINT_REPLAY_SKIPPED",
                    source_identity_sha256=prior_checkpoint.source_identity_sha256,
                    normalized_content_sha256=prior_checkpoint.normalized_content_sha256,
                    checkpoint_sequence=prior_checkpoint.sequence,
                )
                continue
            key = document.eligibility.idempotency_key
            if key in conflicts:
                decisions[document.document_id] = self._decision(
                    document,
                    ProcessingState.QUARANTINED,
                    "IDEMPOTENCY_CONTENT_CONFLICT",
                    (ProcessingState.RECEIVED, ProcessingState.QUARANTINED),
                )
                continue
            prior_content = seen.setdefault(key, document.eligibility.content_sha256)
            if prior_content == document.eligibility.content_sha256 and sum(
                prior.eligibility.idempotency_key == key
                for prior in batch.documents[: batch.documents.index(document)]
            ):
                decisions[document.document_id] = self._decision(
                    document,
                    ProcessingState.SKIPPED_DUPLICATE,
                    "IDEMPOTENT_DUPLICATE_SKIPPED",
                    (ProcessingState.RECEIVED, ProcessingState.SKIPPED_DUPLICATE),
                )
                continue
            try:
                candidate = await self._prepare(document)
            except asyncio.CancelledError:
                raise
            except ProcessingError as exc:
                metrics[MetricName.EXTRACTION_FAILURE] += 1
                terminal = (
                    ProcessingState.DEAD_LETTERED if exc.retryable else ProcessingState.QUARANTINED
                )
                decisions[document.document_id] = self._decision(
                    document,
                    terminal,
                    exc.safe_reason_code,
                    (ProcessingState.RECEIVED, terminal),
                )
                continue
            try:
                pii_safe = await self._pii_verifier.verify(document, candidate.normalized_text)
            except asyncio.CancelledError:
                raise
            except Exception:
                pii_safe = False
            if not pii_safe:
                metrics[MetricName.PII_DETECTION_FAILURE] += 1
                decisions[document.document_id] = self._decision(
                    document,
                    ProcessingState.QUARANTINED,
                    "PII_DETECTION_FAILED",
                    (
                        ProcessingState.RECEIVED,
                        ProcessingState.EXTRACTED,
                        ProcessingState.QUARANTINED,
                    ),
                    candidate.normalized_content_sha256,
                )
                continue
            prepared.append(candidate)

        report = self._quality.evaluate(
            batch,
            tuple(prepared),
            quarantined_count=sum(
                decision.state in {ProcessingState.QUARANTINED, ProcessingState.DEAD_LETTERED}
                for decision in decisions.values()
            ),
            failure_metrics=metrics,
        )
        if not batch.dry_run:
            self._report_sink.write(report.identity, report)
            prepared_ids = {candidate.document_id for candidate in prepared}
            for decision in decisions.values():
                if decision.document_id not in resumed and decision.document_id not in prepared_ids:
                    self._write_checkpoint(batch.batch_id, decision, report.identity)
        if report.status is QualityStatus.FAIL:
            for candidate in prepared:
                decision = self._decision(
                    next(
                        document
                        for document in batch.documents
                        if document.document_id == candidate.document_id
                    ),
                    ProcessingState.QUARANTINED,
                    "BATCH_QUALITY_FAILED",
                    (
                        ProcessingState.RECEIVED,
                        ProcessingState.EXTRACTED,
                        ProcessingState.QUARANTINED,
                    ),
                    candidate.normalized_content_sha256,
                )
                decisions[candidate.document_id] = decision
                if not batch.dry_run:
                    self._write_checkpoint(batch.batch_id, decision, report.identity)
        else:
            for candidate in prepared:
                request = next(
                    document
                    for document in batch.documents
                    if document.document_id == candidate.document_id
                )
                if batch.dry_run:
                    decisions[candidate.document_id] = self._decision(
                        request,
                        ProcessingState.VALIDATED,
                        "DRY_RUN_VALIDATED",
                        (
                            ProcessingState.RECEIVED,
                            ProcessingState.EXTRACTED,
                            ProcessingState.VALIDATED,
                        ),
                        candidate.normalized_content_sha256,
                    )
                    continue
                try:
                    await self._index_with_retry(candidate)
                except ProcessingError as exc:
                    metric = (
                        MetricName.EMBEDDING_FAILURE
                        if exc.safe_reason_code == "EMBEDDING_RETRY_EXHAUSTED"
                        else MetricName.INDEXING_FAILURE
                    )
                    metrics[metric] += 1
                    decision = self._decision(
                        request,
                        ProcessingState.DEAD_LETTERED,
                        exc.safe_reason_code,
                        (
                            ProcessingState.RECEIVED,
                            ProcessingState.EXTRACTED,
                            ProcessingState.VALIDATED,
                            ProcessingState.DEAD_LETTERED,
                        ),
                        candidate.normalized_content_sha256,
                    )
                else:
                    decision = self._decision(
                        request,
                        ProcessingState.CURATED,
                        "CURATED_FOR_EMBEDDING_INDEX",
                        (
                            ProcessingState.RECEIVED,
                            ProcessingState.EXTRACTED,
                            ProcessingState.VALIDATED,
                            ProcessingState.CURATED,
                        ),
                        candidate.normalized_content_sha256,
                    )
                decisions[candidate.document_id] = decision
                self._write_checkpoint(batch.batch_id, decision, report.identity)

        report = self._quality.evaluate(
            batch,
            tuple(prepared),
            quarantined_count=sum(
                decision.state in {ProcessingState.QUARANTINED, ProcessingState.DEAD_LETTERED}
                for decision in decisions.values()
            ),
            failure_metrics=metrics,
        )
        ordered = tuple(decisions[document.document_id] for document in batch.documents)
        if not batch.dry_run:
            self._report_sink.write(report.identity, report)
        return BatchResult(
            schema_version="w7-002.batch-result.v1",
            batch_id=batch.batch_id,
            decisions=ordered,
            quality_report=report,
            dry_run=batch.dry_run,
        )

    async def _index_with_retry(self, document: PreparedDocument) -> None:
        for attempt in range(self._config.processing.maximum_attempts):
            try:
                async with asyncio.timeout(self._config.processing.document_deadline_seconds):
                    await self._indexer.index(document)
                return
            except asyncio.CancelledError:
                raise
            except ProcessingError as exc:
                if not exc.retryable or attempt + 1 == self._config.processing.maximum_attempts:
                    raise
            except Exception:
                if attempt + 1 == self._config.processing.maximum_attempts:
                    raise ProcessingError("INDEXING_RETRY_EXHAUSTED", retryable=True) from None

    def _write_checkpoint(
        self,
        batch_id: str,
        decision: DocumentDecision,
        quality_report_sha256: str,
    ) -> None:
        prior = self._checkpoint_store.get(batch_id, decision.document_id)
        checkpoint = ProcessingCheckpoint(
            schema_version="w7-002.checkpoint.v1",
            batch_id=batch_id,
            document_id=decision.document_id,
            sequence=decision.checkpoint_sequence,
            terminal_state=decision.state,
            source_identity_sha256=decision.source_identity_sha256,
            normalized_content_sha256=decision.normalized_content_sha256,
            quality_report_sha256=quality_report_sha256,
        )
        self._checkpoint_store.compare_and_set(prior, checkpoint)

    @staticmethod
    def _decision(
        document: DocumentRequest,
        state: ProcessingState,
        reason: str,
        history: tuple[ProcessingState, ...],
        normalized_hash: str | None = None,
    ) -> DocumentDecision:
        return DocumentDecision(
            document_id=document.document_id,
            state=state,
            state_history=history,
            safe_reason_code=reason,
            source_identity_sha256=document.source.identity,
            normalized_content_sha256=normalized_hash,
            checkpoint_sequence=1,
        )


class ProcessingPipelineRunner:
    """Adapter preserving W7-001's PipelineRunner signature."""

    def __init__(
        self,
        *,
        resolver: ProcessingRequestResolver,
        coordinator: ProcessingCoordinator,
    ) -> None:
        self._resolver = resolver
        self._coordinator = coordinator

    async def run(self, eligibility: EmbeddingEligibility) -> BatchResult:
        batch = self._resolver.resolve(eligibility)
        if not any(document.eligibility == eligibility for document in batch.documents):
            raise ProcessingError("HANDOFF_REQUEST_MISMATCH")
        return await self._coordinator.process_batch(batch)


def processing_contract_identity(config: ProcessingConfig) -> str:
    """Expose the exact configuration identity to workflow composition."""

    return canonical_sha256(config)
