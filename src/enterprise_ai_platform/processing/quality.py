"""Deterministic Great Expectations-compatible W7-002 quality checks."""

from __future__ import annotations

from collections import Counter

from enterprise_ai_platform.ingestion.governance import canonical_sha256

from .contracts import (
    MetricCount,
    MetricName,
    PreparedDocument,
    ProcessingBatchRequest,
    ProcessingConfig,
    QualityObservation,
    QualityReport,
    QualityStatus,
)


class CompatibleQualityEngine:
    """Evaluate approved expectations without coupling to a vendor runtime."""

    def __init__(self, config: ProcessingConfig) -> None:
        self._config = config

    def evaluate(
        self,
        batch: ProcessingBatchRequest,
        prepared: tuple[PreparedDocument, ...],
        *,
        quarantined_count: int,
        failure_metrics: Counter[MetricName] | None = None,
    ) -> QualityReport:
        identities = [document.eligibility.idempotency_key for document in batch.documents]
        duplicate_count = len(identities) - len(set(identities))
        unique_count = len(identities) - duplicate_count
        conflicts = self.duplicate_conflicts(batch)
        observed_ratio = len(batch.documents) / batch.expected_document_count
        volume_status = (
            QualityStatus.PASS
            if self._config.quality.volume_minimum_ratio
            <= observed_ratio
            <= self._config.quality.volume_maximum_ratio
            else QualityStatus.FAIL
        )
        duplicate_ratio = duplicate_count / len(batch.documents)
        if conflicts:
            duplicate_status = QualityStatus.FAIL
        elif len(batch.documents) < self._config.quality.minimum_drift_sample:
            duplicate_status = QualityStatus.INSUFFICIENT_SAMPLE
        elif duplicate_ratio <= self._config.quality.duplicate_pass_maximum_ratio:
            duplicate_status = QualityStatus.PASS
        elif duplicate_ratio <= self._config.quality.duplicate_warning_maximum_ratio:
            duplicate_status = QualityStatus.WARNING
        else:
            duplicate_status = QualityStatus.FAIL

        schema_failures = sum(
            document.observed_fields != self._config.quality.required_fields
            for document in batch.documents
        )
        schema_status = QualityStatus.PASS if schema_failures == 0 else QualityStatus.FAIL
        statuses = (volume_status, duplicate_status, schema_status)
        status = (
            QualityStatus.FAIL
            if QualityStatus.FAIL in statuses
            else QualityStatus.WARNING
            if QualityStatus.WARNING in statuses
            else QualityStatus.INSUFFICIENT_SAMPLE
            if QualityStatus.INSUFFICIENT_SAMPLE in statuses
            else QualityStatus.PASS
        )
        metrics = Counter(failure_metrics or {})
        metrics[MetricName.DUPLICATE] += duplicate_count
        metrics[MetricName.SCHEMA_DRIFT] += schema_failures
        metrics[MetricName.VOLUME_DRIFT] += int(volume_status is QualityStatus.FAIL)
        return QualityReport(
            schema_version="w7-002.quality-report.v1",
            batch_id=batch.batch_id,
            tenant_id=batch.tenant_id,
            policy_configuration_sha256=batch.policy_configuration_sha256,
            threshold_identity_sha256=canonical_sha256(self._config.quality),
            status=status,
            input_count=len(batch.documents),
            unique_count=unique_count,
            duplicate_count=duplicate_count,
            quarantined_count=quarantined_count,
            observations=(
                QualityObservation(
                    check_name="required_fields",
                    status=schema_status,
                    observed=str(len(self._config.quality.required_fields) - schema_failures),
                    threshold=str(len(self._config.quality.required_fields)),
                    safe_reason_code="SCHEMA_DRIFT" if schema_failures else None,
                ),
                QualityObservation(
                    check_name="volume_ratio",
                    status=volume_status,
                    observed=f"{observed_ratio:.6f}",
                    threshold="0.500000..2.000000",
                    safe_reason_code=(
                        "VOLUME_DRIFT" if volume_status is QualityStatus.FAIL else None
                    ),
                ),
                QualityObservation(
                    check_name="duplicate_ratio",
                    status=duplicate_status,
                    observed=f"{duplicate_ratio:.6f}",
                    threshold="pass<=0.050000;warning<=0.100000",
                    safe_reason_code=(
                        "DUPLICATE_RATE_DRIFT" if duplicate_status is QualityStatus.FAIL else None
                    ),
                ),
            ),
            metrics=tuple(
                MetricCount(
                    name=name,
                    count=metrics[name],
                    total=len(batch.documents),
                    rate=metrics[name] / len(batch.documents),
                )
                for name in MetricName
            ),
            generated_at=batch.requested_at,
        )

    @staticmethod
    def duplicate_conflicts(batch: ProcessingBatchRequest) -> frozenset[str]:
        """Return idempotency keys reused with different content identities."""

        seen: dict[str, str] = {}
        conflicts: set[str] = set()
        for document in batch.documents:
            key = document.eligibility.idempotency_key
            content = document.eligibility.content_sha256
            prior = seen.setdefault(key, content)
            if prior != content:
                conflicts.add(key)
        return frozenset(conflicts)
