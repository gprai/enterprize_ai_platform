"""Stable redacted errors for deterministic offline evaluation."""

from __future__ import annotations


class EvaluationError(Exception):
    """Base error whose public representation contains no evaluated content."""

    code = "evaluation_error"

    def __init__(self) -> None:
        super().__init__(self.code)


class EvaluationDatasetError(EvaluationError):
    code = "invalid_dataset"


class EvaluationSourceReferenceError(EvaluationError):
    code = "invalid_source_reference"


class EvaluationConfigurationError(EvaluationError):
    code = "invalid_configuration"


class DuplicateEvaluationCaseError(EvaluationDatasetError):
    code = "duplicate_case"


class EvaluationResultError(EvaluationError):
    code = "incomplete_evaluation"


class EvaluationThresholdError(EvaluationError):
    code = "threshold_failure"


class EvaluationSecurityError(EvaluationError):
    code = "hard_security_blocker"


class EvaluationReportExistsError(EvaluationError):
    code = "report_target_already_exists"


class EvaluationReportWriteError(EvaluationError):
    code = "report_write_failure"


class IncompatibleBaselineError(EvaluationError):
    code = "incompatible_baseline"


class MissingApprovedBaselineError(EvaluationError):
    code = "missing_approved_baseline"


class PromotionChecksumError(EvaluationError):
    code = "promotion_checksum_mismatch"


class PromotionTargetExistsError(EvaluationError):
    code = "promotion_target_already_exists"


class RAGSafetyDatasetError(EvaluationError):
    code = "rag_safety_dataset_invalid"


class RAGSafetyPolicyError(EvaluationError):
    code = "rag_safety_policy_invalid"


class RAGSafetyIdentityError(EvaluationError):
    code = "rag_safety_identity_invalid"


class RAGSafetyResultError(EvaluationError):
    code = "rag_safety_result_invalid"


class RAGSafetyEvidenceError(EvaluationError):
    code = "rag_safety_evidence_invalid"
