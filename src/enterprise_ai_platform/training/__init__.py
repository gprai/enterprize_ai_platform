"""Offline governed training contracts for W9-001."""

from .capabilities import detect_capability
from .errors import (
    TrainingAdmissionError,
    TrainingAuthorizationError,
    TrainingCapabilityError,
    TrainingError,
    TrainingValidationError,
)
from .models import (
    Accelerator,
    CacheEntry,
    CapabilityEvidence,
    CleanupPlan,
    Hyperparameter,
    ModelSourceIdentity,
    PeftRequest,
    ResourceRequest,
    TrainingApproval,
    TrainingCacheManifest,
    TrainingCodeIdentity,
    TrainingContainerIdentity,
    TrainingDataIdentity,
    TrainingOutcome,
    TrainingRequest,
    TrainingResult,
)
from .policy import DEFAULT_POLICY_PATH, TrainingPolicy, load_training_policy
from .sagemaker import OfflineSageMakerProvider, render_training_request
from .serialization import canonical_json, fingerprint
from .service import TenantTrainingAuthorizer, TrainingService

__all__ = [
    "DEFAULT_POLICY_PATH",
    "Accelerator",
    "CacheEntry",
    "CapabilityEvidence",
    "CleanupPlan",
    "Hyperparameter",
    "ModelSourceIdentity",
    "OfflineSageMakerProvider",
    "PeftRequest",
    "ResourceRequest",
    "TenantTrainingAuthorizer",
    "TrainingAdmissionError",
    "TrainingApproval",
    "TrainingAuthorizationError",
    "TrainingCacheManifest",
    "TrainingCapabilityError",
    "TrainingCodeIdentity",
    "TrainingContainerIdentity",
    "TrainingDataIdentity",
    "TrainingError",
    "TrainingOutcome",
    "TrainingPolicy",
    "TrainingRequest",
    "TrainingResult",
    "TrainingService",
    "TrainingValidationError",
    "canonical_json",
    "detect_capability",
    "fingerprint",
    "load_training_policy",
    "render_training_request",
]
