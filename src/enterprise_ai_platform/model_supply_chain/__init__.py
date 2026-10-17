"""W9-004 immutable model supply-chain controls."""

from .errors import ModelSupplyChainError, SupplyChainAdmissionError, SupplyChainValidationError
from .models import (
    CandidateIdentity,
    EligibilityStatus,
    EvidenceStatus,
    Finding,
    ModelInventory,
    OpaDecision,
    ProvenanceEvidence,
    RiskTreatment,
    SbomEvidence,
    ScannerEvidence,
    Severity,
    SourceLicenseEvidence,
    SupplyChainEligibility,
)
from .policy import SupplyChainPolicy, load_supply_chain_policy
from .serialization import canonical_bytes, fingerprint
from .service import (
    inspect_model_archive,
    reconcile_candidate,
    require_registry_eligible,
    scanner_disagreement,
)

__all__ = [
    "CandidateIdentity",
    "EligibilityStatus",
    "EvidenceStatus",
    "Finding",
    "ModelInventory",
    "ModelSupplyChainError",
    "OpaDecision",
    "ProvenanceEvidence",
    "RiskTreatment",
    "SbomEvidence",
    "ScannerEvidence",
    "Severity",
    "SourceLicenseEvidence",
    "SupplyChainAdmissionError",
    "SupplyChainEligibility",
    "SupplyChainPolicy",
    "SupplyChainValidationError",
    "canonical_bytes",
    "fingerprint",
    "inspect_model_archive",
    "load_supply_chain_policy",
    "reconcile_candidate",
    "require_registry_eligible",
    "scanner_disagreement",
]
