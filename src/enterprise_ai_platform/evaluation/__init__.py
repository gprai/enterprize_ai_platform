"""Provider-neutral deterministic offline evaluation contracts."""

from .config import EvaluationConfig, load_evaluation_config
from .dataset import canonical_dataset_bytes, load_golden_dataset
from .evaluator import DeterministicRAGEvaluator, Evaluator
from .models import EvaluationReport, GoldenCase, GoldenDataset

__all__ = [
    "DeterministicRAGEvaluator",
    "EvaluationConfig",
    "EvaluationReport",
    "Evaluator",
    "GoldenCase",
    "GoldenDataset",
    "canonical_dataset_bytes",
    "load_evaluation_config",
    "load_golden_dataset",
]
