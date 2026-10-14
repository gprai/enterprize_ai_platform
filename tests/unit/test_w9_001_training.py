"""Unit tests for immutable W9-001 training identities and gates."""

import pytest

from enterprise_ai_platform.training import (
    Accelerator,
    CacheEntry,
    Hyperparameter,
    PeftRequest,
    TrainingCapabilityError,
    TrainingContainerIdentity,
    detect_capability,
    fingerprint,
)
from tests.fakes.w9_001_training import FakeTorchRuntime, make_request


def test_request_and_identity_serialization_are_deterministic() -> None:
    request = make_request()

    assert fingerprint(request) == fingerprint(request)
    assert request.model.trust_remote_code is False
    assert request.model.local_files_only is True
    assert request.model.use_safetensors is True


def test_cpu_probe_never_touches_gpu_methods() -> None:
    evidence = detect_capability(FakeTorchRuntime(), Accelerator.CPU)

    assert evidence.accelerator is Accelerator.CPU
    assert evidence.available is True
    assert evidence.device_count == 0


def test_unavailable_gpu_fails_closed() -> None:
    with pytest.raises(TrainingCapabilityError, match="unavailable"):
        detect_capability(FakeTorchRuntime(), Accelerator.GPU)


def test_cache_traversal_and_incomplete_peft_are_rejected() -> None:
    with pytest.raises(ValueError, match="safe relative"):
        CacheEntry(path="../model.bin", size_bytes=1, sha256="a" * 64)
    with pytest.raises(ValueError, match="exactly when"):
        PeftRequest(enabled=False, method="lora", rank=8, target_modules=("q_proj",))


def test_mutable_or_substituted_container_identity_is_rejected() -> None:
    with pytest.raises(ValueError, match="immutable digest"):
        TrainingContainerIdentity(
            registry_uri="registry.example.invalid/training:latest",
            image_digest=f"sha256:{'a' * 64}",
        )
    with pytest.raises(ValueError, match="differ"):
        TrainingContainerIdentity(
            registry_uri=f"registry.example.invalid/training@sha256:{'a' * 64}",
            image_digest=f"sha256:{'b' * 64}",
        )


def test_reordered_or_duplicate_hyperparameters_are_rejected() -> None:
    payload = make_request().model_dump(mode="python")
    payload["hyperparameters"] = (
        Hyperparameter(key="zeta", value="1"),
        Hyperparameter(key="alpha", value="1"),
    )
    with pytest.raises(ValueError, match="sorted and unique"):
        type(make_request()).model_validate(payload, strict=True)
