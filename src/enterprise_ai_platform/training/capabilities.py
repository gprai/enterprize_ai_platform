"""Bounded, injectable CPU/GPU capability detection."""

from __future__ import annotations

from .contracts import TorchRuntime
from .errors import TrainingCapabilityError
from .models import Accelerator, CapabilityEvidence


def detect_capability(runtime: TorchRuntime, requested: Accelerator) -> CapabilityEvidence:
    version = runtime.version
    if not version or len(version) > 80:
        raise TrainingCapabilityError("invalid runtime version")
    if requested is Accelerator.CPU:
        return CapabilityEvidence(
            accelerator=Accelerator.CPU,
            available=True,
            device_count=0,
            runtime_version=version,
        )
    try:
        available = runtime.cuda_available()
        count = runtime.cuda_device_count()
    except Exception as error:
        raise TrainingCapabilityError("GPU capability probe failed") from error
    if not available or count < 1 or count > 64:
        raise TrainingCapabilityError("requested GPU capability is unavailable")
    return CapabilityEvidence(
        accelerator=Accelerator.GPU,
        available=True,
        device_count=count,
        runtime_version=version,
    )
