"""Contract tests for runtime and development dependency separation."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_REQUIREMENTS = REPOSITORY_ROOT / "requirements.txt"
DEVELOPMENT_REQUIREMENTS = REPOSITORY_ROOT / "requirements-dev.txt"

EXPECTED_RUNTIME_PACKAGES = {
    "boto3",
    "fastapi",
    "langchain",
    "langgraph",
    "opensearch-py",
    "opentelemetry-api",
    "opentelemetry-instrumentation-fastapi",
    "opentelemetry-sdk",
    "presidio-analyzer",
    "presidio-anonymizer",
    "pydantic",
    "pydantic-settings",
    "qdrant-client",
    "sentence-transformers",
    "uvicorn",
}
EXPECTED_DEVELOPMENT_PACKAGES = {
    "deepeval",
    "httpx",
    "moto",
    "mypy",
    "pytest",
    "ragas",
    "ruff",
    "testcontainers",
}


def requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def package_name(requirement: str) -> str:
    return re.split(r"[<>=!~\[]", requirement, maxsplit=1)[0].casefold()


def test_runtime_and_development_packages_are_separated() -> None:
    runtime_lines = requirement_lines(RUNTIME_REQUIREMENTS)
    development_lines = requirement_lines(DEVELOPMENT_REQUIREMENTS)
    development_specs = [line for line in development_lines if not line.startswith("-r ")]

    assert {package_name(line) for line in runtime_lines} == EXPECTED_RUNTIME_PACKAGES
    assert {package_name(line) for line in development_specs} == EXPECTED_DEVELOPMENT_PACKAGES
    assert development_lines[0] == "-r requirements.txt"
    assert EXPECTED_RUNTIME_PACKAGES.isdisjoint(EXPECTED_DEVELOPMENT_PACKAGES)


def test_every_direct_package_has_lower_and_upper_bounds() -> None:
    direct_specs = requirement_lines(RUNTIME_REQUIREMENTS) + [
        line
        for line in requirement_lines(DEVELOPMENT_REQUIREMENTS)
        if not line.startswith("-r ")
    ]

    assert all(">=" in requirement and ",<" in requirement for requirement in direct_specs)


def test_default_requirements_contain_no_gpu_only_package() -> None:
    combined = "\n".join(
        requirement_lines(RUNTIME_REQUIREMENTS)
        + requirement_lines(DEVELOPMENT_REQUIREMENTS)
    ).casefold()

    forbidden_tokens = ("cuda", "nvidia", "-gpu", "fastembed-gpu", "onnx-gpu")
    assert not any(token in combined for token in forbidden_tokens)
