"""Contract tests for runtime and development dependency separation."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_REQUIREMENTS = REPOSITORY_ROOT / "requirements.txt"
DEVELOPMENT_REQUIREMENTS = REPOSITORY_ROOT / "requirements-dev.txt"

EXPECTED_RUNTIME_PACKAGES = {
    "boto3",
    "botocore",
    "fastapi",
    "langchain",
    "langgraph",
    "opensearch-py",
    "opentelemetry-api",
    "opentelemetry-sdk",
    "presidio-analyzer",
    "presidio-anonymizer",
    "pypdf",
    "pydantic",
    "pydantic-settings",
    "pyyaml",
    "qdrant-client",
    "sentence-transformers",
    "tokenizers",
    "uvicorn",
}
EXPECTED_DEVELOPMENT_PACKAGES = {
    "deepeval",
    "detect-secrets",
    "httpx",
    "moto",
    "mypy",
    "pre-commit",
    "pytest",
    "ragas",
    "ruff",
    "testcontainers",
}
EXACT_DEVELOPMENT_REQUIREMENTS = {
    "detect-secrets==1.5.0",
    "pre-commit==4.6.2",
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


def test_every_direct_package_is_bounded_or_an_approved_exact_pin() -> None:
    development_specs = [
        line for line in requirement_lines(DEVELOPMENT_REQUIREMENTS) if not line.startswith("-r ")
    ]
    exact_development_specs = {
        requirement for requirement in development_specs if "==" in requirement
    }
    bounded_specs = requirement_lines(RUNTIME_REQUIREMENTS) + [
        requirement
        for requirement in development_specs
        if requirement not in EXACT_DEVELOPMENT_REQUIREMENTS
    ]

    assert exact_development_specs == EXACT_DEVELOPMENT_REQUIREMENTS
    assert all(">=" in requirement and ",<" in requirement for requirement in bounded_specs)


def test_default_requirements_contain_no_gpu_only_package() -> None:
    combined = "\n".join(
        requirement_lines(RUNTIME_REQUIREMENTS) + requirement_lines(DEVELOPMENT_REQUIREMENTS)
    ).casefold()

    forbidden_tokens = ("cuda", "nvidia", "-gpu", "fastembed-gpu", "onnx-gpu")
    assert not any(token in combined for token in forbidden_tokens)


def test_bedrock_sdk_versions_are_exactly_bounded_and_compatible() -> None:
    runtime_lines = requirement_lines(RUNTIME_REQUIREMENTS)

    assert "boto3>=1.43.77,<1.44" in runtime_lines
    assert "botocore>=1.43.77,<1.44" in runtime_lines


def test_opentelemetry_dependencies_are_minimal_and_exactly_bounded() -> None:
    runtime_lines = requirement_lines(RUNTIME_REQUIREMENTS)

    assert "opentelemetry-api>=1.44,<1.45" in runtime_lines
    assert "opentelemetry-sdk>=1.44,<1.45" in runtime_lines
    assert not any(
        package_name(line).startswith("opentelemetry-instrumentation") for line in runtime_lines
    )
    assert not any(
        package_name(line).startswith("opentelemetry-exporter") for line in runtime_lines
    )
