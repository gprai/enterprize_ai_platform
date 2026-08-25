from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from enterprise_ai_platform.embeddings.errors import EmbeddingProviderFailure
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = (
    REPOSITORY_ROOT
    / "src"
    / "enterprise_ai_platform"
    / "embeddings"
    / "sentence_transformer.py"
)
SENSITIVE_NAME_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "credential",
    "apikey",
    "url",
    "endpoint",
    "snapshot",
    "externalmodel",
    "modelpath",
)


def test_adapter_ast_rejects_direct_vendor_imports_and_preserves_safety_controls() -> None:
    source = ADAPTER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.append(node.module)

    assert not any(
        module == "sentence_transformers"
        or module.startswith("sentence_transformers.")
        for module in imported_modules
    )
    assert 'importlib.import_module("sentence_transformers")' in source
    assert "local_files_only=True" in source
    assert "trust_remote_code=False" in source
    assert "token=False" in source
    assert 'device="cpu"' in source
    assert "asyncio.to_thread" in source
    assert "http://" not in source
    assert "https://" not in source


def test_fake_provider_state_has_no_sensitive_identifier_fragments() -> None:
    provider = FakeEmbeddingProvider()
    for name in vars(provider):
        normalized = "".join(character for character in name if character.isalnum())
        assert not any(
            fragment in normalized.casefold() for fragment in SENSITIVE_NAME_FRAGMENTS
        )


def test_adapter_has_no_eager_sentence_transformers_import() -> None:
    tree = ast.parse(ADAPTER_PATH.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert "sentence_transformers" not in imported_modules


def test_failure_does_not_disclose_input_text() -> None:
    secret = "tenant-secret-never-log"

    with pytest.raises(EmbeddingProviderFailure) as caught:
        asyncio.run(FakeEmbeddingProvider(fail=True).embed_query(secret))

    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)


def test_fake_provider_has_no_network_or_external_model_configuration() -> None:
    provider_state = vars(FakeEmbeddingProvider())

    assert "token" not in provider_state
    assert "url" not in provider_state
    assert "snapshot" not in provider_state
