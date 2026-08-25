from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]
APPROVED_EXTERNAL_CACHE_ROOT = PureWindowsPath(
    r"E:\AI\.model-cache\enterprise_ai_platform\W2-002"
)
REPOSITORY_CACHE_PATHS = (
    ROOT / ".cache" / "huggingface",
    ROOT / ".cache" / "torch",
    ROOT / ".cache" / "sentence_transformers",
    ROOT / ".cache" / "sentence-transformers",
    ROOT / ".model-cache",
    ROOT / "models--sentence-transformers--all-MiniLM-L6-v2",
)
CACHE_ENVIRONMENT_VARIABLES = (
    "HF_HOME",
    "HUGGINGFACE_HUB_CACHE",
    "TRANSFORMERS_CACHE",
    "TORCH_HOME",
    "SENTENCE_TRANSFORMERS_HOME",
    "HF_ASSETS_CACHE",
    "XDG_CACHE_HOME",
)
FORBIDDEN_DIRECTORY_NAMES = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "htmlcov",
}
FORBIDDEN_MODEL_ARTIFACT_NAMES = {
    "model.safetensors",
    "pytorch_model.bin",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
}


def test_w2_002_leaves_no_repository_cache_weight_or_python_artifacts() -> None:
    assert all(not path.exists() for path in REPOSITORY_CACHE_PATHS)

    findings: list[str] = []
    for path in ROOT.rglob("*"):
        relative_path = path.relative_to(ROOT)
        if ".git" in relative_path.parts:
            continue
        if path.is_dir() and path.name in FORBIDDEN_DIRECTORY_NAMES:
            findings.append(str(relative_path))
        elif path.is_file() and (
            path.name in FORBIDDEN_MODEL_ARTIFACT_NAMES
            or path.suffix.casefold() in {".pyc", ".pyo"}
        ):
            findings.append(str(relative_path))

    assert findings == []


def test_all_model_cache_environment_variables_resolve_outside_repository() -> None:
    for variable in CACHE_ENVIRONMENT_VARIABLES:
        value = os.environ.get(variable)
        if value:
            assert not Path(value).resolve().is_relative_to(ROOT)


def test_approved_external_cache_is_intentional_and_outside_repository() -> None:
    repository = PureWindowsPath(str(ROOT))

    assert APPROVED_EXTERNAL_CACHE_ROOT.drive == "E:"
    assert APPROVED_EXTERNAL_CACHE_ROOT == PureWindowsPath(
        r"E:\AI\.model-cache\enterprise_ai_platform\W2-002"
    )
    assert not APPROVED_EXTERNAL_CACHE_ROOT.is_relative_to(repository)


def test_no_embedding_model_cache_exists_inside_repository() -> None:
    assert all(not path.exists() for path in REPOSITORY_CACHE_PATHS)


def test_configured_model_caches_do_not_point_inside_repository() -> None:
    for variable in (
        "HF_HOME",
        "HUGGINGFACE_HUB_CACHE",
        "TRANSFORMERS_CACHE",
        "TORCH_HOME",
    ):
        value = os.environ.get(variable)
        if value:
            assert not Path(value).resolve().is_relative_to(ROOT)
