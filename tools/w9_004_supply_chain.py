"""Owner-invoked W9-004 source and evidence validator; never deploys a model."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

from enterprise_ai_platform.json_contracts import JSONValue
from enterprise_ai_platform.model_supply_chain import (
    SupplyChainEligibility,
    canonical_bytes,
    inspect_model_archive,
    load_supply_chain_policy,
)
from enterprise_ai_platform.model_supply_chain.errors import ModelSupplyChainError


class UniqueSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueSafeLoader, node: yaml.Node, deep: bool = False) -> Any:
    result: dict[object, object] = {}
    for key_node, value_node in cast(yaml.MappingNode, node).value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _reject_duplicate_pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _private_output(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_bytes(payload))


def _read_json(path: Path) -> JSONValue:
    if not path.is_file() or path.stat().st_size > 52_428_800:
        raise ValueError("input must be a bounded regular JSON file")
    return cast(
        JSONValue,
        json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    validate_config = subcommands.add_parser("validate-config")
    validate_config.add_argument("--config", type=Path, default=Path("configs/ci/w9-004.json"))
    validate_evidence = subcommands.add_parser("validate-eligibility")
    validate_evidence.add_argument("--input", type=Path, required=True)
    inspect = subcommands.add_parser("inspect-model")
    inspect.add_argument("--config", type=Path, default=Path("configs/ci/w9-004.json"))
    inspect.add_argument("--input", type=Path, required=True)
    inspect.add_argument("--output", type=Path, required=True)
    validate_yaml = subcommands.add_parser("validate-yaml")
    validate_yaml.add_argument("--root", type=Path, default=Path("."))
    return parser


def _validate_yaml(root: Path) -> None:
    for path in sorted((*root.rglob("*.yaml"), *root.rglob("*.yml"))):
        if not path.is_file():
            raise ValueError("YAML input must be a regular file")
        if path.stat().st_size > 52_428_800:
            raise ValueError("YAML input exceeds the file limit")
        list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=UniqueSafeLoader))


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "validate-config":
            load_supply_chain_policy(arguments.config)
        elif arguments.command == "validate-eligibility":
            SupplyChainEligibility.model_validate(_read_json(arguments.input), strict=True)
        elif arguments.command == "inspect-model":
            policy = load_supply_chain_policy(arguments.config)
            inventory = inspect_model_archive(arguments.input, policy)
            _private_output(arguments.output, inventory)
        elif arguments.command == "validate-yaml":
            _validate_yaml(arguments.root)
        else:
            raise ValueError("unsupported command")
    except (ModelSupplyChainError, OSError, UnicodeError, ValueError) as error:
        print(f"W9-004 validation failed: {error}", file=sys.stderr)
        return 2
    print("W9-004 validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
