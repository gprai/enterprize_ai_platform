"""Checkpointed owner orchestration for prepare, provision, release, and cleanup.

Terraform operations execute in HCP. The existing protected GitHub and CodeBuild
workflow remains the application deployment authority.  The run context
is a secret-free restart aid; it is never an approval, plan, state, or release
authority.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast

from tools import capstone_release as release_engine

from provision import bindings, cleanup, hcp, iam_handoff, kubernetes
from provision.services import ServiceError, Services
from provision.setup import ensure_setup, source_identity

SCHEMA_VERSION: Final = "enterprise-ai.lifecycle-context.v1"
MAX_CONTEXT_LIFETIME: Final = timedelta(hours=24)
DEFAULT_CONTEXT_ROOT: Final = Path(r"E:\AI\evidence\enterprise_ai_platform\W12")
REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
APPROVED_ACCOUNT: Final = "526338061652"
APPROVED_REGION: Final = "ap-southeast-1"
APPROVED_ENVIRONMENT: Final = "sandbox"
APPROVED_EXECUTOR: Final = "Gyan-Prakash-Rai"

_HEX40 = frozenset("0123456789abcdef")
_HEX64 = _HEX40
_PROHIBITED_FIELD_PARTS = (
    "authorization",
    "credential",
    "kubeconfig",
    "password",
    "private_key",
    "raw_plan",
    "raw_state",
    "secret",
    "session_token",
    "token",
)
_TERMINAL_PHASES = frozenset({"RELEASE_COMPLETE", "ROLLBACK_COMPLETE", "TEARDOWN_COMPLETE"})


class LifecycleError(RuntimeError):
    """A fail-closed orchestration or context error."""

    def __init__(self, code: str, classification: str = "FAIL") -> None:
        super().__init__(code)
        self.code = code
        self.classification = classification


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleError(f"{label.upper()}_INVALID") from exc
    if parsed.tzinfo is None:
        raise LifecycleError(f"{label.upper()}_TIMEZONE_REQUIRED")
    return parsed.astimezone(UTC)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_hex(value: object, length: int, code: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(c not in _HEX64 for c in value):
        raise LifecycleError(code)
    return value


def _validate_no_sensitive_fields(value: object, path: str = "context") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise LifecycleError("CONTEXT_FIELD_NAME_INVALID")
            normalized = key.lower()
            if any(part in normalized for part in _PROHIBITED_FIELD_PARTS):
                raise LifecycleError(f"PROHIBITED_CONTEXT_FIELD:{path}.{key}")
            _validate_no_sensitive_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_sensitive_fields(child, f"{path}[{index}]")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise LifecycleError(f"CONTEXT_VALUE_INVALID:{path}")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise LifecycleError("CONTEXT_DIRECTORY_PERMISSION_FAILED") from exc


def _atomic_write(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise LifecycleError("CONTEXT_ATOMIC_WRITE_FAILED") from exc


def _repository_identity() -> tuple[str, str]:
    executable = shutil.which("git")
    if executable is None:
        raise LifecycleError("GIT_EXECUTABLE_UNAVAILABLE")

    def git(*arguments: str) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed git executable and read-only arguments
            [executable, "-C", str(REPOSITORY_ROOT), *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise LifecycleError("REPOSITORY_IDENTITY_UNAVAILABLE")
        return result.stdout.strip()

    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    _validate_hex(commit, 40, "SOURCE_COMMIT_INVALID")
    _validate_hex(tree, 40, "SOURCE_TREE_INVALID")
    return commit, tree


def _resolve_external_file(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LifecycleError(f"{label.upper()}_UNAVAILABLE") from exc
    if not resolved.is_file() or _is_relative_to(resolved, REPOSITORY_ROOT):
        raise LifecycleError(f"{label.upper()}_MUST_BE_EXTERNAL_FILE")
    return resolved


def _resolve_external_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LifecycleError(f"{label.upper()}_UNAVAILABLE") from exc
    if not resolved.is_dir() or _is_relative_to(resolved, REPOSITORY_ROOT):
        raise LifecycleError(f"{label.upper()}_MUST_BE_EXTERNAL_DIRECTORY")
    return resolved


class ContextStore:
    """Canonical active/completed context store with per-run exclusion."""

    def __init__(self, root: Path = DEFAULT_CONTEXT_ROOT) -> None:
        self.root = root.resolve()
        if _is_relative_to(self.root, REPOSITORY_ROOT):
            raise LifecycleError("CONTEXT_ROOT_MUST_BE_EXTERNAL")
        self.active = self.root / "active"
        self.completed = self.root / "completed"
        _secure_directory(self.active)
        _secure_directory(self.completed)

    def run_directory(self, run_id: str, *, completed: bool = False) -> Path:
        try:
            parsed = uuid.UUID(run_id)
        except ValueError as exc:
            raise LifecycleError("RUN_ID_INVALID") from exc
        if parsed.version != 4 or str(parsed) != run_id:
            raise LifecycleError("RUN_ID_INVALID")
        base = self.completed if completed else self.active
        target = (base / run_id).resolve()
        if not _is_relative_to(target, base.resolve()):
            raise LifecycleError("RUN_PATH_ESCAPE")
        return target

    def create(self, context: dict[str, Any]) -> Path:
        _validate_context(context, allow_expired=False)
        directory = self.run_directory(cast(str, context["run_id"]))
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise LifecycleError("RUN_CONTEXT_ALREADY_EXISTS") from exc
        raw = _canonical_bytes(context)
        _atomic_write(directory / "context.json", raw)
        _atomic_write(directory / "context.sha256", (_sha256(raw) + "\n").encode("ascii"))
        return directory / "context.json"

    def load(self, run_id: str, *, allow_expired: bool = False) -> dict[str, Any]:
        directory = self.run_directory(run_id)
        context_path = directory / "context.json"
        digest_path = directory / "context.sha256"
        try:
            raw = context_path.read_bytes()
            sidecar = digest_path.read_text(encoding="ascii")
            value = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise LifecycleError("RUN_CONTEXT_UNAVAILABLE_OR_INVALID") from exc
        if raw != _canonical_bytes(value) or sidecar != _sha256(raw) + "\n":
            raise LifecycleError("RUN_CONTEXT_INTEGRITY_MISMATCH")
        if not isinstance(value, dict):
            raise LifecycleError("RUN_CONTEXT_OBJECT_REQUIRED")
        context = cast(dict[str, Any], value)
        _validate_context(context, allow_expired=allow_expired)
        if context["run_id"] != run_id:
            raise LifecycleError("RUN_CONTEXT_ID_MISMATCH")
        return context

    def save(self, context: dict[str, Any]) -> None:
        _validate_context(context, allow_expired=True)
        directory = self.run_directory(cast(str, context["run_id"]))
        if not directory.is_dir():
            raise LifecycleError("RUN_CONTEXT_NOT_ACTIVE")
        raw = _canonical_bytes(context)
        _atomic_write(directory / "context.json", raw)
        _atomic_write(directory / "context.sha256", (_sha256(raw) + "\n").encode("ascii"))

    @contextlib.contextmanager
    def lock(self, run_id: str) -> Any:
        directory = self.run_directory(run_id)
        lock_path = directory / "operation.lock"
        try:
            descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise LifecycleError("RUN_OPERATION_ALREADY_ACTIVE", "INDETERMINATE") from exc
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(f"{os.getpid()}\n")
            yield
        finally:
            with contextlib.suppress(OSError):
                lock_path.unlink()

    def complete(self, context: dict[str, Any]) -> Path:
        if context.get("phase") not in _TERMINAL_PHASES:
            raise LifecycleError("TERMINAL_PHASE_REQUIRED")
        run_id = cast(str, context["run_id"])
        active = self.run_directory(run_id)
        completed = self.run_directory(run_id, completed=True)
        if completed.exists():
            raise LifecycleError("COMPLETED_CONTEXT_ALREADY_EXISTS")
        summary = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "operation": context["operation"],
            "phase": context["phase"],
            "classification": context["classification"],
            "created_at": context["created_at"],
            "completed_at": _timestamp(_utc_now()),
            "source": context["source"],
            "results": context["results"],
            "bindings": context["bindings"],
            "checkpoints": context["checkpoints"],
            "retention": context["retention"],
        }
        _validate_no_sensitive_fields(summary)
        raw = _canonical_bytes(summary)
        _atomic_write(active / "context-summary.json", raw)
        _atomic_write(active / "context-summary.sha256", (_sha256(raw) + "\n").encode("ascii"))
        # Same-volume atomic rename preserves nested receipts/proofs. Never delete evidence.
        active.rename(completed)
        (completed / "operation.lock").unlink(missing_ok=True)
        return completed / "context-summary.json"


def _validate_context(context: dict[str, Any], *, allow_expired: bool) -> None:
    required = {
        "schema_version",
        "run_id",
        "operation",
        "phase",
        "classification",
        "created_at",
        "expires_at",
        "source",
        "bindings",
        "checkpoints",
        "results",
        "retention",
    }
    if set(context) != required or context.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("RUN_CONTEXT_SCHEMA_MISMATCH")
    _validate_no_sensitive_fields(context)
    try:
        parsed_id = uuid.UUID(cast(str, context["run_id"]))
    except (ValueError, TypeError) as exc:
        raise LifecycleError("RUN_ID_INVALID") from exc
    if parsed_id.version != 4 or str(parsed_id) != context["run_id"]:
        raise LifecycleError("RUN_ID_INVALID")
    if context["operation"] not in {"deploy", "rollback", "teardown", "bootstrap-teardown"}:
        raise LifecycleError("OPERATION_INVALID")
    if context["classification"] not in {"NOT RUN", "PASS", "FAIL", "INDETERMINATE"}:
        raise LifecycleError("CLASSIFICATION_INVALID")
    created = _parse_timestamp(cast(str, context["created_at"]), "created_at")
    expires = _parse_timestamp(cast(str, context["expires_at"]), "expires_at")
    if expires <= created or expires - created > MAX_CONTEXT_LIFETIME:
        raise LifecycleError("CONTEXT_LIFETIME_INVALID")
    if not allow_expired and expires <= _utc_now():
        raise LifecycleError("RUN_CONTEXT_EXPIRED")
    source = context["source"]
    if not isinstance(source, dict):
        raise LifecycleError("SOURCE_IDENTITY_INVALID")
    _validate_hex(source.get("commit"), 40, "SOURCE_COMMIT_INVALID")
    _validate_hex(source.get("tree"), 40, "SOURCE_TREE_INVALID")
    retention = context["retention"]
    if retention != {
        "bootstrap": "RETAIN",
        "bootstrap_owned_iam": "RETAIN",
        "canonical_evidence": "RETAIN",
        "decrypting_kms_access": "RETAIN",
    }:
        raise LifecycleError("RETENTION_DEFAULTS_CHANGED")


def _confirmation(expected: str) -> None:
    if not sys.stdin.isatty():
        raise LifecycleError("OWNER_CONFIRMATION_TTY_REQUIRED")
    if input(f"Type {expected} to continue: ") != expected:
        raise LifecycleError("OWNER_DID_NOT_CONFIRM")


def _report(phase: str, result: dict[str, Any], run_id: str = "setup") -> Path:
    """Only caller-selected metadata is logged; never subprocess output or API payloads."""
    if run_id != "setup":
        try:
            run_id = str(uuid.UUID(run_id))
        except ValueError:
            run_id = "invalid-run-id"
    directory = REPOSITORY_ROOT / "report" / run_id
    _secure_directory(directory)
    stamp = _utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"{stamp}-{phase}.json"
    _atomic_write(path, _canonical_bytes(result))
    return path


def _inputs(path: Path) -> dict[str, Any]:
    path = _resolve_external_file(path, label="inputs")
    value = json.loads(path.read_bytes(), object_pairs_hook=release_engine._unique_pairs)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "enterprise-ai.lifecycle-inputs.v1"
    ):
        raise LifecycleError("OWNER_INPUTS_SCHEMA_REQUIRED")
    # Secret values must come from the process environment, not this persistent JSON file.
    for spec in value.get("github_secrets", {}).values():
        if set(spec) != {"from_env"}:
            raise LifecycleError("SECRET_ENVIRONMENT_REFERENCE_REQUIRED")
    return value


def _prepare(arguments: argparse.Namespace, store: ContextStore) -> dict[str, Any]:
    from provision.destroy_source import assert_mode

    assert_mode(REPOSITORY_ROOT, arguments.operation)
    inputs = _inputs(arguments.inputs)
    services = Services(REPOSITORY_ROOT, inputs.get("aws_profile", "enterprise-ai-platform-w6-004"))
    print("Checking protected main, AWS session, HCP setup and GitHub bindings…", flush=True)
    source = source_identity(services)
    summary = ensure_setup(
        services,
        inputs,
        repair=arguments.setup_missing,
        approve=_confirmation,
        login=arguments.login,
    )
    _report("prepare-setup", summary)
    if summary["classification"] != "PASS":
        print(json.dumps(summary, indent=2), flush=True)
        raise LifecycleError("SETUP_INCOMPLETE_SEE_REPORT")
    now = _utc_now()
    expiry = _parse_timestamp(arguments.approval_expires_at, "approval_expires_at")
    if expiry <= now or expiry > now + MAX_CONTEXT_LIFETIME:
        raise LifecycleError("APPROVAL_MUST_EXPIRE_WITHIN_24_HOURS")
    states = {name: services.current_state(wid) for name, wid in summary["workspaces"].items()}
    context = {
        "schema_version": SCHEMA_VERSION,
        "run_id": str(uuid.uuid4()),
        "operation": arguments.operation,
        "phase": "PREPARED",
        "classification": "PASS",
        "created_at": _timestamp(now),
        "expires_at": _timestamp(expiry),
        "source": source,
        "bindings": {
            "inputs_path": str(arguments.inputs.resolve()),
            "inputs_sha256": _file_sha256(arguments.inputs),
            "workspaces": summary["workspaces"],
            "initial_states": states,
        },
        "checkpoints": [{"phase": "PREPARED", "at": _timestamp(now), "classification": "PASS"}],
        "results": {},
        "retention": {
            "bootstrap": "RETAIN",
            "bootstrap_owned_iam": "RETAIN",
            "canonical_evidence": "RETAIN",
            "decrypting_kms_access": "RETAIN",
        },
    }
    path = store.create(context)
    return {
        "Result": "PASS_PREPARED",
        "RunID": context["run_id"],
        "ContextPath": str(path),
        "SetupSummary": summary,
        "HcpStates": states,
        "ExpiresAtUtc": context["expires_at"],
    }


def _resume(context: dict[str, Any]) -> tuple[Services, dict[str, Any]]:
    from provision.destroy_source import assert_mode

    assert_mode(REPOSITORY_ROOT, context["operation"])
    path = Path(context["bindings"]["inputs_path"])
    if _file_sha256(path) != context["bindings"]["inputs_sha256"]:
        raise LifecycleError("OWNER_INPUTS_CHANGED_PREPARE_NEW_CONTEXT")
    inputs = _inputs(path)
    services = Services(REPOSITORY_ROOT, inputs.get("aws_profile", "enterprise-ai-platform-w6-004"))
    if source_identity(services) != context["source"]:
        raise LifecycleError("SOURCE_CHANGED_PREPARE_NEW_CONTEXT")
    return services, inputs


@contextlib.contextmanager
def _workspace_lock(store: ContextStore, workspace: str) -> Any:
    if not workspace.startswith("ws-") or not workspace.replace("-", "").isalnum():
        raise LifecycleError("WORKSPACE_ID_INVALID")
    path = store.root / f"{workspace}.lock"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise LifecycleError("WORKSPACE_OPERATION_ALREADY_ACTIVE", "INDETERMINATE") from exc
    try:
        os.close(fd)
        yield
    finally:
        path.unlink(missing_ok=True)


def _provision(arguments: argparse.Namespace, store: ContextStore) -> dict[str, Any]:
    with store.lock(arguments.run_id):
        context = store.load(arguments.run_id)
        services, inputs = _resume(context)
        stage = arguments.stage
        if context["operation"] != "deploy":
            raise LifecycleError("DEPLOY_CONTEXT_REQUIRED")
        if stage in {"images", "bindings", "prerequisites"} and (
            arguments.plan_only or arguments.new_attempt
        ):
            raise LifecycleError("PLAN_OPTIONS_REQUIRE_HCP_STAGE")
        if arguments.publication_run_id and stage != "images":
            raise LifecycleError("PUBLICATION_RUN_OPTION_REQUIRES_IMAGES_STAGE")
        if stage in {"images", "bindings"}:
            prior = "base" if stage == "images" else "foundation"
            if not context["results"].get("hcp", {}).get(prior, {}).get("complete"):
                raise LifecycleError("PRIOR_STAGE_CHECKPOINT_REQUIRED_" + prior)
            with _workspace_lock(store, context["bindings"]["workspaces"]["sandbox"]):
                if stage == "images":
                    bindings.release_storage(
                        services, context, lambda text: _approve_current(context, text)
                    )
                    store.save(context)
                proof = (
                    bindings.images(
                        services,
                        context,
                        lambda: store.save(context),
                        lambda text: _approve_current(context, text),
                        arguments.publication_run_id,
                    )
                    if stage == "images"
                    else bindings.eks(
                        services,
                        context,
                        lambda: store.save(context),
                        lambda text: _approve_current(context, text),
                    )
                )
            _document(context, stage, proof)
            return {"Result": "IMMUTABLE_BINDING_STAGE", "Stage": stage, "Evidence": proof}
        if stage == "prerequisites":
            if not context["results"].get("hcp", {}).get("pki-access", {}).get("complete"):
                raise LifecycleError("TEMPORARY_PKI_ACCESS_CHECKPOINT_REQUIRED")
            with _workspace_lock(store, context["bindings"]["workspaces"]["sandbox"]):
                proof = kubernetes.prerequisites(
                    services,
                    context,
                    store.run_directory(arguments.run_id) / "prerequisites",
                    lambda text: _approve_current(context, text),
                    lambda: _validate_context(context, allow_expired=False),
                )
            context["bindings"]["prerequisites"] = proof
            bindings.github_binding(
                services,
                "W12_TRUST_BUNDLE_SHA256",
                proof["trust_bundle_sha256"],
                lambda text: _approve_current(context, text),
            )
            bindings.github_binding(
                services,
                "W12_ROOT_FINGERPRINT_SHA256",
                proof["root_fingerprint_sha256"],
                lambda text: _approve_current(context, text),
            )
            store.save(context)
            _document(context, "prerequisites", proof)
            return {"Result": "PASS_KUBERNETES_PREREQUISITES", "Evidence": proof}
        if stage not in inputs.get("stages", {}):
            raise LifecycleError("OWNER_STAGE_INPUTS_REQUIRED")
        if stage == "foundation" and not context["results"].get("images", {}).get("complete"):
            raise LifecycleError("PREREQUISITE_IMAGE_PUBLICATION_REQUIRED")
        if stage == "pki-access" and not context["bindings"].get("runtime_variables", {}).get(
            "w12_owner_approved_eks_issuer"
        ):
            raise LifecycleError("OWNER_APPROVED_EKS_BINDINGS_REQUIRED")
        # Explicit dependency checkpoints prevent retained activation flags skipping stages.
        prerequisite = {
            **iam_handoff.PRIOR,
            "foundation": "base",
            "pki-access": "foundation",
            "pki-disable": "pki-access",
            "activation": "pki-disable",
        }.get(stage)
        if prerequisite and not context["results"].get("hcp", {}).get(prerequisite, {}).get(
            "complete"
        ):
            raise LifecycleError("PRIOR_STAGE_CHECKPOINT_REQUIRED_" + prerequisite)
        if stage in {"pki-disable", "activation"}:
            _prerequisite_proof(context, inputs)
        with (
            _workspace_lock(store, context["bindings"]["workspaces"]["sandbox"]),
            contextlib.ExitStack() as locks,
        ):
            if stage in iam_handoff.BOOTSTRAP_STAGES:
                bootstrap = context["bindings"]["workspaces"]["bootstrap"]
                locks.enter_context(_workspace_lock(store, bootstrap))
                iam_handoff.authority(services, inputs, bootstrap)
                handoffs = context["bindings"].setdefault("iam_handoffs", {})
                if stage not in handoffs:
                    handoffs[stage] = iam_handoff.prepare(services, context, inputs, stage)
                    store.save(context)
                iam_handoff.assert_source(services, context, handoffs[stage])
            result = hcp.execute(
                services,
                context,
                inputs,
                stage,
                store.run_directory(arguments.run_id),
                lambda: store.save(context),
                lambda text: _approve_current(context, text),
                new_attempt=arguments.new_attempt,
                plan_only=arguments.plan_only,
            )
        context["phase"] = (
            "PROVISIONED" if stage == "activation" and result.get("complete") else "PROVISIONING"
        )
        store.save(context)
        _document(context, stage, result)
        return {
            "Result": "PASS_HCP_STAGE" if result.get("complete") else "HCP_PLAN_REVIEWED",
            "Stage": stage,
            "HcpRunID": result["run_id"],
            "Evidence": result["directory"],
            "FinalState": result.get("final_state"),
            "ApplyAttempted": result["apply_attempted"],
        }


def _approve_current(context: dict[str, Any], text: str) -> None:
    _validate_context(context, allow_expired=False)
    _confirmation(text)
    _validate_context(context, allow_expired=False)


def _prerequisite_proof(context: dict[str, Any], inputs: dict[str, Any]) -> None:
    evidence = context["bindings"].get("prerequisites", {})
    if evidence.get("classification") != "PASS" or evidence.get("source") != context["source"]:
        raise LifecycleError("PKI_PREREQUISITES_NOT_VERIFIED")


def _document(context: dict[str, Any], phase: str, result: dict[str, Any]) -> Path:
    directory = (
        REPOSITORY_ROOT
        / "docs"
        / (
            "rollback-records"
            if phase in {"rollback", "teardown", "bootstrap-teardown"}
            else "deployment-records"
        )
        / "lifecycle"
        / str(context["run_id"])
    )
    stamp = _utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    hcp.save_pair(directory, f"{phase}-{stamp}", _canonical_bytes(result))
    return directory


def _teardown(
    arguments: argparse.Namespace, store: ContextStore, *, bootstrap: bool = False
) -> dict[str, Any]:
    with store.lock(arguments.run_id):
        context = store.load(arguments.run_id)
        services, inputs = _resume(context)
        target = "bootstrap" if bootstrap else "sandbox"
        stage = "bootstrap-teardown" if bootstrap else "teardown"
        if bootstrap:
            if context["operation"] != "bootstrap-teardown":
                raise LifecycleError("SEPARATE_BOOTSTRAP_TEARDOWN_CONTEXT_REQUIRED")
            iam_handoff.authority(services, inputs, context["bindings"]["workspaces"]["bootstrap"])
            if services.resources(context["bindings"]["workspaces"]["sandbox"]):
                raise LifecycleError("BOOTSTRAP_DESTROY_REQUIRES_EMPTY_SANDBOX_STATE")
            proof = inputs.get("bootstrap_destroy_archive", {})
            archive = _resolve_external_file(
                Path(proof.get("path", "")), label="independent_archive"
            )
            if _file_sha256(archive) != proof.get("sha256"):
                raise LifecycleError("INDEPENDENT_EVIDENCE_ARCHIVE_MISMATCH")
            _approve_current(
                context, "AUTHORIZE BOOTSTRAP IAM AND STORAGE DESTRUCTION " + proof["sha256"]
            )
        elif context["results"].get("rollback", {}).get("classification") not in {"PASS", "NOOP"}:
            raise LifecycleError("CONTROLLED_ROLLBACK_CHECKPOINT_REQUIRED")
        workspace = context["bindings"]["workspaces"][target]

        def before_apply(step: dict[str, Any]) -> None:
            def current() -> None:
                _validate_context(context, allow_expired=False)
                if services.current_state(workspace) != step["input_state"]:
                    raise LifecycleError("STATE_CHANGED_DURING_PURGE")

            current()
            step["ecr_images_removed"] = cleanup.purge_ecr(
                cleanup.session(services).client("ecr"),
                step.get("cleanup_repositories", []),
                current,
            )
            if bootstrap:
                step["s3_versions_removed"] = cleanup.purge_bootstrap_buckets(
                    cleanup.session(services).client("s3"), step, current
                )
            store.save(context)

        with _workspace_lock(store, workspace):
            result = hcp.execute(
                services,
                context,
                inputs,
                stage,
                store.run_directory(arguments.run_id),
                lambda: store.save(context),
                lambda text: _approve_current(context, text),
                new_attempt=arguments.new_attempt,
                plan_only=arguments.plan_only,
                before_apply=before_apply,
            )
            if not result.get("complete"):
                return {"Result": "DESTROY_PLAN_REVIEWED", "RunID": result["run_id"]}
            result["reconciliation"] = cleanup.reconcile(services, result, workspace)
        context["phase"] = "TEARDOWN_COMPLETE"
        context["classification"] = "PASS"
        store.save(context)
        evidence = _document(context, stage, result)
        completed = store.complete(context)
        return {
            "Result": "HCP_TEARDOWN_COMPLETE_RECONCILIATION_OPEN",
            "Evidence": str(evidence),
            "CompletedContext": str(completed),
            "Reconciliation": result["reconciliation"],
        }


def _release(arguments: argparse.Namespace, store: ContextStore) -> dict[str, Any]:
    with store.lock(arguments.run_id):
        context = store.load(arguments.run_id)
        if context["operation"] != "deploy":
            raise LifecycleError("DEPLOY_CONTEXT_REQUIRED")
        services, inputs = _resume(context)
        if not context["results"].get("hcp", {}).get("activation", {}).get("complete"):
            raise LifecycleError("ACTIVATION_CHECKPOINT_REQUIRED")
        with _workspace_lock(store, context["bindings"]["workspaces"]["sandbox"]):
            step = hcp.execute(
                services,
                context,
                inputs,
                "release-plan",
                store.run_directory(arguments.run_id),
                lambda: store.save(context),
                lambda text: _approve_current(context, text),
            )
        directory = Path(step["directory"])
        raw = (directory / "release-record.json").read_bytes()
        record = release_engine.validate_record(
            raw, (directory / "release-record.sha256").read_bytes(), requested=True
        )
        receipt = (directory / "opa-receipt.json").read_bytes()
        release_engine.validate_opa_receipt(
            receipt,
            (directory / "opa-receipt.sha256").read_bytes(),
            record=record,
            record_sha256=step["record_sha256"],
        )
        return _workflow(
            arguments, store, context, services, inputs, directory, record, raw, receipt, "release"
        )


def _workflow(
    arguments: argparse.Namespace,
    store: ContextStore,
    context: dict[str, Any],
    services: Services,
    inputs: dict[str, Any],
    directory: Path,
    record: dict[str, Any],
    raw: bytes,
    receipt: bytes,
    operation: str,
) -> dict[str, Any]:
    """One protected workflow dispatch; observing a resume never creates another run."""
    record_sha256 = _sha256(raw)
    result = context["results"].setdefault(operation, {})
    if not result.get("workflow_run_id"):
        if result.get("dispatch_attempted"):
            found = release_engine._lookup_existing(
                record, record_sha256, _sha256(receipt), services.github_token
            )
            if not found:
                raise LifecycleError(
                    "DISPATCH_UNCERTAIN_READ_ONLY_RECONCILIATION_REQUIRED", "INDETERMINATE"
                )
            result["workflow_run_id"] = found[0]
        else:
            _approve_current(context, f"DISPATCH GOVERNED {operation.upper()} {record_sha256}")
            result["dispatch_attempted"] = True
            store.save(context)
            dispatched = release_engine._trigger(
                argparse.Namespace(
                    record=str(directory / "release-record.json"),
                    sha256_file=str(directory / "release-record.sha256"),
                    previous_record=None,
                    opa_receipt=str(directory / "opa-receipt.json"),
                    opa_receipt_sha256_file=str(directory / "opa-receipt.sha256"),
                    commit=context["source"]["commit"],
                )
            )
            result["workflow_run_id"] = dispatched["workflow_run_id"]
        context["phase"] = operation.upper() + "_DISPATCHED"
        store.save(context)
    run_id = result["workflow_run_id"]
    run = services.github(f"/actions/runs/{run_id}")
    release_engine._valid_run(run, context["source"]["commit"])
    result["status"] = run["status"]
    if run["status"] != "completed":
        store.save(context)
        return {
            "Result": operation.upper() + "_IN_PROGRESS",
            "WorkflowRunID": run_id,
            "Status": run["status"],
            "RunURL": run["html_url"],
            "Approval": "OWNER_USES_GITHUB_PROTECTED_ENVIRONMENT",
        }
    if run["conclusion"] != "success":
        result["classification"] = "FAIL"
        store.save(context)
        raise LifecycleError("GITHUB_RELEASE_" + str(run["conclusion"]).upper())
    proof_directory = store.run_directory(arguments.run_id) / operation / "publication"
    proof_inputs = dict(inputs)
    if context["bindings"].get("publication"):
        proof_inputs["publication_kms_key_arn"] = context["bindings"]["publication"]["kms_key_arn"]
    proof = _collect_publication(
        services, record, record_sha256, run_id, proof_directory, proof_inputs
    )
    result.update(classification="PASS", publication=proof)
    context.update(phase=operation.upper() + "_COMPLETE", classification="PASS")
    context["checkpoints"].append(
        {"phase": "VERIFIED", "at": _timestamp(_utc_now()), "classification": "PASS"}
    )
    evidence = _document(context, operation, result)
    # Only the already validated, sanitized record chain is copied; no state/plan payloads.
    shutil.copytree(proof_directory, evidence / f"{operation}-publication", dirs_exist_ok=True)
    store.save(context)
    # Keep context active for the separately invoked rollback/teardown stages.
    return {
        "Result": "PASS_VERIFIED_" + operation.upper(),
        "WorkflowRunID": run_id,
        "EvidenceDirectory": str(evidence),
    }


def _rollback(arguments: argparse.Namespace, store: ContextStore) -> dict[str, Any]:
    with store.lock(arguments.run_id):
        context = store.load(arguments.run_id)
        services, inputs = _resume(context)
        observation = kubernetes.application_inventory(services)
        if observation["workload_absent"]:
            proof = {
                "classification": "NOOP",
                "reason": "NO_DEPLOYED_APPLICATION_WORKLOAD_TO_ROLL_BACK",
                "observation": observation,
                "source": context["source"],
            }
            context["results"]["rollback"] = proof
            store.save(context)
            return {
                "Result": "PASS_CONTROLLED_ROLLBACK_NOOP",
                "Evidence": str(_document(context, "rollback", proof)),
            }
        # Rollback must use a real prior VERIFIED lineage, never kubectl rollout undo or a tag.
        spec = inputs.get("rollback_record", {})
        directory = _resolve_external_directory(
            Path(spec.get("directory", "")), label="rollback_record"
        )
        raw = (directory / "release-record.json").read_bytes()
        if _sha256(raw) != spec.get("sha256"):
            raise LifecycleError("ROLLBACK_RECORD_IDENTITY_MISMATCH")
        record = release_engine.validate_record(
            raw, (directory / "release-record.sha256").read_bytes(), requested=True
        )
        if (
            record["operation"] != "rollback"
            or record["source"]["commit"] != context["source"]["commit"]
        ):
            raise LifecycleError("OWNER_BOUND_ROLLBACK_RECORD_REQUIRED")
        receipt = (directory / "opa-receipt.json").read_bytes()
        release_engine.validate_opa_receipt(
            receipt,
            (directory / "opa-receipt.sha256").read_bytes(),
            record=record,
            record_sha256=_sha256(raw),
        )
        return _workflow(
            arguments, store, context, services, inputs, directory, record, raw, receipt, "rollback"
        )


def _collect_publication(
    services: Services,
    requested: dict[str, Any],
    requested_sha: str,
    run_id: int,
    directory: Path,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    artifacts = services.github_pages(f"/actions/runs/{run_id}/artifacts", "artifacts")
    name = f"w12-001-publication-proof-{requested['record_id']}-r5"
    found = [a for a in artifacts if a.get("name") == name and a.get("expired") is False]
    if len(found) != 1:
        raise LifecycleError("VERIFIED_PUBLICATION_ARTIFACT_MISSING_OR_AMBIGUOUS")
    expected = {"publication-selector.json"} | {
        f"records/r{rev}/{name}"
        for rev in range(1, 6)
        for name in ("release-record.json", "release-record.sha256")
    }
    files, metadata = release_engine._github_artifact_files(
        found[0]["id"], run_id, services.github_token, expected
    )
    if _sha256(files["records/r1/release-record.json"]) != requested_sha:
        raise LifecycleError("PUBLICATION_REQUESTED_RECORD_MISMATCH")
    previous = None
    for rev in range(1, 6):
        raw = files[f"records/r{rev}/release-record.json"]
        record = release_engine.validate_record(
            raw, files[f"records/r{rev}/release-record.sha256"], previous=previous
        )
        if (
            record["record_id"] != requested["record_id"]
            or record["source"]["commit"] != requested["source"]["commit"]
        ):
            raise LifecycleError("PUBLICATION_SOURCE_MISMATCH")
        previous = raw
    if record["status"] != "VERIFIED" or record["gates"]["github_run_id"] != run_id:
        raise LifecycleError("VERIFIED_RELEASE_REQUIRED")
    for name, raw in files.items():
        path = directory / name
        _secure_directory(path.parent)
        _atomic_write(path, raw)
    import boto3  # type: ignore[import-untyped]

    client = boto3.Session(profile_name=services.profile, region_name=APPROVED_REGION).client("s3")
    proof = release_engine.validate_publication_proof(
        directory, client=client, kms_key_arn=inputs["publication_kms_key_arn"], now=_utc_now()
    )
    return {
        "artifact_id": metadata["id"],
        "artifact_digest": metadata["digest"],
        "verified_sha256": _sha256(files["records/r5/release-record.json"]),
        "canonical_publication": proof,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Owner-controlled HCP infrastructure and governed GitHub release"
    )
    parser.add_argument("--context-root", type=Path, default=DEFAULT_CONTEXT_ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--inputs", type=Path, required=True)
    prepare.add_argument("--approval-expires-at", required=True)
    prepare.add_argument("--setup-missing", action="store_true")
    prepare.add_argument("--login", action="store_true")
    prepare.add_argument(
        "--operation",
        choices=("deploy", "rollback", "teardown", "bootstrap-teardown"),
        default="deploy",
    )
    provision = sub.add_parser("provision")
    provision.add_argument("--run-id", required=True)
    provision.add_argument(
        "--stage",
        required=True,
        choices=(
            "identity-seed",
            "bootstrap-bind-seed",
            "network-seed",
            "bootstrap-bind-complete",
            "base",
            "images",
            "foundation",
            "bindings",
            "pki-access",
            "prerequisites",
            "pki-disable",
            "activation",
        ),
    )
    provision.add_argument("--publication-run-id", type=int)
    provision.add_argument("--plan-only", action="store_true")
    provision.add_argument("--new-attempt", action="store_true")
    for name in ("release", "rollback", "teardown", "status"):
        item = sub.add_parser(name)
        item.add_argument("--run-id", required=True)
        if name == "teardown":
            item.add_argument("--new-attempt", action="store_true")
            item.add_argument("--plan-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code = 0
    try:
        store = ContextStore(args.context_root)
        if args.command == "prepare":
            result = _prepare(args, store)
        elif args.command == "provision":
            result = _provision(args, store)
        elif args.command == "release":
            result = _release(args, store)
        elif args.command == "teardown":
            result = _teardown(args, store)
        elif args.command == "rollback":
            result = _rollback(args, store)
        elif args.command == "status":
            directory = store.run_directory(args.run_id, completed=True)
            if directory.exists():
                raw = (directory / "context-summary.json").read_bytes()
                if (directory / "context-summary.sha256").read_text().strip() != _sha256(raw):
                    raise LifecycleError("COMPLETED_CONTEXT_INTEGRITY_MISMATCH")
                result = json.loads(raw)
            else:
                result = store.load(args.run_id, allow_expired=True)
    except (LifecycleError, ServiceError, release_engine.ReleaseError) as exc:
        result = {
            "Result": "LIFECYCLE_STOPPED",
            "ErrorCode": exc.code,
            "Classification": exc.classification,
        }
        code = 3 if exc.classification == "INDETERMINATE" else 2
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        result = {
            "Result": "LIFECYCLE_STOPPED",
            "ErrorCode": "LOCAL_OR_RESPONSE_SCHEMA_FAILURE",
            "Classification": "INDETERMINATE",
        }
        code = 3
    except Exception:
        # SDK/contract failures can embed credentials or response bodies in their text.
        # The durable mutation journal remains the authority for safe resumption.
        result = {
            "Result": "LIFECYCLE_STOPPED",
            "ErrorCode": "SERVICE_OR_CONTRACT_FAILURE",
            "Classification": "INDETERMINATE",
        }
        code = 3
    report = _report(args.command, result, getattr(args, "run_id", "setup"))
    print(json.dumps({**result, "Report": str(report)}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
