"""Plan intent, immutable identity, and drift invalidation controls."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from .aws_inventory import (
    DIAGNOSTIC_LIMITS,
    PREREQUISITE_CORRECTION_CHECK_IDS,
    PREREQUISITE_CORRECTION_DIRECTORY,
    PREREQUISITE_CORRECTION_OPERATION,
    PREREQUISITE_DIRECTORY,
    PREREQUISITE_LOG_ACTIONS,
    PREREQUISITE_LOG_NAMES,
    PREREQUISITE_OPERATION_ID,
    PREREQUISITE_POLICY,
    PREREQUISITE_ROLES,
    PREREQUISITE_ROUTES,
    RESOLUTION_BILLING_END,
    RESOLUTION_BILLING_START,
    RESOLUTION_DIRECTORY,
    RESOLUTION_EVENTS_END,
    RESOLUTION_EVENTS_START,
    RESOLUTION_EVIDENCE_SHA256,
    RESOLUTION_FOLLOWUP_DIRECTORY,
    RESOLUTION_FOLLOWUP_EVIDENCE_SHA256,
    RESOLUTION_FOLLOWUP_IDENTITY_SHA256,
    RESOLUTION_FOLLOWUP_OPERATION_ID,
    RESOLUTION_OPERATION_ID,
    NativeAssertion,
    NativeOwnershipBinding,
    NativeReadSpec,
    NativeScanBundle,
    NativeTarget,
    NativeTargetBundle,
)
from .aws_live import (
    Boto3AwsInventoryProvider,
    DiagnosticAwsSession,
    DiagnosticCollectionError,
    DiagnosticFatalError,
    DiagnosticReadError,
    diagnose_native_target,
    diagnostic_discovery_coverage,
    diagnostic_failure_reason,
    discover_diagnostic_scan,
    native_identity_key,
    observe_native_targets,
    resolution_policy_differences,
)
from .contracts import (
    APPROVED_ENVIRONMENT,
    OWNER_GOVERNANCE_EXPIRES_AT,
    Action,
    ApprovalConsumptionRegistry,
    ApprovalRecord,
    Clock,
    ContractError,
    ExecutionRevalidator,
    ExitCode,
    MutationRequest,
    OperationResult,
    VerifiedExecutionContext,
    authorize_mutation,
    canonical_resource_tags,
    generated_resource_expires_at,
    parse_utc_timestamp,
    validate_cycle_prerequisites,
    validate_mutation_request,
    validate_prerequisite_terms,
    validate_review_package,
    validate_runtime_token,
)
from .cost import INFRACOST_EXECUTABLE, INFRACOST_EXECUTABLE_SHA256, InfracostRunner
from .lifecycle_io import (
    BoundEvidenceReader,
    DiagnosticEvidenceReader,
    bounded_relative_path,
    canonical_json_bytes,
    decode_diagnostic_record,
    decode_json_strict,
    decode_operational_record,
    ensure_external_path,
    load_json_strict,
    read_private_state,
    reserve_operation_directory,
    sha256_bytes,
    sha256_file,
    validate_original_ancestors,
    verify_private_directory,
    write_canonical_json_atomic,
)
from .lifecycle_models import (
    DIAGNOSTIC_SCHEMA_VERSION,
    OPERATIONAL_SCHEMA_VERSION,
    ApprovalRecordV2,
    CostResultV2,
    DiagnosticCheck,
    DiagnosticReport,
    DiagnosticRequest,
    DiagnosticRuntimeConfiguration,
    DiagnosticStatus,
    DispatchObservation,
    EvidenceRef,
    ExistingReviewRequest,
    FinalizeCostRequest,
    IdentityBundle,
    InventoryEntry,
    InventoryResult,
    MutationEnvelope,
    OperationPhase,
    Outcome,
    PlanIdentity,
    PlanSummary,
    PostExecutionRequest,
    PreparedResourceExpiryInput,
    PrerequisiteTerms,
    PurgeReviewRequest,
    ResourceChangeRule,
    ReviewPackage,
    ReviewRequest,
    RuntimeConfiguration,
    StateEvidence,
)
from .operation_state import OperationLedger
from .policy_runner import OpaPolicyRunner, normalize_plan, summarize_plan
from .terraform_runner import (
    CommandRunner,
    GitObservationRunner,
    SubprocessCommandRunner,
    TerraformRunner,
    controlled_environment,
)

if TYPE_CHECKING:
    from .destroy import PurgeAdapter


# Public integrity identity of the reviewed dependent-action diagnostic, not a credential.
HISTORICAL_DEPENDENT_ACTION_DIAGNOSTIC_SHA256 = (
    "a7ff3ab351914e626ac67539a74536e3b48a422669b505e5edcdee07ded25590"  # pragma: allowlist secret
)


def validate_request(environment: str, target: str) -> OperationResult:
    """Validate a read-only planning request without running Terraform."""
    validate_runtime_token(environment, "environment")
    validate_runtime_token(target, "target")
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: plan intent validated; Terraform plan was NOT RUN",
    )


def validate_plan_identity(
    approved: PlanIdentity,
    current: PlanIdentity,
    now: datetime,
) -> None:
    """Invalidate the plan when any governed identity or expiry differs."""
    approved.validate()
    current.validate()
    for field in fields(PlanIdentity):
        if getattr(approved, field.name) != getattr(current, field.name):
            raise ContractError(f"saved plan invalidated by drift in {field.name}")
    if parse_utc_timestamp(approved.expires_at, "plan expires_at") <= now:
        raise ContractError("saved plan approval window has expired")


def prepare_resource_expiry_input(
    *,
    path: Path,
    external_root: Path,
    repository_root: Path,
    plan_preparation_time: datetime,
    environment: str,
) -> PreparedResourceExpiryInput:
    """Write the sole generated tfvars override for one new saved plan."""
    validate_runtime_token(environment, "environment")
    if environment != APPROVED_ENVIRONMENT:
        raise ContractError("resource expiry input environment is not approved")
    prepared_at = plan_preparation_time.replace(microsecond=0)
    resource_expires_at = generated_resource_expires_at(prepared_at)
    input_sha256 = write_canonical_json_atomic(
        path,
        {
            "mandatory_tags": canonical_resource_tags(
                environment,
                resource_expires_at,
            )
        },
        allowed_root=external_root,
        repository_root=repository_root,
    )
    prepared = PreparedResourceExpiryInput(
        path=path.resolve(strict=False),
        environment=environment,
        prepared_at=prepared_at.isoformat().replace("+00:00", "Z"),
        resource_expires_at=resource_expires_at,
        sha256=input_sha256,
    )
    prepared.validate()
    return prepared


def _validate_prepared_inputs(
    variables_file: Path,
    expected_input_sha256: str,
    resource_expiry_input: PreparedResourceExpiryInput,
) -> None:
    resource_expiry_input.validate()
    if sha256_file(variables_file) != expected_input_sha256:
        raise ContractError("external Terraform input identity changed")
    if sha256_file(resource_expiry_input.path) != resource_expiry_input.sha256:
        raise ContractError("generated resource-expiry input identity changed")
    value = load_json_strict(resource_expiry_input.path)
    if not isinstance(value, dict):
        raise ContractError("generated resource-expiry input is malformed")
    expected = {
        "mandatory_tags": canonical_resource_tags(
            resource_expiry_input.environment,
            resource_expiry_input.resource_expires_at,
        )
    }
    if cast(dict[str, object], value) != expected:
        raise ContractError("generated resource-expiry input content changed")


def generate_saved_plan(
    runner: TerraformRunner,
    *,
    terraform_root: Path,
    variables_file: Path,
    expected_input_sha256: str,
    resource_expiry_input: PreparedResourceExpiryInput,
    saved_plan: Path,
    normalized_plan_json: Path,
    external_root: Path,
    repository_root: Path,
    destroy: bool = False,
) -> tuple[PlanSummary, str]:
    """Create saved bytes, normalize show JSON, and return its deterministic identity."""
    if terraform_root.resolve() == repository_root.resolve() / "infra/environments/sandbox":
        raise ContractError("PLATFORM_PLAN_REQUIRES_VERIFIED_PREPARATION_COORDINATOR")
    _validate_prepared_inputs(
        variables_file,
        expected_input_sha256,
        resource_expiry_input,
    )
    runner.create_saved_plan(
        terraform_root,
        variables_file=variables_file,
        resource_expiry_file=resource_expiry_input.path,
        output_file=saved_plan,
        destroy=destroy,
    )
    raw = runner.show_plan_json(terraform_root, saved_plan)
    _validate_prepared_inputs(
        variables_file,
        expected_input_sha256,
        resource_expiry_input,
    )
    value = decode_json_strict(raw)
    normalized = normalize_plan(value, evaluation_time=resource_expiry_input.prepared_at)
    report_hash = write_canonical_json_atomic(
        normalized_plan_json,
        normalized,
        allowed_root=external_root,
        repository_root=repository_root,
    )
    if report_hash != sha256_bytes(normalized_plan_json.read_bytes()):
        raise ContractError("normalized plan identity changed after atomic write")
    return summarize_plan(normalized), report_hash


def execute_reviewed_plan(
    request: MutationRequest,
    approval_id: str,
    usage_registry: ApprovalConsumptionRegistry,
    now: datetime,
    *,
    runner: TerraformRunner,
    terraform_root: Path,
    saved_plan: Path,
    execution_context: VerifiedExecutionContext | None,
) -> OperationResult:
    """Shared direct-call execution path; no operation can bypass the complete gate."""
    from .lifecycle_models import OperationPhase
    from .operation_state import OperationLedger
    from .terraform_runner import ProcessOutcomeUncertain

    if not isinstance(execution_context, VerifiedExecutionContext):
        raise ContractError("VERIFIED_EXECUTION_CONTEXT_REQUIRED")
    if not isinstance(usage_registry, OperationLedger):
        raise ContractError("DURABLE_OPERATION_LEDGER_REQUIRED")
    package = execution_context.package
    if (
        approval_id != execution_context.approval.approval_id
        or request.target != package.target
        or request.environment != package.environment
        or request.aws_account_id != package.account_id
        or request.aws_region != package.region
        or request.executor != execution_context.approval.executor
        or request.confirmation != execution_context.approval.confirmation
    ):
        raise ContractError("DIRECT_REQUEST_REVIEW_MISMATCH")
    execution_context.revalidate(request.action, request.artifact_sha256, consumed=False)
    if sha256_file(saved_plan) != package.artifact.sha256:
        raise ContractError("DISPATCH_PLAN_DRIFT")
    usage_registry.begin_execution(execution_context, now)
    state = OperationPhase.EXECUTION_COMPLETED
    reason = "EXECUTION_COMPLETED_VERIFICATION_PENDING"
    try:
        runner.apply_saved_plan(
            terraform_root,
            saved_plan,
            request.artifact_sha256,
            execution_context=execution_context,
        )
    except ProcessOutcomeUncertain:
        state = OperationPhase.EXECUTION_OUTCOME_UNCERTAIN
        reason = "EXECUTION_OUTCOME_UNCERTAIN"
    except ContractError:
        state = OperationPhase.EXECUTION_FAILED
        reason = "EXECUTION_FAILED_RECONCILIATION_REQUIRED"
    except Exception:
        state = OperationPhase.EXECUTION_OUTCOME_UNCERTAIN
        reason = "EXECUTION_OUTCOME_UNCERTAIN"
    try:
        usage_registry.finish_execution(execution_context, state, reason)
    except ContractError:
        return OperationResult(
            ExitCode.VALIDATION_FAILURE,
            "INDETERMINATE: post-dispatch durability failure",
            "POST_DISPATCH_DURABILITY_UNCERTAIN",
        )
    if state is not OperationPhase.EXECUTION_COMPLETED:
        return OperationResult(ExitCode.VALIDATION_FAILURE, "FAIL: reconciliation required", reason)
    return OperationResult(
        ExitCode.SUCCESS, "EXECUTION COMPLETED: independent verification remains NOT RUN", reason
    )


class ReviewServices(Protocol):
    """Production ports and deterministic fakes share this single review coordinator."""

    clock: Clock
    repository_root: Path
    external_root: Path
    terraform: TerraformRunner
    policy: OpaPolicyRunner
    ledger: OperationLedger

    def identities(self, request: ReviewRequest) -> IdentityBundle:
        """Observe scoped working/index/governance identities and exact tools."""
        ...

    def copy_evidence(self, request: ReviewRequest) -> None:
        """Copy only hash-bound approved safe evidence into the reserved operation."""
        ...

    def state(self, request: ReviewRequest) -> StateEvidence:
        """Observe the exact configured backend without exposing state content."""
        ...

    def inventory(self, request: ReviewRequest, state: StateEvidence) -> InventoryResult:
        """Reconcile current native resources against state and the request scope."""
        ...

    def cost(self, request: ReviewRequest, saved_plan: Path, plan_sha256: str) -> CostResultV2:
        """Use only the saved-binary cost adapter and approved exposure assumptions."""
        ...

    def expiry_input(
        self,
        request: ReviewRequest,
        prepared: datetime,
        operation_root: Path,
    ) -> PreparedResourceExpiryInput:
        """Generate apply expiry; preserve applied values for destructive/rollback reviews."""
        ...


def _validate_preparation_request(request: ReviewRequest) -> None:
    """Reject mismatched direct requests before any operation-owned side effect."""
    from .lifecycle_models import ChangeProfile

    if request.schema_version != OPERATIONAL_SCHEMA_VERSION:
        raise ContractError("V2_REVIEW_REQUEST_REQUIRED")
    validate_runtime_token(request.operation_id, "operation_id")
    if (
        request.environment != APPROVED_ENVIRONMENT
        or request.target
        not in {
            "bootstrap",
            "platform",
        }
        or request.profile.action is not request.action
    ):
        raise ContractError("PREPARATION_SCOPE_MISMATCH")
    expected_target = (
        "bootstrap"
        if request.action
        in {
            Action.BOOTSTRAP_APPLY,
            Action.BOOTSTRAP_DESTROY,
        }
        else "platform"
    )
    if request.action is not Action.PURGE_SANDBOX and request.target != expected_target:
        raise ContractError("PREPARATION_TARGET_MISMATCH")
    profiles = {
        Action.BOOTSTRAP_APPLY: {ChangeProfile.INITIAL, ChangeProfile.PARTIAL_RECOVERY},
        Action.PLATFORM_APPLY: {ChangeProfile.INITIAL, ChangeProfile.PARTIAL_RECOVERY},
        Action.INFRASTRUCTURE_ROLLBACK: {ChangeProfile.ROLLBACK},
        Action.PLATFORM_DESTROY: {ChangeProfile.DESTROY},
        Action.BOOTSTRAP_DESTROY: {ChangeProfile.DESTROY},
        Action.PURGE_SANDBOX: {ChangeProfile.PURGE},
    }
    if request.profile.profile not in profiles[request.action] or not request.profile.rules:
        raise ContractError("PREPARATION_PROFILE_MISMATCH")
    if request.action is Action.INFRASTRUCTURE_ROLLBACK and request.profile.last_known_good is None:
        raise ContractError("LAST_KNOWN_GOOD_UNAVAILABLE")


def prepare_review(request: ReviewRequest, services: ReviewServices) -> ReviewPackage:
    """Prepare one immutable operation review; no mutation dispatch exists in this path."""
    _validate_preparation_request(request)
    if request.action not in {
        Action.BOOTSTRAP_APPLY,
        Action.PLATFORM_APPLY,
        Action.PLATFORM_DESTROY,
        Action.BOOTSTRAP_DESTROY,
        Action.INFRASTRUCTURE_ROLLBACK,
    }:
        raise ContractError("SAVED_PLAN_REVIEW_ACTION_INVALID")
    prepared = services.clock.now().replace(microsecond=0)
    prepared_text = prepared.isoformat().replace("+00:00", "Z")
    root = ensure_external_path(
        Path(request.operation_root), services.external_root, services.repository_root
    )
    if root.exists():
        raise ContractError("OPERATION_DIRECTORY_ALREADY_EXISTS")
    # An exclusive directory reservation is owned by the I/O adapter.
    from .lifecycle_io import reserve_operation_directory

    reserve_operation_directory(root, services.external_root, services.repository_root)
    services.ledger.transition(
        request.operation_id,
        OperationPhase.PREPARED,
        artifact_sha256=None,
        recorded_at=prepared_text,
    )
    artifact_hash: str | None = None
    try:
        if services.identities(request) != request.approved_identities:
            raise ContractError("PREPARATION_IDENTITY_DRIFT")
        state = services.state(request)
        if request.target == "platform":
            services.copy_evidence(request)
            validate_cycle_prerequisites(
                request.profile,
                state,
                BoundEvidenceReader(root, services.repository_root),
                services.clock.now(),
                prepared_at=prepared_text,
                action=request.action,
                identities=request.approved_identities,
            )
        native = services.inventory(request, state)
        if native.incomplete_services:
            raise ContractError("PREPARATION_NATIVE_INCOMPLETE")
        terraform_root = services.repository_root / (
            "infra/bootstrap" if request.target == "bootstrap" else "infra/environments/sandbox"
        )
        variables = ensure_external_path(
            Path(request.variables_path), services.external_root, services.repository_root
        )
        backend = ensure_external_path(
            Path(request.backend_path), services.external_root, services.repository_root
        )
        if (
            sha256_file(variables) != request.variables_sha256
            or sha256_file(backend) != request.backend_sha256
        ):
            raise ContractError("PREPARATION_INPUT_DRIFT")
        expiry = services.expiry_input(request, prepared, root)
        saved_plan = root / "plan.tfplan"
        services.terraform.verify_version(terraform_root)
        services.terraform.create_saved_plan(
            terraform_root,
            variables_file=variables,
            resource_expiry_file=expiry.path,
            output_file=saved_plan,
            destroy=request.profile.profile.value == "DESTROY",
        )
        artifact_hash = sha256_file(saved_plan)
        private = services.terraform.show_plan_json(terraform_root, saved_plan)
        normalized = normalize_plan(decode_json_strict(private), evaluation_time=prepared_text)
        summary = summarize_plan(normalized)
        expected = {
            (rule.address, rule.resource_type, tuple(rule.actions))
            for rule in request.profile.rules
        }
        changes = cast(list[dict[str, object]], normalized["resource_changes"])
        actual = {
            (
                str(change["address"]),
                str(change["type"]),
                tuple(cast(list[str], cast(dict[str, object], change["change"])["actions"])),
            )
            for change in changes
        }
        if actual != expected or len(summary.records) != len(request.profile.rules):
            raise ContractError("PREPARATION_ACTION_PROFILE_DIFFERS")
        native_expiry = parse_utc_timestamp(native.valid_until, "native expiry")
        resource_limit = (
            parse_utc_timestamp(expiry.resource_expires_at, "resource expiry")
            if request.action
            in {
                Action.BOOTSTRAP_APPLY,
                Action.PLATFORM_APPLY,
                Action.INFRASTRUCTURE_ROLLBACK,
            }
            else parse_utc_timestamp(OWNER_GOVERNANCE_EXPIRES_AT, "governance expiry")
        )
        expires = min(
            prepared + timedelta(minutes=60),
            native_expiry,
            resource_limit,
            parse_utc_timestamp(OWNER_GOVERNANCE_EXPIRES_AT, "governance expiry"),
            parse_utc_timestamp(request.profile.expires_at, "profile expiry"),
        )
        mandatory = (*request.profile.evidence, state.inventory)
        mandatory += tuple(
            reference
            for reference in (
                request.profile.last_known_good,
                request.profile.platform_cleanliness,
                request.profile.cleanup_spending,
            )
            if reference is not None
        )
        for reference in mandatory:
            expires = min(expires, parse_utc_timestamp(reference.valid_until, "evidence expiry"))
        if expires <= services.clock.now():
            raise ContractError("MANDATORY_EVIDENCE_ALREADY_EXPIRED")
        expires_text = expires.isoformat().replace("+00:00", "Z")
        context = cast(dict[str, object], normalized["evaluation_context"])
        context["operation"] = {
            "schema_version": OPERATIONAL_SCHEMA_VERSION,
            "operation_id": request.operation_id,
            "action": request.action.value,
            "profile": request.profile.profile.value,
            "rules": [
                dict(
                    zip(
                        ("address", "resource_type", "actions", "update_paths", "delta_rule"),
                        (
                            rule.address,
                            rule.resource_type,
                            list(rule.actions),
                            list(rule.update_paths),
                            rule.delta_rule,
                        ),
                        strict=True,
                    )
                )
                for rule in request.profile.rules
            ],
            "state_lineage": state.lineage,
            "state_serial": state.serial,
            "inventory_sha256": sha256_bytes(canonical_json_bytes(native)),
            "source_sha256": request.approved_identities.working_sha256,
            "resource_expires_at": expiry.resource_expires_at,
            "expires_at": expires_text,
        }
        normalized_path = root / "normalized-plan.json"
        write_canonical_json_atomic(
            normalized_path,
            normalized,
            allowed_root=services.external_root,
            repository_root=services.repository_root,
        )
        decision = services.policy.evaluate_decision(normalized_path)
        if decision["allow"] is not True or decision["findings"] != []:
            raise ContractError("PREPARATION_POLICY_REJECTED")
        policy_path = root / "policy-result.json"
        policy_hash = write_canonical_json_atomic(
            policy_path,
            decision,
            allowed_root=services.external_root,
            repository_root=services.repository_root,
        )
        cost = services.cost(request, saved_plan, artifact_hash)
        expires = min(expires, parse_utc_timestamp(cost.valid_until, "cost expiry"))
        expires_text = expires.isoformat().replace("+00:00", "Z")
        if (
            services.identities(request) != request.approved_identities
            or sha256_file(saved_plan) != artifact_hash
        ):
            raise ContractError("POST_REVIEW_IDENTITY_DRIFT")
        inputs = dict(request.approved_identities.inputs)
        inputs.update(
            {
                "review/normalized-plan.json": sha256_file(normalized_path),
                "review/resource-expiry.tfvars.json": expiry.sha256,
            }
        )
        identities = replace(request.approved_identities, inputs=tuple(sorted(inputs.items())))
        package = ReviewPackage(
            OPERATIONAL_SCHEMA_VERSION,
            request.operation_id,
            request.action,
            request.target,
            request.environment,
            native.account_id,
            native.region,
            "arn:aws:iam::526338061652:user/finopsinfra",
            request.profile,
            identities,
            EvidenceRef(
                "saved-plan",
                "plan.tfplan",
                artifact_hash,
                saved_plan.stat().st_size,
                "terraform-1.16.1",
                prepared_text,
                expires_text,
                request.operation_id,
            ),
            state,
            native,
            EvidenceRef(
                "policy-result",
                "policy-result.json",
                policy_hash,
                policy_path.stat().st_size,
                "opa-1.20.0",
                prepared_text,
                expires_text,
                request.operation_id,
            ),
            cost,
            request.profile.rules,
            prepared_text,
            expiry.resource_expires_at,
            expires_text,
            Outcome.PASS,
        )
        if cost.status is Outcome.FAIL:
            raise ContractError("COST_REVIEW_FAILED")
        if (
            cost.status is Outcome.INDETERMINATE
            and not any(
                reference.kind == "conservative-cost-bound"
                for reference in request.profile.evidence
            )
            and request.profile.cleanup_spending is None
        ):
            pending = replace(package, eligibility=Outcome.INDETERMINATE)
            write_canonical_json_atomic(
                root / "candidate-review.json",
                pending,
                allowed_root=services.external_root,
                repository_root=services.repository_root,
            )
            return pending
        validate_review_package(
            package,
            now=services.clock.now(),
            reader=BoundEvidenceReader(root, services.repository_root),
        )
        write_canonical_json_atomic(
            root / "review.json",
            package,
            allowed_root=services.external_root,
            repository_root=services.repository_root,
        )
        services.ledger.transition(
            request.operation_id,
            OperationPhase.ELIGIBLE_FOR_REVIEW,
            artifact_sha256=artifact_hash,
            recorded_at=services.clock.now().isoformat().replace("+00:00", "Z"),
        )
        return package
    except Exception:
        services.ledger.transition(
            request.operation_id,
            OperationPhase.REVIEW_FAILED,
            artifact_sha256=artifact_hash,
            recorded_at=services.clock.now().isoformat().replace("+00:00", "Z"),
            reason_code="PREPARATION_FAILED",
        )
        raise


class RepositoryLifecycleCoordinator:
    """The sole CLI/direct composition layer; services are explicit adapter instances."""

    def __init__(
        self,
        review_services: ReviewServices,
        revalidator: ExecutionRevalidator,
        *,
        purge_adapter: PurgeAdapter | None = None,
    ) -> None:
        self.services = review_services
        self.revalidator = revalidator
        self.external_root = review_services.external_root
        self.repository_root = review_services.repository_root
        self.purge_adapter = purge_adapter

    def execute_request(self, command: str, payload: bytes) -> tuple[int, str]:
        """Decode an exact v2 request and dispatch no subsequent lifecycle phase."""
        if command == "cost-review":
            cost_request = decode_operational_record(payload, FinalizeCostRequest)
            return self.finalize_cost_review(cost_request)
        if command == "policy-review":
            value = decode_json_strict(payload)
            if isinstance(value, dict) and "inventory" in value:
                purge_request = decode_operational_record(payload, PurgeReviewRequest)
                return self.prepare_purge(purge_request)
            existing = decode_operational_record(payload, ExistingReviewRequest)
            root = ensure_external_path(
                Path(existing.operation_root), self.external_root, self.repository_root
            )
            reader = BoundEvidenceReader(root, self.repository_root)
            package = decode_operational_record(
                reader.read(
                    existing.review_path,
                    existing.review_sha256,
                    (root / bounded_relative_path(existing.review_path)).stat().st_size,
                ),
                ReviewPackage,
            )
            if package.action is Action.PURGE_SANDBOX:
                from .destroy import validate_purge_review

                validate_purge_review(package, reader, self.services.clock.now())
            else:
                decision = self.services.policy.evaluate_decision(root / "normalized-plan.json")
                if decision != decode_json_strict(
                    reader.read(
                        package.policy.path, package.policy.sha256, package.policy.byte_count
                    )
                ):
                    raise ContractError("POLICY_REVIEW_EVIDENCE_CHANGED")
            return 0, "POLICY_REVIEW_ONLY_NO_MUTATION_AUTHORITY"
        if command in {"aws-verify", "verify-clean"}:
            request_value = decode_json_strict(payload)
            if isinstance(request_value, dict) and "review_path" in request_value:
                from .verify_clean import verify_post_execution

                verification = decode_operational_record(payload, PostExecutionRequest)
                root = ensure_external_path(
                    Path(verification.operation_root), self.external_root, self.repository_root
                )
                reader = BoundEvidenceReader(root, self.repository_root)
                package = decode_operational_record(
                    reader.read(
                        verification.review_path,
                        verification.review_sha256,
                        (root / verification.review_path).stat().st_size,
                    ),
                    ReviewPackage,
                )
                if command == "verify-clean" and package.action not in {
                    Action.PLATFORM_DESTROY,
                    Action.BOOTSTRAP_DESTROY,
                    Action.PURGE_SANDBOX,
                }:
                    raise ContractError("CLEANLINESS_REQUIRES_DESTRUCTIVE_OPERATION")
                observed = self.revalidator.observe(package)
                if (observed.identities, observed.account_id, observed.region, observed.caller) != (
                    package.identities,
                    package.account_id,
                    package.region,
                    package.caller,
                ):
                    raise ContractError("POST_EXECUTION_IDENTITY_DRIFT")
                if verification.state is not None and (
                    observed.state.lineage,
                    observed.state.serial,
                    observed.state.sha256,
                ) != (
                    verification.state.lineage,
                    verification.state.serial,
                    verification.state.sha256,
                ):
                    raise ContractError("POST_EXECUTION_OBSERVATION_DRIFT")
                if verification.native is not None and {
                    (entry.address, entry.presence, entry.native_identity, entry.configuration)
                    for entry in observed.native.entries
                } != {
                    (entry.address, entry.presence, entry.native_identity, entry.configuration)
                    for entry in verification.native.entries
                }:
                    raise ContractError("POST_EXECUTION_NATIVE_DRIFT")
                if package.action is Action.PURGE_SANDBOX:
                    from .destroy import verify_purge_execution

                    if self.purge_adapter is None:
                        raise ContractError("PURGE_NATIVE_ADAPTER_REQUIRED")
                    purge_verification = verify_purge_execution(
                        package,
                        observed.state,
                        observed.native,
                        reader=reader,
                        adapter=self.purge_adapter,
                        ledger=self.services.ledger,
                        now=self.services.clock.now(),
                    )
                    return purge_verification.exit_code, purge_verification.reason_code
                verified_result = verify_post_execution(
                    package,
                    observed.state,
                    observed.native,
                    now=self.services.clock.now(),
                    reader=reader,
                    ledger=self.services.ledger,
                    retention_evidence=verification.evidence,
                )
                return verified_result.exit_code, verified_result.reason_code
            if command == "verify-clean":
                raise ContractError("POST_EXECUTION_VERIFICATION_REQUEST_REQUIRED")
            preflight = decode_operational_record(payload, ReviewRequest)
            _validate_preparation_request(preflight)
            if self.services.identities(preflight) != preflight.approved_identities:
                raise ContractError("PREFLIGHT_IDENTITY_DRIFT")
            from .lifecycle_io import reserve_operation_directory

            reserve_operation_directory(
                Path(preflight.operation_root), self.external_root, self.repository_root
            )
            state = self.services.state(preflight)
            native = self.services.inventory(preflight, state)
            if native.incomplete_services or not native.covered_services:
                raise ContractError("PREFLIGHT_NATIVE_INCOMPLETE")
            if self.services.identities(preflight) != preflight.approved_identities:
                raise ContractError("PREFLIGHT_FINAL_IDENTITY_DRIFT")
            preflight_root = Path(preflight.operation_root)
            write_canonical_json_atomic(
                preflight_root / "preflight-state.json",
                state,
                allowed_root=self.external_root,
                repository_root=self.repository_root,
            )
            write_canonical_json_atomic(
                preflight_root / "preflight-native.json",
                native,
                allowed_root=self.external_root,
                repository_root=self.repository_root,
            )
            return 0, "READ_ONLY_PREFLIGHT_COMPLETED_NO_PLAN"
        plan_commands = {"bootstrap-plan", "platform-plan", "destroy-plan"}
        if command in plan_commands:
            request = decode_operational_record(payload, ReviewRequest)
            if command == "bootstrap-plan" and request.action is not Action.BOOTSTRAP_APPLY:
                raise ContractError("COMMAND_ACTION_MISMATCH")
            if command == "platform-plan" and request.action is not Action.PLATFORM_APPLY:
                raise ContractError("COMMAND_ACTION_MISMATCH")
            if command == "destroy-plan" and request.action not in {
                Action.PLATFORM_DESTROY,
                Action.BOOTSTRAP_DESTROY,
            }:
                raise ContractError("COMMAND_ACTION_MISMATCH")
            package = prepare_review(request, self.services)
            if package.eligibility is not Outcome.PASS:
                return 3, "COST_INDETERMINATE_OWNER_BOUND_REQUIRED"
            return 0, "REVIEW_READY_OWNER_APPROVAL_REQUIRED"
        actions = {
            "bootstrap-apply": Action.BOOTSTRAP_APPLY,
            "platform-apply": Action.PLATFORM_APPLY,
            "infrastructure-rollback": Action.INFRASTRUCTURE_ROLLBACK,
            "platform-destroy": Action.PLATFORM_DESTROY,
            "bootstrap-destroy": Action.BOOTSTRAP_DESTROY,
            "purge-sandbox": Action.PURGE_SANDBOX,
        }
        if command not in actions:
            raise ContractError("SEPARATE_OPERATION_ADAPTER_REQUIRED")
        envelope = decode_operational_record(payload, MutationEnvelope)
        root = ensure_external_path(
            Path(envelope.operation_root), self.external_root, self.repository_root
        )
        reader = BoundEvidenceReader(root, self.repository_root)
        bounded_relative_path(envelope.review_path)
        bounded_relative_path(envelope.approval_path)
        package = decode_operational_record(
            reader.read(
                envelope.review_path,
                envelope.review_sha256,
                (root / envelope.review_path).stat().st_size,
            ),
            ReviewPackage,
        )
        approval = decode_operational_record(
            reader.read(
                envelope.approval_path,
                envelope.approval_sha256,
                (root / envelope.approval_path).stat().st_size,
            ),
            ApprovalRecordV2,
        )
        if package.action is not actions[command]:
            raise ContractError("COMMAND_ACTION_MISMATCH")
        context = authorize_mutation(
            package,
            approval,
            reader=reader,
            revalidator=self.revalidator,
            clock=self.services.clock,
        )
        if package.action is Action.PURGE_SANDBOX:
            from .destroy import purge_approved_inventory

            if self.purge_adapter is None:
                raise ContractError("PURGE_NATIVE_ADAPTER_REQUIRED")
            purge_result = purge_approved_inventory(
                context, self.services.ledger, self.purge_adapter, self.services.clock.now()
            )
            return int(purge_result.exit_code), purge_result.reason_code
        mutation_request = MutationRequest(
            package.action,
            package.environment,
            package.account_id,
            package.region,
            package.target,
            package.artifact.sha256,
            approval.confirmation,
            approval.executor,
        )
        # Legacy intent validation is additional only; v1 can never create this context.
        legacy = ApprovalRecord(
            "1.0",
            approval.approval_id,
            package.action,
            package.environment,
            package.account_id,
            package.region,
            package.target,
            package.artifact.sha256,
            approval.approver,
            approval.approved_at,
            approval.expires_at,
        )
        validate_mutation_request(
            mutation_request, legacy, self.services.ledger, self.services.clock.now()
        )
        result = execute_reviewed_plan(
            mutation_request,
            approval.approval_id,
            self.services.ledger,
            self.services.clock.now(),
            runner=self.services.terraform,
            terraform_root=self.repository_root
            / (
                "infra/bootstrap" if package.target == "bootstrap" else "infra/environments/sandbox"
            ),
            saved_plan=root / package.artifact.path,
            execution_context=context,
        )
        return int(result.exit_code), result.reason_code

    def finalize_cost_review(self, request: FinalizeCostRequest) -> tuple[int, str]:
        """Review actual pricing evidence or a bound without renewing the plan lifetime."""
        from .cost import reconcile_cost_coverage
        from .lifecycle_io import copy_reviewed_evidence

        root = ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )
        reader = BoundEvidenceReader(root, self.repository_root)
        package = decode_operational_record(
            reader.read(
                request.review_path,
                request.review_sha256,
                (root / bounded_relative_path(request.review_path)).stat().st_size,
            ),
            ReviewPackage,
        )
        history = self.services.ledger.journal(package.operation_id)
        if not history or history[-1]["state"] != OperationPhase.PREPARED.value:
            raise ContractError("COST_FINALIZATION_PHASE_INVALID")
        if (
            package.eligibility is not Outcome.INDETERMINATE
            or package.cost.status is not Outcome.INDETERMINATE
        ):
            raise ContractError("COST_FINALIZATION_NOT_AN_UNCERTAIN_CANDIDATE")
        for reference, source in request.evidence_sources:
            if reference.operation_id != package.operation_id:
                raise ContractError("COST_FINALIZATION_EVIDENCE_OPERATION")
            copy_reviewed_evidence(
                reference,
                Path(source),
                operation_root=root,
                external_root=self.external_root,
                repository_root=self.repository_root,
            )
        bound, cost = request.conservative_bound, request.reconciled_cost
        if (bound is None) == (cost is None):
            raise ContractError("EXACTLY_ONE_COST_FINALIZATION_METHOD_REQUIRED")
        if bound is not None:
            if bound.kind != "conservative-cost-bound":
                raise ContractError("CONSERVATIVE_COST_BOUND_REQUIRED")
            profile = replace(package.profile, evidence=(*package.profile.evidence, bound))
            final = replace(package, profile=profile, eligibility=Outcome.PASS)
        else:
            if cost is None or package.action in {
                Action.PURGE_SANDBOX,
                Action.PLATFORM_DESTROY,
                Action.BOOTSTRAP_DESTROY,
            }:
                raise ContractError("CLEANUP_REQUIRES_EXPLICIT_SPENDING_DECISION")
            if (
                cost.status is not Outcome.PASS
                or cost.raw_estimate != package.cost.raw_estimate
                or cost.saved_plan_sha256 != package.artifact.sha256
                or cost.observed_at != package.cost.observed_at
                or parse_utc_timestamp(cost.valid_until, "cost expiry")
                > parse_utc_timestamp(package.cost.valid_until, "original cost expiry")
            ):
                raise ContractError("COST_FINALIZATION_RAW_IDENTITY_OR_LIFETIME_CHANGED")
            saved = root / bounded_relative_path(package.artifact.path)
            reader.read(package.artifact.path, package.artifact.sha256, package.artifact.byte_count)
            private = self.services.terraform.show_plan_json(
                self.repository_root
                / (
                    "infra/bootstrap"
                    if package.target == "bootstrap"
                    else "infra/environments/sandbox"
                ),
                saved,
            )
            reader.read(package.artifact.path, package.artifact.sha256, package.artifact.byte_count)
            raw_cost = decode_json_strict(
                reader.read(
                    cost.raw_estimate.path, cost.raw_estimate.sha256, cost.raw_estimate.byte_count
                )
            )
            reconcile_cost_coverage(private, raw_cost, cost, scope=package.target)
            final = replace(package, cost=cost, eligibility=Outcome.PASS)
        observed = self.revalidator.observe(final)
        if (
            observed.identities != final.identities
            or (observed.account_id, observed.region, observed.caller)
            != (final.account_id, final.region, final.caller)
            or (
                observed.state.backend,
                observed.state.lineage,
                observed.state.serial,
                observed.state.sha256,
                observed.state.remote_version,
            )
            != (
                final.state.backend,
                final.state.lineage,
                final.state.serial,
                final.state.sha256,
                final.state.remote_version,
            )
            or tuple(replace(entry, observed_at="") for entry in observed.native.entries)
            != tuple(replace(entry, observed_at="") for entry in final.native.entries)
            or observed.native.incomplete_services
            or observed.native.covered_services != final.native.covered_services
        ):
            raise ContractError("COST_FINALIZATION_IDENTITY_DRIFT")
        validate_review_package(final, now=self.services.clock.now(), reader=reader)
        write_canonical_json_atomic(
            root / "review.json",
            final,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        self.services.ledger.transition(
            final.operation_id,
            OperationPhase.ELIGIBLE_FOR_REVIEW,
            artifact_sha256=final.artifact.sha256,
            recorded_at=self.services.clock.now()
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        )
        return 0, (
            "COST_BOUND_ACCEPTED_RAW_COVERAGE_REMAINS_INDETERMINATE"
            if bound is not None
            else "RESOURCE_COST_RECONCILIATION_ACCEPTED"
        )

    def prepare_purge(self, envelope: PurgeReviewRequest) -> tuple[int, str]:
        """Journal a single-use purge preparation, including every rejection."""
        from .lifecycle_io import reserve_operation_directory

        request = envelope.request
        _validate_preparation_request(request)
        if (
            self.purge_adapter is None
            or request.action is not Action.PURGE_SANDBOX
            or envelope.cost.status is not Outcome.INDETERMINATE
        ):
            raise ContractError("PURGE_REVIEW_ADAPTER_ACTION_OR_SPENDING")
        root = ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )
        reserve_operation_directory(root, self.external_root, self.repository_root)
        self.services.ledger.transition(
            request.operation_id,
            OperationPhase.PREPARED,
            artifact_sha256=None,
            recorded_at=self.services.clock.now()
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        )
        try:
            return self._prepare_purge_review(envelope)
        except Exception:
            self.services.ledger.transition(
                request.operation_id,
                OperationPhase.REVIEW_FAILED,
                artifact_sha256=None,
                recorded_at=self.services.clock.now()
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                reason_code="PURGE_PREPARATION_FAILED",
            )
            raise

    def _prepare_purge_review(self, envelope: PurgeReviewRequest) -> tuple[int, str]:
        """Produce a purge review only from an independently reconciled exact inventory."""
        from .destroy import validate_purge_review

        request, inventory = envelope.request, envelope.inventory
        if self.purge_adapter is None or request.action is not Action.PURGE_SANDBOX:
            raise ContractError("PURGE_REVIEW_ADAPTER_OR_ACTION")
        if (
            envelope.operation_root != request.operation_root
            or request.operation_id != inventory.operation_id
        ):
            raise ContractError("PURGE_REVIEW_OPERATION_MISMATCH")
        root = ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )
        now = self.services.clock.now().replace(microsecond=0)
        timestamp = now.isoformat().replace("+00:00", "Z")
        if self.services.identities(request) != request.approved_identities:
            raise ContractError("PURGE_PREPARATION_IDENTITY_DRIFT")
        state = self.services.state(request)
        native = self.services.inventory(request, state)
        self.services.copy_evidence(request)
        actual = self.purge_adapter.inventory(inventory)
        expected = (*inventory.items, *inventory.retained)
        if len(actual) != len(set(actual)) or set(actual) != set(expected):
            raise ContractError("PURGE_PREPARATION_INVENTORY_DRIFT")
        expires = min(
            now + timedelta(minutes=15),
            parse_utc_timestamp(native.valid_until, "native expiry"),
            parse_utc_timestamp(state.inventory.valid_until, "state evidence expiry"),
            parse_utc_timestamp(inventory.valid_until, "purge expiry"),
            parse_utc_timestamp(request.profile.expires_at, "profile expiry"),
            parse_utc_timestamp(envelope.cost.valid_until, "cost expiry"),
            parse_utc_timestamp(OWNER_GOVERNANCE_EXPIRES_AT, "governance expiry"),
        )
        for reference in (
            *request.profile.evidence,
            request.profile.platform_cleanliness,
            request.profile.cleanup_spending,
        ):
            if reference is not None:
                expires = min(
                    expires, parse_utc_timestamp(reference.valid_until, "evidence expiry")
                )
        if expires <= self.services.clock.now():
            raise ContractError("PURGE_EVIDENCE_EXPIRED")
        expires_text = expires.isoformat().replace("+00:00", "Z")
        # Pagination proof comes from the completed adapter, not a Boolean input.
        proof = {
            "schema_version": OPERATIONAL_SCHEMA_VERSION,
            "operation_id": request.operation_id,
            "bucket": inventory.bucket,
            "versions_complete": True,
            "uploads_complete": True,
            "inventory_sha256": sha256_bytes(canonical_json_bytes(expected)),
            "retained_sha256": sha256_bytes(canonical_json_bytes(inventory.retained)),
            "observed_at": timestamp,
            "valid_until": expires_text,
        }
        proof_path = root / "purge-pagination.json"
        proof_hash = write_canonical_json_atomic(
            proof_path, proof, allowed_root=self.external_root, repository_root=self.repository_root
        )
        proof_ref = EvidenceRef(
            "purge-pagination",
            proof_path.name,
            proof_hash,
            proof_path.stat().st_size,
            "platformctl",
            timestamp,
            expires_text,
            request.operation_id,
        )
        frozen = replace(
            inventory,
            observed_at=timestamp,
            valid_until=expires_text,
            pagination_evidence=proof_ref,
        )
        path = root / "purge-inventory.json"
        digest = write_canonical_json_atomic(
            path, frozen, allowed_root=self.external_root, repository_root=self.repository_root
        )
        policy = {
            "schema_version": "w5-004.purge-policy-result.v2",
            "allow": True,
            "findings": [],
            "input_sha256": digest,
            "policy_sha256": sha256_file(self.repository_root / "tools/platformctl/destroy.py"),
            "exceptions_sha256": sha256_file(self.repository_root / "policies/opa/exceptions.json"),
        }
        policy_path = root / "policy-result.json"
        policy_hash = write_canonical_json_atomic(
            policy_path,
            policy,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        inputs = dict(request.approved_identities.inputs)
        inputs["review/purge-inventory.json"] = digest
        package = ReviewPackage(
            OPERATIONAL_SCHEMA_VERSION,
            request.operation_id,
            request.action,
            request.target,
            request.environment,
            native.account_id,
            native.region,
            "arn:aws:iam::526338061652:user/finopsinfra",
            request.profile,
            replace(request.approved_identities, inputs=tuple(sorted(inputs.items()))),
            EvidenceRef(
                "purge-inventory",
                path.name,
                digest,
                path.stat().st_size,
                "platformctl",
                timestamp,
                expires_text,
                request.operation_id,
            ),
            state,
            native,
            EvidenceRef(
                "policy-result",
                policy_path.name,
                policy_hash,
                policy_path.stat().st_size,
                "platformctl",
                timestamp,
                expires_text,
                request.operation_id,
            ),
            replace(envelope.cost, saved_plan_sha256=digest),
            request.profile.rules,
            timestamp,
            expires_text,
            expires_text,
            Outcome.INDETERMINATE,
        )
        validate_purge_review(package, BoundEvidenceReader(root, self.repository_root), now)
        if self.services.identities(request) != request.approved_identities:
            raise ContractError("PURGE_POST_REVIEW_IDENTITY_DRIFT")
        write_canonical_json_atomic(
            root / "candidate-review.json",
            package,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        return 3, "PURGE_INVENTORY_REVIEWED_CLEANUP_COST_BOUND_REQUIRED"


class ProductionReviewServices:
    """Concrete, request-bound ports used by the installed CLI and direct coordinator."""

    def __init__(
        self,
        configuration: RuntimeConfiguration,
        *,
        repository: Path,
        external: Path,
        ledger: OperationLedger,
        clock: Clock,
        process: CommandRunner,
        identity_runner: GitObservationRunner,
        aws: Boto3AwsInventoryProvider,
    ) -> None:
        self.configuration = configuration
        self._operation_root = external
        self._runtime_identity: tuple[str, str] | None = None
        self._remote_state_version: str | None = None
        self.repository_root = repository
        self.external_root = external
        self.ledger = ledger
        self.clock = clock
        self.git = identity_runner
        self.aws = aws
        self.targets = decode_operational_record(
            configuration.native_targets_json.encode("utf-8"), NativeTargetBundle
        ).targets
        self.post_targets = decode_operational_record(
            configuration.post_execution_targets_json.encode("utf-8"), NativeTargetBundle
        ).targets
        self.scans = decode_operational_record(
            configuration.native_scans_json.encode("utf-8"), NativeScanBundle
        )
        tools = {
            name: (path, version, digest) for name, path, version, digest in configuration.tools
        }
        if len(tools) != len(configuration.tools) or set(tools) != {
            "git",
            "terraform",
            "opa",
            "infracost",
        }:
            raise ContractError("RUNTIME_TOOLS_NOT_EXACT")
        for name, expected in (
            ("terraform", "1.16.1"),
            ("opa", "1.20.0"),
            ("infracost", "0.10.45"),
        ):
            if tools[name][1] != expected:
                raise ContractError("RUNTIME_TOOL_VERSION_NOT_APPROVED")
        environment = dict(configuration.child_environment)
        if len(environment) != len(configuration.child_environment):
            raise ContractError("RUNTIME_ENVIRONMENT_DUPLICATE")
        self.environment = controlled_environment(environment, cost_child=False)
        data_root = ensure_external_path(
            Path(configuration.terraform_data_root), external, repository
        )
        path, _, digest = tools["terraform"]
        self.terraform = TerraformRunner(
            executable=Path(path),
            executable_sha256=digest,
            runner=process,
            repository_root=repository,
            external_root=external,
            environment=self.environment,
            data_root=data_root,
        )
        path, _, digest = tools["opa"]
        self.policy = OpaPolicyRunner(
            executable=Path(path),
            executable_sha256=digest,
            runner=process,
            repository_root=repository,
            external_root=external,
            environment=self.environment,
        )
        path, _, digest = tools["infracost"]
        if Path(path) != INFRACOST_EXECUTABLE or digest != INFRACOST_EXECUTABLE_SHA256:
            raise ContractError("INFRACOST_TOOL_NOT_APPROVED")
        self.cost_runner = InfracostRunner(
            runner=process,
            repository_root=repository,
            external_root=external,
        )

    def _timestamp(self) -> str:
        return self.clock.now().replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _root(self, request: ReviewRequest) -> Path:
        return ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )

    def expiry_input(
        self,
        request: ReviewRequest,
        prepared: datetime,
        operation_root: Path,
    ) -> PreparedResourceExpiryInput:
        if request.action in {Action.BOOTSTRAP_APPLY, Action.PLATFORM_APPLY}:
            return prepare_resource_expiry_input(
                path=operation_root / "resource-expiry.tfvars.json",
                external_root=self.external_root,
                repository_root=self.repository_root,
                plan_preparation_time=prepared,
                environment=request.environment,
            )
        source = self.configuration.preserved_expiry_path
        if source is None:
            raise ContractError("APPLIED_EXPIRY_INPUT_REQUIRED")
        path = ensure_external_path(Path(source), self.external_root, self.repository_root)
        inputs = {
            logical: (file, digest) for logical, file, digest in self.configuration.input_files
        }
        if inputs.get("preserved-expiry") != (str(path), sha256_file(path)):
            raise ContractError("PRESERVED_EXPIRY_NOT_APPROVED")
        value = load_json_strict(path)
        if (
            not isinstance(value, dict)
            or set(value) != {"mandatory_tags"}
            or not isinstance(value["mandatory_tags"], dict)
        ):
            raise ContractError("PRESERVED_EXPIRY_SHAPE")
        expiry = value["mandatory_tags"].get("ExpiresAt")
        if not isinstance(expiry, str) or value["mandatory_tags"] != canonical_resource_tags(
            request.environment, expiry
        ):
            raise ContractError("PRESERVED_EXPIRY_TAGS")
        digest = write_canonical_json_atomic(
            operation_root / "resource-expiry.tfvars.json",
            value,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        return PreparedResourceExpiryInput(
            operation_root / "resource-expiry.tfvars.json",
            request.environment,
            prepared.isoformat().replace("+00:00", "Z"),
            expiry,
            digest,
        )

    def identities(self, request: ReviewRequest) -> IdentityBundle:
        return observe_repository_identities(
            self.configuration,
            request,
            repository=self.repository_root,
            git=self.git,
            environment=self.environment,
            runtime_identity=self._runtime_identity,
        )

    def _state_bytes(self, request: ReviewRequest) -> bytes | None:
        self._remote_state_version = None
        backend_configuration = self.terraform.verify_backend(
            self.repository_root
            / (
                "infra/bootstrap" if request.target == "bootstrap" else "infra/environments/sandbox"
            ),
            Path(request.backend_path),
            request.backend_sha256,
        )
        self.aws.verify_identity()
        if request.target == "bootstrap":
            source = self.configuration.local_state_path
            if source is None:
                raise ContractError("LOCAL_STATE_PATH_REQUIRED")
            approved_state = Path(
                "E:/AI/.runtime/enterprise_ai_platform/w5-004/owner-test-01/"
                "terraform-state/bootstrap.tfstate"
            )
            if Path(source) != approved_state:
                raise ContractError("LOCAL_STATE_PATH_NOT_APPROVED")
            if backend_configuration.get("path") != approved_state.as_posix():
                # HCL can preserve either Windows spelling; do not resolve an unrelated path.
                if backend_configuration.get("path") != str(approved_state):
                    raise ContractError("LOCAL_BACKEND_STATE_PATH_MISMATCH")
            path = ensure_external_path(Path(source), approved_state.parent, self.repository_root)
            if not path.exists():
                return None
            if path.stat().st_size > 64 * 1024 * 1024:
                raise ContractError("STATE_SIZE_LIMIT")
            return path.read_bytes()
        if self.configuration.state_probe_json is None:
            raise ContractError("REMOTE_STATE_EXISTENCE_PROBE_REQUIRED")
        probe_value = decode_json_strict(self.configuration.state_probe_json.encode())
        from .lifecycle_io import decode_record

        probe = decode_record(probe_value, NativeReadSpec)
        if probe.service != "s3" or probe.method != "head_object":
            raise ContractError("REMOTE_STATE_PROBE_NOT_EXACT")
        probe_arguments = decode_json_strict(probe.arguments_json.encode("utf-8"))
        if (
            probe_arguments
            != {
                "Bucket": backend_configuration["bucket"],
                "Key": backend_configuration["key"],
                "ExpectedBucketOwner": "526338061652",
            }
            or probe.expected_native_identity != backend_configuration["key"]
        ):
            raise ContractError("REMOTE_STATE_PROBE_BACKEND_MISMATCH")
        result = self.aws.bounded_reader().inspect(probe)
        if result.presence == "ABSENT":
            return None
        if result.presence != "PRESENT":
            raise ContractError("REMOTE_STATE_EXISTENCE_INDETERMINATE")
        raw = self.terraform.pull_state(self.repository_root / "infra/environments/sandbox")
        repeated = self.aws.bounded_reader().inspect(probe)
        if repeated.presence != "PRESENT" or repeated.remote_version != result.remote_version:
            raise ContractError("REMOTE_STATE_CHANGED_DURING_PULL")
        self._remote_state_version = result.remote_version
        return raw

    def state(self, request: ReviewRequest) -> StateEvidence:
        """Persist only state lineage/serial and address/type inventory, never attributes."""
        return self.observe_state(request, persist=True)

    def observe_state(
        self,
        request: ReviewRequest,
        *,
        persist: bool,
        filename: str = "state-inventory.json",
        post_execution: bool = False,
    ) -> StateEvidence:
        raw = self._state_bytes(request)
        lineage, serial, entries = state_inventory(raw)
        if not post_execution and (lineage, serial) != (
            self.configuration.expected_state_lineage,
            self.configuration.expected_state_serial,
        ):
            raise ContractError("CURRENT_STATE_NOT_APPROVED")
        digest = sha256_bytes(raw if raw is not None else b"STATE_ABSENT")
        timestamp = self._timestamp()
        expiry = (
            (self.clock.now().replace(microsecond=0) + timedelta(minutes=60))
            .isoformat()
            .replace("+00:00", "Z")
        )
        inventory = {
            "schema_version": OPERATIONAL_SCHEMA_VERSION,
            "operation_id": request.operation_id,
            "state_sha256": digest,
            "managed_resources": entries,
        }
        path = self._root(request) / bounded_relative_path(filename)
        encoded = canonical_json_bytes(inventory)
        if persist and path.exists():
            if path.read_bytes() != encoded:
                raise ContractError("STATE_INVENTORY_CHANGED")
        elif persist:
            write_canonical_json_atomic(
                path,
                inventory,
                allowed_root=self.external_root,
                repository_root=self.repository_root,
            )
        return StateEvidence(
            "local" if request.target == "bootstrap" else "s3",
            lineage,
            serial,
            digest,
            timestamp,
            self._remote_state_version,
            EvidenceRef(
                "state-inventory",
                path.name,
                sha256_bytes(encoded),
                len(encoded),
                "platformctl",
                timestamp,
                expiry,
                request.operation_id,
            ),
        )

    def observe(self, package: ReviewPackage) -> DispatchObservation:
        """Reobserve through the same ports; no approval flag can bypass native reads."""
        sources = {
            logical: (path, digest) for logical, path, digest in self.configuration.input_files
        }
        if "variables" not in sources or "backend" not in sources:
            raise ContractError("RUNTIME_VARIABLE_AND_BACKEND_BINDINGS_REQUIRED")
        variables, variables_hash = sources["variables"]
        backend, backend_hash = sources["backend"]
        root = self._operation_root
        request = ReviewRequest(
            OPERATIONAL_SCHEMA_VERSION,
            package.operation_id,
            package.action,
            package.target,
            package.environment,
            package.identities,
            package.profile,
            variables,
            variables_hash,
            backend,
            backend_hash,
            str(root),
        )
        identities = self.identities(request)
        inputs = dict(identities.inputs)
        for logical, digest in package.identities.inputs:
            if logical.startswith("review/"):
                actual = sha256_file(root / bounded_relative_path(logical.removeprefix("review/")))
                if actual != digest:
                    raise ContractError("REVIEW_INPUT_CHANGED")
                inputs[logical] = actual
        identities = replace(identities, inputs=tuple(sorted(inputs.items())))
        history = self.ledger.journal(package.operation_id)
        post_execution = bool(
            history and history[-1]["state"] == OperationPhase.EXECUTION_COMPLETED.value
        )
        state = self.observe_state(
            request,
            persist=post_execution,
            filename="post-state-inventory.json" if post_execution else "state-inventory.json",
            post_execution=post_execution,
        )
        native = self.inventory(
            request, state, post_execution=post_execution, reviewed_native=package.native
        )
        fresh_state = self.observe_state(request, persist=False, post_execution=post_execution)
        if (
            fresh_state.lineage,
            fresh_state.serial,
            fresh_state.sha256,
            fresh_state.remote_version,
        ) != (state.lineage, state.serial, state.sha256, state.remote_version):
            raise ContractError("STATE_CHANGED_DURING_NATIVE_RECONCILIATION")
        state = replace(state, observed_at=fresh_state.observed_at)
        identity = self.aws.verify_identity()
        final_identities = self.identities(request)
        final_inputs = dict(final_identities.inputs)
        final_inputs.update(
            {name: digest for name, digest in identities.inputs if name.startswith("review/")}
        )
        if replace(final_identities, inputs=tuple(sorted(final_inputs.items()))) != identities:
            raise ContractError("FINAL_DISPATCH_SOURCE_IDENTITY_DRIFT")
        return DispatchObservation(
            identities,
            state,
            native,
            identity.account_id,
            identity.region,
            identity.caller_arn,
            self._timestamp(),
        )

    def approval_consumed(self, operation_id: str, approval_id: str) -> bool:
        used = self.ledger.is_used(approval_id)
        if used and not self.ledger.execution_started(operation_id, approval_id):
            raise ContractError("CONSUMED_APPROVAL_RECONCILIATION_REQUIRED")
        return used

    def inventory(
        self,
        request: ReviewRequest,
        state: StateEvidence,
        *,
        post_execution: bool = False,
        reviewed_native: InventoryResult | None = None,
    ) -> InventoryResult:
        timestamp = self._timestamp()
        expires = (
            (self.clock.now().replace(microsecond=0) + timedelta(minutes=15))
            .isoformat()
            .replace("+00:00", "Z")
        )
        targets = self.post_targets if post_execution else self.targets
        if not post_execution:
            from .contracts import validate_native_prerequisites
            from .lifecycle_io import decode_record

            self.copy_evidence(request)
            prerequisites = validate_native_prerequisites(
                request.profile,
                state,
                BoundEvidenceReader(self._root(request), self.repository_root),
                self.clock.now(),
            )
            for prerequisite in prerequisites:
                probe = decode_record(
                    decode_json_strict(prerequisite.probe_json.encode("utf-8")), NativeReadSpec
                )
                fields = decode_json_strict(prerequisite.expected_fields_json.encode("utf-8"))
                observed = self.aws.bounded_reader().inspect(
                    probe, expected_fields=cast(dict[str, object], fields)
                )
                if observed.presence != prerequisite.presence or (
                    observed.presence == "PRESENT" and observed.configuration is not Outcome.PASS
                ):
                    raise ContractError("NATIVE_PREREQUISITE_CHANGED_OR_INDETERMINATE")
        private_state = self._state_bytes(request)
        if (
            sha256_bytes(private_state if private_state is not None else b"STATE_ABSENT")
            != state.sha256
        ):
            raise ContractError("NATIVE_STATE_IDENTITY_DRIFT")
        if post_execution:
            expiry_path = self._root(request) / "resource-expiry.tfvars.json"
            expiry_hash = dict(request.approved_identities.inputs).get(
                "review/resource-expiry.tfvars.json"
            )
            frozen_expiry = None
            if expiry_hash is not None:
                if sha256_file(expiry_path) != expiry_hash:
                    raise ContractError("POST_EXECUTION_EXPIRY_INPUT_DRIFT")
                expiry_record = load_json_strict(expiry_path)
                tags = (
                    expiry_record.get("mandatory_tags") if isinstance(expiry_record, dict) else None
                )
                frozen_expiry = tags.get("ExpiresAt") if isinstance(tags, dict) else None
                if not isinstance(frozen_expiry, str):
                    raise ContractError("POST_EXECUTION_EXPIRY_INPUT_MALFORMED")
            targets = resolve_post_execution_targets(
                targets,
                private_state,
                request.profile.rules,
                reviewed_native,
                frozen_expiry=frozen_expiry,
            )
        result = observe_native_targets(
            self.aws,
            self.aws.bounded_reader(),
            targets,
            operation_id=request.operation_id,
            observed_at=timestamp,
            valid_until=expires,
        )
        local_entries: list[InventoryEntry] = []
        state_value = decode_json_strict(
            BoundEvidenceReader(self._root(request), self.repository_root).read(
                state.inventory.path, state.inventory.sha256, state.inventory.byte_count
            )
        )
        if not isinstance(state_value, dict) or not isinstance(
            state_value.get("managed_resources"), list
        ):
            raise ContractError("STATE_INVENTORY_REQUIRED_FOR_LOCAL_SENTINEL")
        managed = {entry["address"] for entry in state_value["managed_resources"]}
        for rule in request.profile.rules:
            if (
                rule.resource_type == "aws_iam_policy_document"
                and ".data.aws_iam_policy_document." in "." + rule.address
            ):
                if rule.actions not in {("read",), ("no-op",)}:
                    raise ContractError("POLICY_DATA_SOURCE_ACTION_INVALID")
                local_entries.append(
                    InventoryEntry(
                        rule.address,
                        rule.resource_type,
                        None,
                        None,
                        "PROJECT_MANAGED",
                        "EVALUATION_ONLY",
                        Outcome.NOT_RUN,
                        False,
                        timestamp,
                    )
                )
            elif (
                rule.address == "terraform_data.owner_expiry_gate"
                and rule.resource_type == "terraform_data"
            ):
                present = rule.address in managed
                if present:
                    sentinel = _state_identity_projection(private_state).get(rule.address, {})
                    expiry_value = sentinel.get("input")
                    if not isinstance(expiry_value, str):
                        raise ContractError("SENTINEL_STATE_INPUT_UNCLASSIFIED")
                    parse_utc_timestamp(expiry_value, "state sentinel expiry")
                    if post_execution and rule.actions != ("delete",):
                        expiry_path = self._root(request) / "resource-expiry.tfvars.json"
                        expiry_record = load_json_strict(expiry_path)
                        tags = (
                            expiry_record.get("mandatory_tags")
                            if isinstance(expiry_record, dict)
                            else None
                        )
                        if not isinstance(tags, dict) or tags.get("ExpiresAt") != expiry_value:
                            raise ContractError("SENTINEL_POST_EXECUTION_EXPIRY_MISMATCH")
                local_entries.append(
                    InventoryEntry(
                        rule.address,
                        rule.resource_type,
                        None,
                        state.lineage if present else None,
                        "PROJECT_MANAGED",
                        "PRESENT" if present else "ABSENT",
                        Outcome.PASS if present else Outcome.NOT_RUN,
                        False,
                        timestamp,
                    )
                )
        result = replace(
            result,
            entries=tuple(
                sorted(
                    (*result.entries, *local_entries),
                    key=lambda entry: entry.address,
                )
            ),
        )
        if not post_execution:
            projection = _state_identity_projection(private_state)
            managed_rules = {
                rule.address
                for rule in request.profile.rules
                if rule.resource_type != "aws_iam_policy_document"
            }
            if request.action is not Action.PURGE_SANDBOX and set(projection) - managed_rules:
                raise ContractError("STATE_RESOURCE_OUTSIDE_REVIEW_PROFILE")
            rules = {rule.address: rule for rule in request.profile.rules}
            bound_entries: list[InventoryEntry] = []
            for entry in result.entries:
                rule = rules[entry.address]
                current = projection.get(entry.address)
                if rule.resource_type == "aws_iam_policy_document":
                    bound_entries.append(entry)
                    continue
                if rule.actions == ("create",):
                    if current is not None or entry.presence != "ABSENT":
                        raise ContractError("CREATE_REQUIRES_STATE_AND_NATIVE_ABSENCE")
                elif rule.actions in {("update",), ("no-op",), ("delete",)}:
                    if current is None or entry.presence not in {"PRESENT", "PENDING_DELETION"}:
                        raise ContractError("EXISTING_RESOURCE_STATE_NATIVE_MISMATCH")
                    if entry.presence == "PENDING_DELETION" and rule.actions != ("delete",):
                        raise ContractError("PENDING_DELETION_RESOURCE_NOT_USABLE")
                    if rule.resource_type != "terraform_data" and (
                        entry.native_identity is None
                        or entry.native_identity not in current.values()
                    ):
                        raise ContractError("NATIVE_TARGET_NOT_BOUND_TO_STATE_IDENTITY")
                bound_entries.append(
                    replace(
                        entry,
                        state_identity=entry.address if current is not None else None,
                    )
                )
            result = replace(result, entries=tuple(bound_entries))
        found = set(self.aws.discover(self.scans))
        expected_native = {
            native_identity_key(target.presence.service, target.presence.expected_native_identity)
            for target in targets
        }
        retained = {
            native_identity_key(service, identity)
            for service, identity in self.scans.retained_identities
        }
        if len(retained) != len(self.scans.retained_identities) or retained.intersection(
            expected_native
        ):
            raise ContractError("NATIVE_RETAINED_INVENTORY_DUPLICATED")
        if found - expected_native - retained:
            raise ContractError("UNEXPECTED_PROJECT_NATIVE_RESOURCE")
        if retained - found:
            raise ContractError("RETAINED_RESOURCE_OBSERVATION_DRIFT")
        result = replace(
            result,
            covered_services=tuple(
                sorted(set(result.covered_services) | {scan.coverage for scan in self.scans.scans})
            ),
        )
        if {(entry.address, entry.resource_type) for entry in result.entries} != {
            (rule.address, rule.resource_type) for rule in request.profile.rules
        }:
            raise ContractError("NATIVE_PROFILE_COVERAGE_MISMATCH")
        return result

    def cost(self, request: ReviewRequest, saved_plan: Path, plan_sha256: str) -> CostResultV2:
        """The actual CLI estimate supplies its own identity, not an asserted future hash."""
        from .aws_live import process_cost_environment

        terms = self.configuration.cost_terms
        if terms.operation_id != request.operation_id or terms.scope != request.target:
            raise ContractError("COST_TERMS_OPERATION_MISMATCH")
        self.copy_evidence(request)
        root = self._root(request)
        result = self.cost_runner.estimate_saved_plan(
            terraform_runner=self.terraform,
            terraform_root=self.repository_root
            / (
                "infra/bootstrap" if request.target == "bootstrap" else "infra/environments/sandbox"
            ),
            saved_plan=saved_plan,
            expected_saved_plan_sha256=plan_sha256,
            transient_plan_json=root / "private-cost-input.json",
            output_json=root / "infracost-result.json",
            environment=process_cost_environment(self.environment),
            review_terms=terms,
            evidence_reader=BoundEvidenceReader(root, self.repository_root),
            now=self.clock.now(),
            cleanup_review=request.action in {Action.PLATFORM_DESTROY, Action.BOOTSTRAP_DESTROY},
            state_lineage=self.configuration.expected_state_lineage,
        )
        if not isinstance(result, CostResultV2):
            raise ContractError("V2_COST_RESULT_REQUIRED")
        return result

    def copy_evidence(self, request: ReviewRequest) -> None:
        for reference, source in self.configuration.evidence_sources:
            if reference.operation_id != request.operation_id:
                raise ContractError("EXTERNAL_EVIDENCE_OPERATION_MISMATCH")
            path = ensure_external_path(Path(source), self.external_root, self.repository_root)
            raw = BoundEvidenceReader(path.parent, self.repository_root).read(
                path.name, reference.sha256, reference.byte_count
            )
            value = decode_json_strict(raw)
            if canonical_json_bytes(value) != raw:
                raise ContractError("EXTERNAL_EVIDENCE_NOT_CANONICAL")
            target = self._root(request) / bounded_relative_path(reference.path)
            if target.exists():
                if target.read_bytes() != raw:
                    raise ContractError("EVIDENCE_TARGET_COLLISION")
            else:
                write_canonical_json_atomic(
                    target,
                    value,
                    allowed_root=self.external_root,
                    repository_root=self.repository_root,
                )


def state_inventory(raw: bytes | None) -> tuple[str | None, int | None, list[dict[str, str]]]:
    """Inspect only resource identity structure and keep private state values in memory."""
    if raw is None:
        return None, None, []
    value = decode_json_strict(raw, maximum_bytes=64 * 1024 * 1024)
    if not isinstance(value, dict) or value.get("version") != 4:
        raise ContractError("STATE_SCHEMA_UNCLASSIFIED")
    lineage, serial, resources = value.get("lineage"), value.get("serial"), value.get("resources")
    if (
        not isinstance(lineage, str)
        or not lineage
        or type(serial) is not int
        or serial < 0
        or not isinstance(resources, list)
    ):
        raise ContractError("STATE_IDENTITY_UNCLASSIFIED")
    entries: list[dict[str, str]] = []
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("mode") not in {"data", "managed"}:
            raise ContractError("STATE_RESOURCE_UNCLASSIFIED")
        if resource["mode"] == "data":
            continue
        prefix = resource.get("module", "")
        kind, name, instances = (
            resource.get("type"),
            resource.get("name"),
            resource.get("instances"),
        )
        if (
            not isinstance(prefix, str)
            or not isinstance(kind, str)
            or not isinstance(name, str)
            or not isinstance(instances, list)
        ):
            raise ContractError("STATE_RESOURCE_SHAPE")
        for instance in instances:
            if not isinstance(instance, dict) or instance.get("deposed"):
                raise ContractError("STATE_INSTANCE_UNCLASSIFIED")
            address = f"{prefix + '.' if prefix else ''}{kind}.{name}"
            if "index_key" in instance:
                key = instance["index_key"]
                if type(key) not in {str, int}:
                    raise ContractError("STATE_INDEX_UNCLASSIFIED")
                address += "[" + canonical_json_bytes(key).decode().removesuffix("\n") + "]"
            entries.append({"address": address, "resource_type": kind})
    if len({entry["address"] for entry in entries}) != len(entries):
        raise ContractError("STATE_DUPLICATE_RESOURCE")
    return lineage, serial, sorted(entries, key=lambda entry: entry["address"])


def _state_identity_projection(raw: bytes | None) -> dict[str, dict[str, object]]:
    """Select only native identity fields and the expiry sentinel, in private memory."""
    state_inventory(raw)
    if raw is None:
        return {}
    value = cast(dict[str, object], decode_json_strict(raw, maximum_bytes=64 * 1024 * 1024))
    result: dict[str, dict[str, object]] = {}
    for resource in cast(list[dict[str, object]], value["resources"]):
        if resource["mode"] != "managed":
            continue
        prefix = cast(str, resource.get("module", ""))
        base = f"{prefix + '.' if prefix else ''}{resource['type']}.{resource['name']}"
        for instance in cast(list[dict[str, object]], resource["instances"]):
            address = base
            if "index_key" in instance:
                address += (
                    "["
                    + canonical_json_bytes(instance["index_key"]).decode().removesuffix("\n")
                    + "]"
                )
            attributes = instance.get("attributes")
            if not isinstance(attributes, dict):
                raise ContractError("STATE_NATIVE_IDENTITIES_UNCLASSIFIED")
            selected = {
                key: attributes[key]
                for key in (
                    "id",
                    "arn",
                    "name",
                    "bucket",
                    "role",
                    "domain_name",
                    "policy_name",
                    "route_table_id",
                    "repository",
                    "security_group_id",
                    "key_id",
                    "target_key_id",
                    "prefix_list_id",
                )
                if key in attributes
            }
            if address == "terraform_data.owner_expiry_gate":
                sentinel_input = attributes.get("input")
                # terraform_data stores its dynamic input as a typed value in state.
                if isinstance(sentinel_input, dict) and set(sentinel_input) == {"type", "value"}:
                    if sentinel_input["type"] != "string":
                        raise ContractError("SENTINEL_STATE_INPUT_TYPE")
                    sentinel_input = sentinel_input["value"]
                selected["input"] = sentinel_input
            result[address] = selected
    return result


def expected_platform_kms_policy(raw: bytes, digest: str, key_arn: str) -> dict[str, object]:
    """Extract one current bound policy privately; never enrich identity/report projections."""
    if sha256_bytes(raw) != digest:
        raise ContractError("KMS_EXPECTED_STATE_IDENTITY")
    document = decode_json_strict(raw)
    if not isinstance(document, dict) or not isinstance(document.get("resources"), list):
        raise ContractError("KMS_EXPECTED_STATE_MALFORMED")
    resources = [
        row
        for row in document["resources"]
        if isinstance(row, dict)
        and row.get("module") == "module.kms"
        and row.get("type") == "aws_kms_key"
        and row.get("name") == "this"
        and row.get("mode") == "managed"
    ]
    if len(resources) != 1 or not isinstance(resources[0].get("instances"), list):
        raise ContractError("KMS_EXPECTED_POLICY_MISSING")
    instances = resources[0]["instances"]
    if len(instances) != 1 or not isinstance(instances[0], dict) or instances[0].get("deposed"):
        raise ContractError("KMS_EXPECTED_INSTANCE_AMBIGUOUS")
    attributes = instances[0].get("attributes")
    if not isinstance(attributes, dict) or attributes.get("arn") != key_arn:
        raise ContractError("KMS_EXPECTED_KEY_IDENTITY")
    policy = attributes.get("policy")
    if not isinstance(policy, str):
        raise ContractError("KMS_EXPECTED_POLICY_MISSING")
    value = decode_json_strict(policy.encode())
    if not isinstance(value, dict) or not isinstance(value.get("Statement"), (dict, list)):
        raise ContractError("KMS_EXPECTED_POLICY_MALFORMED")
    return value


def private_policy_comparison(expected: object, native: object) -> dict[str, object]:
    """Exact parsed-JSON comparison; differing paths do not assert changed permissions."""
    differences: list[dict[str, str]] = []

    def walk(left: object, right: object, path: str) -> None:
        if type(left) is not type(right):
            differences.append({"path": path, "category": "TYPE_DIFFERENCE"})
        elif isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                # Only known policy field names are reportable; identifiers stay private.
                safe = (
                    key
                    if key
                    in {
                        "Version",
                        "Statement",
                        "Sid",
                        "Effect",
                        "Action",
                        "Resource",
                        "Principal",
                        "Condition",
                        "AWS",
                        "Service",
                    }
                    else "<field>"
                )
                child = path + "." + safe
                if key not in left or key not in right:
                    differences.append({"path": child, "category": "FIELD_MISSING"})
                else:
                    walk(left[key], right[key], child)
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                differences.append({"path": path, "category": "LENGTH_DIFFERENCE"})
            for index, (a, b) in enumerate(zip(left, right, strict=False)):
                walk(a, b, f"{path}[{index}]")
        elif left != right:
            differences.append({"path": path, "category": "VALUE_OR_ORDER_DIFFERENCE"})

    walk(expected, native, "policy")
    return {
        "equal": not differences,
        "differences": differences[:128],
        "differences_truncated": len(differences) > 128,
        "semantic_difference_proven": False,
    }


def _has_exact_opensearch_log_kms_statement(policy: object) -> bool:
    """Recognize only the reviewed regional Logs grant and four exact log-group contexts."""
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    selected = (
        [
            row
            for row in statements
            if isinstance(row, dict) and row.get("Sid") == "AllowExactOpenSearchLogEncryption"
        ]
        if isinstance(statements, list)
        else []
    )

    def values(value: object) -> set[str]:
        if isinstance(value, str):
            return {value}
        return (
            set(value)
            if isinstance(value, list) and all(isinstance(item, str) for item in value)
            else set()
        )

    if len(selected) != 1:
        return False
    statement = selected[0]
    condition = statement.get("Condition", {})
    return (
        statement.get("Effect") == "Allow"
        and statement.get("Principal") == {"Service": "logs.ap-southeast-1.amazonaws.com"}
        and values(statement.get("Action"))
        == {
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:ReEncryptFrom",
            "kms:ReEncryptTo",
        }
        and values(statement.get("Resource")) == {"*"}
        and isinstance(condition, dict)
        and set(condition) == {"ArnEquals"}
        and isinstance(condition.get("ArnEquals"), dict)
        and set(condition["ArnEquals"]) == {"kms:EncryptionContext:aws:logs:arn"}
        and values(condition["ArnEquals"]["kms:EncryptionContext:aws:logs:arn"])
        == {
            "arn:aws:logs:ap-southeast-1:526338061652:log-group:" + name
            for name in PREREQUISITE_LOG_NAMES
        }
    )


def resolve_post_execution_targets(
    targets: tuple[NativeTarget, ...],
    raw_state: bytes | None,
    rules: tuple[ResourceChangeRule, ...],
    reviewed_native: InventoryResult | None,
    *,
    frozen_expiry: str | None = None,
) -> tuple[NativeTarget, ...]:
    """Resolve whole-token identities; never interpolate or invent provider IDs.

    state://ADDRESS#id (or arn/name/bucket) reads the exact current state member.
    review://ADDRESS retains the pre-execution identity for deleted resources.
    The template is part of the immutable runtime identity approved before dispatch.
    """
    values = _state_identity_projection(raw_state)
    allowed = {rule.address for rule in rules}
    previous = (
        {}
        if reviewed_native is None
        else {entry.address: entry.native_identity for entry in reviewed_native.entries}
    )

    def resolve(value: object) -> object:
        if value == "expiry://resource":
            if frozen_expiry is None:
                raise ContractError("NATIVE_FROZEN_EXPIRY_REFERENCE_UNRESOLVED")
            parse_utc_timestamp(frozen_expiry, "frozen native expiry")
            return frozen_expiry
        if isinstance(value, str) and value.startswith("state://"):
            address, separator, field = value.removeprefix("state://").rpartition("#")
            if (
                not separator
                or address not in allowed
                or field not in {"id", "arn", "name", "bucket", "prefix_list_id"}
                or (
                    field == "prefix_list_id"
                    and address
                    not in {
                        'module.network.aws_vpc_endpoint.gateway["S3"]',
                        'module.network.aws_vpc_endpoint.gateway["DynamoDB"]',
                    }
                )
            ):
                raise ContractError("NATIVE_STATE_REFERENCE_NOT_APPROVED")
            selected = values.get(address, {}).get(field)
            if not isinstance(selected, str) or not selected:
                raise ContractError("NATIVE_STATE_REFERENCE_UNRESOLVED")
            return selected
        if isinstance(value, str) and value.startswith("review://"):
            address = value.removeprefix("review://")
            selected = previous.get(address)
            if address not in allowed or not isinstance(selected, str) or not selected:
                raise ContractError("NATIVE_REVIEW_REFERENCE_UNRESOLVED")
            return selected
        if isinstance(value, dict):
            return {key: resolve(child) for key, child in value.items()}
        if isinstance(value, list):
            return [resolve(child) for child in value]
        return value

    def json_projection(raw: str) -> str:
        return canonical_json_bytes(resolve(decode_json_strict(raw.encode("utf-8")))).decode(
            "utf-8"
        )

    def expected_projection(raw: str) -> str:
        from .aws_live import (
            diagnostic_policy_digest,
            native_policy_digest,
            native_unordered_value,
        )

        value = resolve(decode_json_strict(raw.encode("utf-8")))
        if not isinstance(value, dict):
            raise ContractError("NATIVE_EXPECTED_FIELDS_OBJECT_REQUIRED")
        # A reviewed policy template may use exact state identities and frozen expiry.
        # Hash its resolved semantics in memory; never persist the resulting policy.
        for path, expected in value.items():
            if path.endswith("@unordered"):
                value[path] = native_unordered_value(expected)
            if path.endswith("@policy_sha256") and isinstance(expected, dict):
                value[path] = native_policy_digest(expected)
            if path.endswith("@diagnostic_policy_sha256") and isinstance(expected, dict):
                value[path] = diagnostic_policy_digest(expected)
        return canonical_json_bytes(value).decode("utf-8")

    def probe(spec: NativeReadSpec) -> NativeReadSpec:
        return replace(
            spec,
            arguments_json=json_projection(spec.arguments_json),
            expected_native_identity=cast(str, resolve(spec.expected_native_identity)),
        )

    result: list[NativeTarget] = []
    for target in targets:
        if target.address not in allowed:
            raise ContractError("NATIVE_POST_TARGET_OUTSIDE_PROFILE")
        binding = target.ownership_binding
        result.append(
            replace(
                target,
                presence=probe(target.presence),
                assertions=tuple(
                    NativeAssertion(
                        assertion.category,
                        probe(assertion.probe),
                        expected_projection(assertion.expected_fields_json),
                    )
                    for assertion in target.assertions
                ),
                ownership_binding=None
                if binding is None
                else NativeOwnershipBinding(
                    binding.consumer_field,
                    cast(str, resolve(binding.parent_identity)),
                ),
            )
        )
    return tuple(result)


# Reviewed amended governance identities; public integrity values, not credentials.
DIAGNOSTIC_PROTECTED_IDENTITIES: tuple[tuple[str, str], ...] = (
    (
        ".secrets.baseline",
        # pragma: allowlist nextline secret
        "4fbc64d2ecae2978aa47e98c72a4a03e8f9a8ae0e0e04cadd126d7eca1b68453",
    ),
    (
        "docs/governance/Enterprise_AI_Architecture_6_Week_Execution_Tracker_v1.3.5.xlsx",
        # pragma: allowlist nextline secret
        "051504b1acf394d0dc268e3bf4a3487af95b7de5fb6fe0f98b1a5da960b30ccf",
    ),
    (
        "feature-matrix.yaml",
        # pragma: allowlist nextline secret
        "3df730b73588e773ddbc81a4f961a25c0ec0c17fe0f186cd391424f6b5095256",
    ),
    (
        "infra/bootstrap/main.tf",
        # pragma: allowlist nextline secret
        "c8f74bd67f8c6cfeb21d3a2f1744ddf0d5c1d05ce7d3da7db9b3c6431cd94cee",
    ),
    (
        "infra/bootstrap/versions.tf",
        # pragma: allowlist nextline secret
        "e24c3e797acf515399be65c895c372441be9a27364c23b02b38d7b446826e4b5",
    ),
    (
        "infra/environments/sandbox/main.tf",
        # pragma: allowlist nextline secret
        "a94aea6543fd08b4504bb9ea89962b0d74b7daf6c83b54245f6123362a85c60a",
    ),
    (
        "infra/environments/sandbox/versions.tf",
        # pragma: allowlist nextline secret
        "f8f87af1638121e67f3453b6c1392f2c9052eb94ba1fcf0afc2b0d0a1bfe7323",
    ),
    (
        "tests/contract/test_terraform_module_contract.py",
        # pragma: allowlist nextline secret
        "749f271cde9d8915ddf0341e7d8b28b1ca77ddeda4281e3c5ac0ab17de90ac7a",
    ),
    (
        "tests/feature/test_feature_matrix.py",
        # pragma: allowlist nextline secret
        "e352af31e94c8ec70d1662f713fb1aac2859efa86005b5edb20b207d6bb8224a",
    ),
    (
        "tests/feature/test_mvp_001_platformctl.py",
        # pragma: allowlist nextline secret
        "2aedc7f91f496eaa3331447ea974be33e7744784c44ebcb09d6afd8494c980a5",
    ),
    (
        "tests/security/test_precommit_controls.py",
        # pragma: allowlist nextline secret
        "ebce36d282bc574c839e3536ab1fff595abfd2c5082118dcfb402d3ca8e27b52",
    ),
    (
        "tests/security/test_repository_security.py",
        # pragma: allowlist nextline secret
        "6cfb7a1d355929520b966984208da6819fbbf1dac537b707a2f1cb4fb9ead733",
    ),
    (
        "tests/security/test_terraform_security.py",
        # pragma: allowlist nextline secret
        "a4d4ed85d63682f66b76d1e40a2862b18b3460933fc8fddd40004256ce9c2308",
    ),
    (
        "tests/teardown/test_platformctl_cleanup.py",
        # pragma: allowlist nextline secret
        "dfc663c4c6daaa8ce6c9a927bdf289137908d78a007b5450e5bea44a521487ae",
    ),
    (
        "tests/teardown/test_terraform_state_boundary.py",
        # pragma: allowlist nextline secret
        "14235777d14294d1540ce3be4122369c6f0da66b8dc08a36ed4a99e4020a41b0",
    ),
    (
        "tests/teardown/test_w1_08_cleanliness.py",
        # pragma: allowlist nextline secret
        "4917d4ebd96ad9c9c5394da427f71bd1873c1f8765e566bc8865ae19c259e4d2",
    ),
    (
        "tools/platformctl/__init__.py",
        # pragma: allowlist nextline secret
        "73a23bce7760940f2c7f5870f749a4a79692edf7d65031ce52a9dac6af255822",
    ),
    (
        "docs/governance/Enterprise_AI_Architecture_Source_of_Truth_v1.1.docx",
        # pragma: allowlist nextline secret
        "d4ce5c6d2cbba3704e8f7f385edeb16573cf21e009b1bf7e87914bace03fb04f",
    ),
    (
        "docs/learning/W5-002-W5-003-security-learning-review.docx",
        # pragma: allowlist nextline secret
        "ac029cb6e0a990ede8a81f204b3d46fe9bfb8e154577e0fca2d33f4249359457",
    ),
    (
        "configs/eval/baselines/w3-002-v1.json",
        # pragma: allowlist nextline secret
        "4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f",
    ),
    (
        "infra/environments/sandbox/terraform.tfvars.example",
        # pragma: allowlist nextline secret
        "6591ffc050788a08d7a8263a3b1c19199992ebb3adeafbdc2d2ec7c4b06ab630",
    ),
    (
        "docs/cost-estimates/W5-inputs.md",
        # pragma: allowlist nextline secret
        "0a0653f0f3a9ff83e8514326484e8807ee25cc1032a24d4cd85611a3c9df3687",
    ),
    (
        "infra/bootstrap/.terraform.lock.hcl",
        # pragma: allowlist nextline secret
        "9b0470598479b3d5b593f1c9f8d40d866a1e68b6bbaca9ffb8e7f784c381d0fc",
    ),
    (
        "infra/environments/sandbox/.terraform.lock.hcl",
        # pragma: allowlist nextline secret
        "9b0470598479b3d5b593f1c9f8d40d866a1e68b6bbaca9ffb8e7f784c381d0fc",
    ),
    (
        "requirements-runtime.lock",
        # pragma: allowlist nextline secret
        "796831a21aaa94d95d1e2a6a831b6770c1c8609527c05e0d079a573e9457a69a",
    ),
    (
        "requirements-ci.lock",
        # pragma: allowlist nextline secret
        "8e8592ebf3161f5e8d74d4944bb3b7ef506dd428ce679490dc8170e52e722ad2",
    ),
    (
        "requirements-checkov.lock",
        # pragma: allowlist nextline secret
        "1bd2e5915cca74ee60f82443bae15a49c109a1d614888bea1608ea5b18135da6",
    ),
    (
        "policies/opa/exceptions.json",
        # pragma: allowlist nextline secret
        "765c8889afb1ca4d0da148e120998343c979c02524a2b1f1070aa0aec83f4087",
    ),
)


def diagnostic_rules(scope: str) -> tuple[ResourceChangeRule, ...]:
    """Inventory membership only; not an approved recovery or mutation action set."""
    from .aws_inventory import diagnostic_resource_profile

    resources = [
        (target.address, target.resource_type)
        for target in diagnostic_resource_profile(scope).targets
    ]
    resources.append(("terraform_data.owner_expiry_gate", "terraform_data"))
    return tuple(
        ResourceChangeRule(address, kind, ("no-op",), (), "DIAGNOSTIC_ONLY")
        for address, kind in sorted(resources)
    )


def validate_diagnostic_profiles(configuration: DiagnosticRuntimeConfiguration) -> None:
    """Reject forged collection profiles before dispatch, including direct-function calls."""
    from .aws_inventory import diagnostic_discovery_profile, diagnostic_resource_profile

    for scope, encoded, rules in (
        ("bootstrap", configuration.bootstrap_targets_json, configuration.bootstrap_rules),
        ("platform", configuration.native_targets_json, configuration.platform_rules),
    ):
        if decode_operational_record(
            encoded.encode(), NativeTargetBundle
        ) != diagnostic_resource_profile(scope) or rules != diagnostic_rules(scope):
            raise ContractError("DIAGNOSTIC_REVIEWED_RESOURCE_PROFILE_CHANGED")
    if (
        decode_operational_record(configuration.native_scans_json.encode(), NativeScanBundle)
        != diagnostic_discovery_profile()
    ):
        raise ContractError("DIAGNOSTIC_REVIEWED_DISCOVERY_PROFILE_CHANGED")


DIAGNOSTIC_OPERATION_DIRECTORY = "codex-diagnostic-001/attempt-002"
DIAGNOSTIC_OPERATION_ID = "w5-004-codex-diagnostic-001-attempt-002"
DIAGNOSTIC_PRIOR_INPUTS = {
    # Integrity identities of the preserved, locally rejected first attempt.
    # pragma: allowlist nextline secret
    "diagnostic-request.json": "85c76c529afdb9adb51d94048b6daab7a48d2493b2e7f208389989e9a4e6a537",
    # pragma: allowlist nextline secret
    "diagnostic-runtime.json": "00575bdb12e3c0575f6cfc8377f889542dd2ce3f755fd705bb8dfa003decf784",
}


def verify_diagnostic_attempt_parent(root: Path, external: Path, repository: Path) -> None:
    """Continue only beneath this override's verified, preserved first-attempt root."""
    from .lifecycle_io import ensure_external_path, sha256_file, verify_private_directory

    ensure_external_path(root, external, repository)
    if root.exists():
        raise ContractError("DIAGNOSTIC_PREPARATION_DIRECTORY_ALREADY_EXISTS")
    verify_private_directory(root.parent)
    previous = root.parent / "attempt-001"
    if set(root.parent.iterdir()) != {previous}:
        raise ContractError("DIAGNOSTIC_PRIOR_ATTEMPT_INVENTORY_CHANGED")
    verify_private_directory(previous)
    inputs = previous / "inputs"
    verify_private_directory(inputs)
    if set(previous.iterdir()) != {inputs} or {p.name for p in inputs.iterdir()} != set(
        DIAGNOSTIC_PRIOR_INPUTS
    ):
        raise ContractError("DIAGNOSTIC_PRIOR_ATTEMPT_INVENTORY_CHANGED")
    for name, digest in DIAGNOSTIC_PRIOR_INPUTS.items():
        path = ensure_external_path(inputs / name, external, repository)
        if sha256_file(path) != digest:
            raise ContractError("DIAGNOSTIC_PRIOR_ATTEMPT_CONTENT_CHANGED")


def _build_owner_diagnostic_inputs(
    repository: Path,
    external: Path,
    source_sha256: str,
    *,
    resolution_only: bool = False,
    followup: bool = False,
    prerequisite_hashes: tuple[str, str] | None = None,
    correction: bool = False,
    prepare_correction_inputs: bool = False,
) -> tuple[DiagnosticRuntimeConfiguration, DiagnosticRequest, GitObservationRunner]:
    """Local owner entry point: existing evidence -> typed, reviewable diagnostic inputs.

    The full current manifest is owner-bound, not compared with obsolete pre-edit hashes.
    Historical state/pricing stay historical. No AWS client or pricing runner is created.
    Missing current accounting/incident acceptance remains unknown in the coordinator.
    """
    import os

    from .aws_inventory import diagnostic_discovery_profile, diagnostic_resource_profile
    from .contracts import validate_sha256
    from .lifecycle_io import (
        LIFECYCLE_ADMITTED_FILES,
        LIFECYCLE_BASELINE_HEAD,
        parse_git_status,
        unique_paths,
        working_manifest,
    )
    from .lifecycle_models import CONTENT_SCOPE_VERSION

    validate_sha256(source_sha256)
    if prepare_correction_inputs and not correction:
        raise ContractError("CORRECTION_PREPARATION_SCOPE_REQUIRED")
    if repository != Path("E:/AI/enterprise_ai_platform") or external != Path(
        "E:/AI/.tmp/enterprise-ai-platform-w5-004/owner-test-01"
    ):
        raise ContractError("DIAGNOSTIC_PREPARATION_EXACT_ROOTS_REQUIRED")
    parent = external / "consolidated-remediation-001"
    if followup and not resolution_only:
        raise ContractError("RESOLUTION_EXACT_SCOPE_REQUIRED")
    directory = (
        PREREQUISITE_CORRECTION_DIRECTORY
        if correction
        else PREREQUISITE_DIRECTORY
        if prerequisite_hashes is not None
        else RESOLUTION_FOLLOWUP_DIRECTORY
        if followup
        else RESOLUTION_DIRECTORY
    )
    if prerequisite_hashes is not None and (not resolution_only or followup):
        raise ContractError("PREREQUISITE_EXACT_SCOPE_REQUIRED")
    if correction and prerequisite_hashes is None:
        raise ContractError("PREREQUISITE_CORRECTION_BINDINGS_REQUIRED")
    root = parent / (directory if resolution_only else DIAGNOSTIC_OPERATION_DIRECTORY)
    ensure_external_path(root, external, repository)
    if resolution_only:
        if root.exists():
            raise ContractError("RESOLUTION_DIRECTORY_ALREADY_USED")
    else:
        verify_diagnostic_attempt_parent(root, external, repository)
    report_path = parent / "recovery-preparation-001/recovery-preparation-diagnostic.json"
    # pragma: allowlist nextline secret
    report_hash = "118832685bc529f526954039cfa4b262a85d377e8996bbe639b0dc1cd882720e"
    validate_original_ancestors(report_path)
    if sha256_file(report_path) != report_hash:
        raise ContractError("DIAGNOSTIC_PREPARATION_SOURCE_REPORT_CHANGED")
    report = load_json_strict(report_path)
    if not isinstance(report, dict) or (
        report.get("account_id") != "526338061652"
        or report.get("region") != "ap-southeast-1"
        or report.get("caller") != "arn:aws:iam::526338061652:user/finopsinfra"
        or report.get("repository_head") != LIFECYCLE_BASELINE_HEAD
    ):
        raise ContractError("DIAGNOSTIC_PREPARATION_SOURCE_REPORT_SCOPE")
    rows = report.get("tools")
    if not isinstance(rows, list) or len(rows) != 5:
        raise ContractError("DIAGNOSTIC_PREPARATION_TOOL_MANIFEST")
    tools: list[tuple[str, str, str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ContractError("DIAGNOSTIC_PREPARATION_TOOL_ROW")
        values = tuple(
            row.get(key) for key in ("name", "path", "expected_version", "executable_sha256")
        )
        if not all(isinstance(value, str) and value for value in values):
            raise ContractError("DIAGNOSTIC_PREPARATION_TOOL_FIELDS")
        name, tool_path, tool_version, tool_digest = cast(tuple[str, str, str, str], values)
        validate_original_ancestors(Path(tool_path))
        if sha256_file(Path(tool_path)) != tool_digest:
            raise ContractError("DIAGNOSTIC_PREPARATION_TOOL_CHANGED")
        tools.append((name, tool_path, tool_version, tool_digest))
    tool_map = {name: (path, version, digest) for name, path, version, digest in tools}
    if set(tool_map) != {"git", "python", "terraform", "opa", "infracost"}:
        raise ContractError("DIAGNOSTIC_PREPARATION_TOOL_NAMES")
    # Preserve the owner's Git trust context; never copy credential or routing variables.
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE", "HOME")
        if key in os.environ
    }
    environment.update(
        TEMP=str(
            (parent / "recovery-resolution-validation-002")
            if followup
            else external
            / ("resolution-validation-001" if resolution_only else "codex-validation-001")
        ),
        TMP=str(
            (parent / "recovery-resolution-validation-002")
            if followup
            else external
            / ("resolution-validation-001" if resolution_only else "codex-validation-001")
        ),
        GIT_OPTIONAL_LOCKS="0",
        PYTHONDONTWRITEBYTECODE="1",
    )
    environment = controlled_environment(environment, cost_child=False)
    if prerequisite_hashes is not None:
        environment["TEMP"] = str(
            parent
            / (
                "prerequisite-correction-validation-001"
                if correction
                else "prerequisite-validation-001"
            )
        )
        environment["TMP"] = environment["TEMP"]
    executable, version, digest = tool_map["git"]
    git = GitObservationRunner(
        Path(executable),
        digest,
        version,
        SubprocessCommandRunner(repository_root=repository, external_root=external),
        repository,
        environment,
    )
    tree = git.read("tree")
    if not tree.endswith(b"\x00"):
        raise ContractError("DIAGNOSTIC_PREPARATION_TREE_TRUNCATED")
    names = unique_paths((*tree.decode("utf-8").split("\x00")[:-1], *LIFECYCLE_ADMITTED_FILES))

    def current_manifest() -> str:
        records = working_manifest(repository, names)
        if len(records) != 517 or any(row[1] != "FILE" for row in records):
            raise ContractError("DIAGNOSTIC_PREPARATION_CONTENT_INVENTORY")
        return sha256_bytes(
            "".join(f"{name}|{digest}\n" for name, _, _, digest in records).encode("utf-8")
        )

    if current_manifest() != source_sha256:
        raise ContractError("DIAGNOSTIC_PREPARATION_REVIEWED_CONTENT_CHANGED")
    status = parse_git_status(git.read("status"))
    inputs = report.get("input_identities")
    if not isinstance(inputs, list):
        raise ContractError("DIAGNOSTIC_PREPARATION_INPUT_MANIFEST")
    input_map: dict[str, str] = {}
    for row in inputs:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ContractError("DIAGNOSTIC_PREPARATION_INPUT_ROW")
        input_source = row["path"]
        input_digest = row.get("sha256")
        if not isinstance(input_digest, str) or input_source in input_map:
            raise ContractError("DIAGNOSTIC_PREPARATION_INPUT_IDENTITY")
        input_map[input_source] = input_digest
    bootstrap_backend = external / "bootstrap/saved-plan-008/inputs/bootstrap.backend.hcl"
    platform_backend = external / "platform/saved-plan-007/inputs/platform.backend.hcl"
    base_input = external / "platform/saved-plan-007/inputs/platform.tfvars.json"
    bindings: list[tuple[str, str, str]] = [
        ("diagnostic/source-report.json", str(report_path), report_hash)
    ]
    if resolution_only:
        retained = parent / "codex-diagnostic-001/attempt-002/run-001/diagnostic.json"
        validate_original_ancestors(retained)
        if sha256_file(retained) != RESOLUTION_EVIDENCE_SHA256:
            raise ContractError("RESOLUTION_RETAINED_EVIDENCE_CHANGED")
        bindings.append(
            ("resolution/completed-diagnostic.json", str(retained), RESOLUTION_EVIDENCE_SHA256)
        )
    if followup:
        for name, digest in (
            ("resolution.json", RESOLUTION_FOLLOWUP_EVIDENCE_SHA256),
            ("resolution-identity.json", RESOLUTION_FOLLOWUP_IDENTITY_SHA256),
        ):
            path = parent / RESOLUTION_DIRECTORY / name
            validate_original_ancestors(path)
            if sha256_file(path) != digest:
                raise ContractError("RESOLUTION_RETAINED_EVIDENCE_CHANGED")
            bindings.append(("resolution/previous/" + name, str(path), digest))
    if prerequisite_hashes is not None:
        for name, digest in zip(
            ("resolution.json", "resolution-identity.json"), prerequisite_hashes, strict=True
        ):
            validate_sha256(digest)
            path = (
                parent
                / (PREREQUISITE_DIRECTORY if correction else RESOLUTION_FOLLOWUP_DIRECTORY)
                / name
            )
            validate_original_ancestors(path)
            if sha256_file(path) != digest:
                raise ContractError("PREREQUISITE_RETAINED_EVIDENCE_CHANGED")
            bindings.append(("prerequisite/previous/" + name, str(path), digest))
    for logical, path in (
        ("diagnostic/bootstrap.backend.hcl", bootstrap_backend),
        ("diagnostic/platform.backend.hcl", platform_backend),
        ("diagnostic/platform.tfvars.json", base_input),
    ):
        bound_digest = input_map.get(str(path))
        validate_original_ancestors(path)
        if bound_digest is None or sha256_file(path) != bound_digest:
            raise ContractError("DIAGNOSTIC_PREPARATION_EXISTING_INPUT_CHANGED")
        bindings.append((logical, str(path), bound_digest))
    states = report.get("states")
    if not isinstance(states, dict) or set(states) != {"bootstrap", "platform"}:
        raise ContractError("DIAGNOSTIC_PREPARATION_STATE_MANIFEST")
    expected_states: list[tuple[str, str, int, str]] = []
    for scope in ("bootstrap", "platform"):
        state = states[scope]
        if not isinstance(state, dict):
            raise ContractError("DIAGNOSTIC_PREPARATION_STATE_ROW")
        lineage, serial, state_digest = (
            state.get("lineage"),
            state.get("serial"),
            state.get("raw_state_sha256"),
        )
        if (
            not isinstance(lineage, str)
            or type(serial) is not int
            or not isinstance(state_digest, str)
        ):
            raise ContractError("DIAGNOSTIC_PREPARATION_STATE_FIELDS")
        expected_states.append((scope, lineage, serial, state_digest))
    if prerequisite_hashes is not None:
        bootstrap_state_path = Path(
            r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01\terraform-state\bootstrap.tfstate"
        )
        validate_original_ancestors(bootstrap_state_path)
        bootstrap_digest = next(row[3] for row in expected_states if row[0] == "bootstrap")
        if sha256_file(bootstrap_state_path) != bootstrap_digest:
            raise ContractError("PREREQUISITE_BOOTSTRAP_STATE_CHANGED")
        bindings.append(
            ("prerequisite/bootstrap-state", str(bootstrap_state_path), bootstrap_digest)
        )
    evidence_sources: tuple[tuple[EvidenceRef, str], ...] = ()
    if correction and not prepare_correction_inputs:
        for filename in ("owner-decisions.json", "charging-basis.json", "input-identity.json"):
            path = parent / "prerequisite-correction-inputs-001" / filename
            validate_original_ancestors(path)
            bindings.append(("correction/" + filename, str(path), sha256_file(path)))
        owner_input = load_json_strict(
            parent / "prerequisite-correction-inputs-001" / "owner-decisions.json"
        )
        if not isinstance(owner_input, dict) or not isinstance(owner_input.get("scope"), dict):
            raise ContractError("CORRECTION_OWNER_INPUT_INVALID")
        scope_input = owner_input["scope"]
        approval_path, approval_digest = (
            scope_input.get("approval_path"),
            scope_input.get("approval_sha256"),
        )
        if (
            not isinstance(approval_path, str)
            or not isinstance(approval_digest, str)
            or sha256_file(Path(approval_path)) != approval_digest
        ):
            raise ContractError("CORRECTION_APPROVAL_IDENTITY")
        bindings.append(("correction/approval", approval_path, approval_digest))
        from .lifecycle_models import CycleChargingEvidence

        charging_input = decode_operational_record(
            (parent / "prerequisite-correction-inputs-001" / "charging-basis.json").read_bytes(),
            CycleChargingEvidence,
        )
        evidence_sources = charging_input.sources
        correction_identity = load_json_strict(
            parent / "prerequisite-correction-inputs-001" / "input-identity.json"
        )
        if (
            not isinstance(correction_identity, dict)
            or correction_identity.get("source_sha256") != source_sha256
        ):
            raise ContractError("CORRECTION_PREPARATION_SOURCE_CHANGED")
        supplied_identity = correction_identity.get("supplied_charging_input")
        if supplied_identity is not None:
            if not isinstance(supplied_identity, dict) or set(supplied_identity) != {
                "path",
                "sha256",
            }:
                raise ContractError("CORRECTION_CHARGING_INPUT_IDENTITY")
            supplied_path, supplied_hash = supplied_identity["path"], supplied_identity["sha256"]
            if not isinstance(supplied_path, str) or not isinstance(supplied_hash, str):
                raise ContractError("CORRECTION_CHARGING_INPUT_IDENTITY")
            ensure_external_path(Path(supplied_path), external, repository)
            if sha256_file(Path(supplied_path)) != supplied_hash:
                raise ContractError("CORRECTION_CHARGING_INPUT_IDENTITY")
            bindings.append(("correction/supplied-charging-input", supplied_path, supplied_hash))
        DiagnosticEvidenceReader(evidence_sources, external, repository).verify_all()
        for reference, source_path in evidence_sources:
            bindings.append(("correction/source/" + reference.path, source_path, reference.sha256))
    pricing_path = parent / "pricing-breakdown-001/resource-pricing-breakdown.json"
    # pragma: allowlist nextline secret
    pricing_hash = "157768f419db9f572e3807286a624d0df5c8ba4e95fcce029a70e7d450e09e6d"
    validate_original_ancestors(pricing_path)
    pricing_raw = pricing_path.read_bytes()
    if sha256_bytes(pricing_raw) != pricing_hash:
        raise ContractError("DIAGNOSTIC_PREPARATION_HISTORICAL_PRICING_CHANGED")
    pricing = decode_json_strict(pricing_raw)
    if not isinstance(pricing, dict) or not isinstance(pricing.get("observed_at"), str):
        raise ContractError("DIAGNOSTIC_PREPARATION_PRICING_TIME_MISSING")
    observed = datetime.fromisoformat(pricing["observed_at"])
    if observed.tzinfo is None:
        raise ContractError("DIAGNOSTIC_PREPARATION_PRICING_TIME_UNCLASSIFIED")
    # No new validity or approval is assigned to historical disclosure.
    historical_time = observed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    pricing_reference = EvidenceRef(
        "HISTORICAL_PRICING_DISCLOSURE",
        "resource-pricing-breakdown.json",
        pricing_hash,
        len(pricing_raw),
        "pricing-breakdown-001",
        historical_time,
        historical_time,
        "w5-004-pricing-breakdown-001",
    )
    bindings.append(("diagnostic/historical-pricing.json", str(pricing_path), pricing_hash))
    configuration = DiagnosticRuntimeConfiguration(
        schema_version=DIAGNOSTIC_SCHEMA_VERSION,
        tools=tuple(sorted(tools)),
        child_environment=tuple(sorted(environment.items())),
        protected_files=DIAGNOSTIC_PROTECTED_IDENTITIES,
        authorized_status=status,
        input_files=tuple(bindings),
        terraform_data_root=str(external / "terraform-data"),
        bootstrap_backend_path=str(bootstrap_backend),
        bootstrap_backend_sha256=input_map[str(bootstrap_backend)],
        native_targets_json=canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        bootstrap_targets_json=canonical_json_bytes(
            diagnostic_resource_profile("bootstrap")
        ).decode(),
        native_scans_json=canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        platform_rules=diagnostic_rules("platform"),
        bootstrap_rules=diagnostic_rules("bootstrap"),
        retained_pricing=(pricing_reference, str(pricing_path)),
        exposure=None,
        evidence_sources=evidence_sources,
        failure_resolution=None,
    )
    # An in-memory observation carrier is replaced before serialization/publication.
    carrier = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        (
            (PREREQUISITE_CORRECTION_OPERATION if correction else PREREQUISITE_OPERATION_ID)
            if prerequisite_hashes is not None
            else RESOLUTION_FOLLOWUP_OPERATION_ID
            if followup
            else RESOLUTION_OPERATION_ID
        )
        if resolution_only
        else DIAGNOSTIC_OPERATION_ID,
        "sandbox",
        "platform",
        str(root),
        str(platform_backend),
        input_map[str(platform_backend)],
        IdentityBundle(CONTENT_SCOPE_VERSION, "", "", "", "", "", (), (), ""),
        tuple(expected_states),
    )
    source = observe_repository_identities(
        configuration,
        carrier,
        repository=repository,
        git=git,
        environment=environment,
        runtime_identity=None,
    )
    if current_manifest() != source_sha256:
        raise ContractError("DIAGNOSTIC_PREPARATION_CONTENT_CHANGED_DURING_READ")
    return configuration, replace(carrier, approved_identities=source), git


def prepare_owner_diagnostic(
    repository: Path, external: Path, source_sha256: str
) -> tuple[tuple[str, str], ...]:
    """Preserve ordinary artifact preparation; resolution inputs never use this writer."""
    configuration, request, git = _build_owner_diagnostic_inputs(
        repository, external, source_sha256
    )
    return prepare_diagnostic_artifacts(
        configuration,
        repository=repository,
        external=external,
        git=git,
        approved_source=request.approved_identities,
        backend_path=Path(request.backend_path),
        backend_sha256=request.backend_sha256,
        expected_states=request.expected_states,
    )


def run_owner_resolution(
    repository: Path,
    external: Path,
    source_sha256: str,
    evidence_sha256: str,
    *,
    clock: Clock,
    followup: bool = False,
) -> tuple[int, str]:
    """Construct verified records in memory and dispatch the existing read-only coordinator."""
    if evidence_sha256 != (
        RESOLUTION_FOLLOWUP_EVIDENCE_SHA256 if followup else RESOLUTION_EVIDENCE_SHA256
    ):
        raise ContractError("RESOLUTION_RETAINED_EVIDENCE_IDENTITY_REQUIRED")
    configuration, request, git = _build_owner_diagnostic_inputs(
        repository, external, source_sha256, resolution_only=True, followup=followup
    )
    aws = Boto3AwsInventoryProvider.from_profile(
        native_lister=None,
        profile="default",
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
        diagnostic_only=True,
    )
    coordinator = RepositoryDiagnosticCoordinator(
        configuration,
        repository=repository,
        external=external,
        clock=clock,
        git=git,
        session=DiagnosticAwsSession(aws, resolution_only=True, resolution_followup=followup),
        runtime_identity=None,
    )
    return coordinator.execute_request("aws-verify", canonical_json_bytes(request))


def run_owner_prerequisite(
    repository: Path,
    external: Path,
    source_sha256: str,
    evidence_sha256: str,
    evidence_identity_sha256: str,
    *,
    clock: Clock,
    correction: bool = False,
) -> tuple[int, str]:
    """Reviewed local inputs -> existing coordinator; no extra orchestration or artifacts."""
    options = {"correction": True} if correction else {}
    configuration, request, git = _build_owner_diagnostic_inputs(
        repository,
        external,
        source_sha256,
        resolution_only=True,
        prerequisite_hashes=(evidence_sha256, evidence_identity_sha256),
        **options,
    )
    aws = Boto3AwsInventoryProvider.from_profile(
        native_lister=None,
        profile="default",
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
        diagnostic_only=True,
    )
    coordinator = RepositoryDiagnosticCoordinator(
        configuration,
        repository=repository,
        external=external,
        clock=clock,
        git=git,
        session=DiagnosticAwsSession(
            aws, resolution_only=True, prerequisite=True, prerequisite_correction=correction
        ),
        runtime_identity=None,
    )
    return coordinator.execute_request("aws-verify", canonical_json_bytes(request))


def prepare_prerequisite_correction_inputs(
    repository: Path,
    external: Path,
    approval: Path,
    approval_sha256: str,
    *,
    clock: Clock,
    source_sha256: str,
    charging_input: tuple[Path, str] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Produce bounded diagnostic inputs; no missing charging fact is filled with an approval."""
    from .contracts import validate_recovery_scope_declaration, validate_sha256
    from .cost import PUBLIC_CHARGING_PAGES, cycle_required_charge_ids
    from .lifecycle_models import CycleCharge, CycleChargingEvidence, RecoveryScopeDeclaration

    validate_original_ancestors(approval)
    validate_sha256(source_sha256)
    if sha256_file(approval) != approval_sha256:
        raise ContractError("CORRECTION_APPROVAL_IDENTITY")
    declaration = RecoveryScopeDeclaration(
        "W5-CYCLE-A",
        "526338061652",
        (*PREREQUISITE_ROLES, PREREQUISITE_POLICY),
        "NO_ASSUME_MODIFY_DELETE_OR_INTENTIONAL_USE_UNLESS_REVIEWED_DEPENDENCY",
        str(approval),
        approval_sha256,
    )
    validate_recovery_scope_declaration(declaration)
    parent = external / "consolidated-remediation-001"
    root = parent / "prerequisite-correction-inputs-001"
    ensure_external_path(root, external, repository)
    if root.exists():
        raise ContractError("CORRECTION_INPUT_DIRECTORY_ALREADY_USED")
    # Retained observations are disclosures, not newly attested rate/quantity evidence.
    previous = parent / PREREQUISITE_DIRECTORY / "resolution.json"
    pricing = parent / "pricing-breakdown-001" / "resource-pricing-breakdown.json"
    for path in (previous, pricing):
        validate_original_ancestors(path)
    historical = load_json_strict(pricing)
    if not isinstance(historical, dict) or not isinstance(historical.get("resources"), list):
        raise ContractError("CORRECTION_PRICING_COMPONENTS_UNAVAILABLE")
    components = [
        CycleCharge(
            name,
            "W5_CYCLE_A",
            name,
            category,
            start,
            end,
            "USD",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        for name, category, start, end in (
            (
                "historical-account-reservation",
                "HISTORICAL_ACCOUNT_RESERVATION",
                "2026-09-08T00:00:00Z",
                "2026-09-13T00:00:00Z",
            ),
        )
    ]
    for resource in historical["resources"]:
        if not isinstance(resource, dict) or not isinstance(resource.get("components"), list):
            raise ContractError("CORRECTION_PRICING_COMPONENT_INVALID")
        address = resource.get("address")
        if not isinstance(address, str):
            raise ContractError("CORRECTION_PRICING_COMPONENT_INVALID")
        for row in resource["components"]:
            if not isinstance(row, dict) or type(row.get("component_id")) is not int:
                raise ContractError("CORRECTION_PRICING_COMPONENT_INVALID")
            identifier = f"{address}/component-{row['component_id']}"
            if identifier not in cycle_required_charge_ids():
                raise ContractError("CORRECTION_PRICING_COMPONENT_UNAPPROVED")
            unit, rate = row.get("unit"), row.get("unit_price_usd")
            if not isinstance(unit, str) or (rate is not None and not isinstance(rate, str)):
                raise ContractError("CORRECTION_PRICING_COMPONENT_INVALID")
            components.append(
                CycleCharge(
                    identifier,
                    address,
                    identifier,
                    "POST_CUTOFF_FIXED"
                    if row.get("monthly_cost_usd") is not None
                    else "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
                    "2026-09-13T00:00:00Z",
                    "2026-09-14T12:00:00Z",
                    unit,
                    None,
                    rate,
                    None,
                    None,
                    None,
                    None,
                )
            )
    for name in sorted(cycle_required_charge_ids() - {row.component_id for row in components}):
        tail = name.startswith("terminal-")
        components.append(
            CycleCharge(
                name,
                "W5_CYCLE_A",
                name,
                "RETAINED_TAIL" if tail else "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
                "2026-09-14T12:00:00Z" if tail else "2026-09-13T00:00:00Z",
                None if tail else "2026-09-14T12:00:00Z",
                "UNRESOLVED_CHARGING_UNIT",
                None,
                None,
                None,
                None,
                None,
                None,
            )
        )
    source_paths = [previous, pricing]
    public_root = parent / "pricing-basis-002"
    if public_root.exists():
        report_path, identity_path = (
            public_root / "charging-rates.json",
            public_root / "pricing-identity.json",
        )
        for path in (report_path, identity_path):
            validate_original_ancestors(path)
        public_report, public_identity = (
            load_json_strict(report_path),
            load_json_strict(identity_path),
        )
        if (
            not isinstance(public_report, dict)
            or not isinstance(public_identity, dict)
            or public_report.get("cycle") != "W5-CYCLE-A"
            or public_identity.get("report_sha256") != sha256_file(report_path)
            or not isinstance(public_identity.get("request"), dict)
            or public_identity["request"].get("urls") != list(PUBLIC_CHARGING_PAGES)
            or public_identity.get("request_sha256")
            != sha256_bytes(canonical_json_bytes(public_identity["request"]))
        ):
            raise ContractError("CORRECTION_PUBLIC_PRICING_IDENTITY")
        source_paths.extend((report_path, identity_path))
    charging = CycleChargingEvidence(
        "w5-004.lifecycle.v2",
        "W5-CYCLE-A",
        "USD",
        tuple(components),
        tuple(row.component_id for row in components),
        clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
        None,
        tuple(
            (
                EvidenceRef(
                    "HISTORICAL_DISCLOSURE_NOT_COST_AUTHORITY",
                    path.name,
                    sha256_file(path),
                    path.stat().st_size,
                    "retained-evidence",
                    "2026-09-13T00:00:00Z",
                    "2026-09-13T00:00:00Z",
                    "W5-CYCLE-A",
                ),
                str(path),
            )
            for path in source_paths
        ),
    )
    charging_input_identity = None
    if charging_input is not None:
        from .cost import calculate_cycle_charges

        supplied_path, supplied_hash = charging_input
        ensure_external_path(supplied_path, external, repository)
        validate_original_ancestors(supplied_path)
        validate_sha256(supplied_hash)
        raw = supplied_path.read_bytes()
        if sha256_bytes(raw) != supplied_hash:
            raise ContractError("CORRECTION_CHARGING_INPUT_IDENTITY")
        supplied = decode_operational_record(raw, CycleChargingEvidence)
        if not cycle_required_charge_ids() <= set(supplied.required_components):
            raise ContractError("CORRECTION_CHARGING_COVERAGE_INCOMPLETE")
        evidence_reader = DiagnosticEvidenceReader(supplied.sources, external, repository)
        evidence_reader.verify_all()
        calculate_cycle_charges(supplied, reader=evidence_reader, now=clock.now(), final_requests=0)
        charging = supplied
        charging_input_identity = {"path": str(supplied_path), "sha256": supplied_hash}
    reserve_operation_directory(root, external, repository)
    outputs = []
    for name, value in (
        (
            "owner-decisions.json",
            {
                "scope": declaration,
                "archive_status": "DESIGN_ONLY_NOT_EXECUTED_OR_VERIFIED",
                "archive_location": str(
                    Path(
                        r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01\terminal-archive-001"
                    )
                ),
                "archive_plaintext_max_bytes": 16 * 1024 * 1024,
                "archive_stored_max_bytes": 20 * 1024 * 1024,
                "archive_deadline": "2026-09-21T12:00:00Z",
                "archive_encryption": "DPAPI_CURRENT_USER",
                "status": "DIAGNOSTIC_ONLY_NOT_EXECUTION_READY",
            },
        ),
        ("charging-basis.json", charging),
    ):
        digest = write_canonical_json_atomic(
            root / name, value, allowed_root=external, repository_root=repository
        )
        outputs.append((str(root / name), digest))
    identity: dict[str, object] = {Path(path).name: digest for path, digest in outputs}
    identity.update(
        {
            "approval_sha256": approval_sha256,
            "source_sha256": source_sha256,
            "supplied_charging_input": charging_input_identity,
            "previous_report_sha256": sha256_file(previous),
            "historical_pricing_sha256": sha256_file(pricing),
            "historical_rates": "DISCLOSED_NOT_VERIFIED_NO_MINIMA_OR_LIFETIME_INFERRED",
            "status": "DIAGNOSTIC_ONLY_COST_BLOCKED",
        }
    )
    digest = write_canonical_json_atomic(
        root / "input-identity.json", identity, allowed_root=external, repository_root=repository
    )
    return (*outputs, (str(root / "input-identity.json"), digest))


def prepare_diagnostic_artifacts(
    configuration: DiagnosticRuntimeConfiguration,
    *,
    repository: Path,
    external: Path,
    git: GitObservationRunner,
    approved_source: IdentityBundle,
    backend_path: Path,
    backend_sha256: str,
    expected_states: tuple[tuple[str, str, int, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Owner-invoked local preparation; returned identities still require owner review.

    No credentials, live observations, cost amounts or approval timestamps are generated.
    The caller supplies the reviewed typed inputs and current approved source identity.
    """
    root = external / "consolidated-remediation-001" / DIAGNOSTIC_OPERATION_DIRECTORY
    ensure_external_path(root, external, repository)
    verify_diagnostic_attempt_parent(root, external, repository)
    if configuration.schema_version != DIAGNOSTIC_SCHEMA_VERSION:
        raise ContractError("DIAGNOSTIC_RUNTIME_SCHEMA_REQUIRED")
    decode_diagnostic_record(canonical_json_bytes(configuration), DiagnosticRuntimeConfiguration)
    validate_diagnostic_profiles(configuration)
    validate_diagnostic_state_bindings(expected_states)
    for encoded, rules, count in (
        (configuration.bootstrap_targets_json, configuration.bootstrap_rules, 11),
        (configuration.native_targets_json, configuration.platform_rules, 42),
    ):
        bundle = decode_operational_record(encoded.encode(), NativeTargetBundle)
        resources = {rule.address: rule.resource_type for rule in rules}
        required = {
            address: kind for address, kind in resources.items() if kind != "terraform_data"
        }
        if (
            len(resources) != count
            or len(rules) != count
            or {target.address: target.resource_type for target in bundle.targets} != required
            or len(bundle.targets) != len(required)
            or "aws_iam_service_linked_role" in resources.values()
        ):
            raise ContractError("DIAGNOSTIC_PREPARATION_RESOURCE_PROFILE_INCOMPLETE")
    scans = diagnostic_scan_bundle(configuration.native_scans_json)
    if {scan.coverage for scan in scans.scans} != diagnostic_discovery_coverage() or len(
        scans.scans
    ) != len(diagnostic_discovery_coverage()):
        raise ContractError("DIAGNOSTIC_PREPARATION_DISCOVERY_PROFILE_INCOMPLETE")
    DiagnosticEvidenceReader(configuration.evidence_sources, external, repository).verify_all()
    runtime_path = root / "inputs/diagnostic-runtime.json"
    runtime_hash = sha256_bytes(canonical_json_bytes(configuration))
    request = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        DIAGNOSTIC_OPERATION_ID,
        "sandbox",
        "platform",
        str(root),
        str(backend_path),
        backend_sha256,
        approved_source,
        expected_states,
    )
    observed = observe_repository_identities(
        configuration,
        request,
        repository=repository,
        git=git,
        environment=dict(configuration.child_environment),
        runtime_identity=None,
    )
    if observed != approved_source:
        raise ContractError("DIAGNOSTIC_PREPARATION_APPROVED_SOURCE_CHANGED")
    inputs = dict(observed.inputs)
    if "runtime/configuration.json" in inputs:
        raise ContractError("DIAGNOSTIC_PREPARATION_RUNTIME_IDENTITY_DUPLICATED")
    inputs["runtime/configuration.json"] = runtime_hash
    request = replace(
        request,
        approved_identities=replace(observed, inputs=tuple(sorted(inputs.items()))),
    )
    raw_request = canonical_json_bytes(request)
    decode_diagnostic_record(raw_request, DiagnosticRequest)
    verify_private_directory(root.parent.parent)
    verify_diagnostic_attempt_parent(root, external, repository)
    reserve_operation_directory(root, external, repository)
    written_runtime = write_canonical_json_atomic(
        runtime_path,
        configuration,
        allowed_root=external,
        repository_root=repository,
    )
    written_request = write_canonical_json_atomic(
        root / "inputs/diagnostic-request.json",
        request,
        allowed_root=external,
        repository_root=repository,
    )
    after = observe_repository_identities(
        configuration,
        request,
        repository=repository,
        git=git,
        environment=dict(configuration.child_environment),
        runtime_identity=(str(runtime_path), runtime_hash),
    )
    if written_runtime != runtime_hash or after != request.approved_identities:
        raise ContractError("DIAGNOSTIC_PREPARATION_CHANGED_PRESERVE_ARTIFACTS")
    return (
        (str(root / "inputs/diagnostic-request.json"), written_request),
        (str(runtime_path), written_runtime),
    )


def validate_diagnostic_state_bindings(
    bindings: tuple[tuple[str, str, int, str], ...],
) -> dict[str, tuple[str, int, str]]:
    from .contracts import validate_sha256
    from .lifecycle_io import approved_monthly_exception

    expected = {scope: (lineage, serial, digest) for scope, lineage, serial, digest in bindings}
    if set(expected) != {"bootstrap", "platform"} or len(bindings) != 2:
        raise ContractError("DIAGNOSTIC_STATE_BINDINGS_REQUIRED")
    cycle = approved_monthly_exception()
    for scope, (lineage, serial, digest) in expected.items():
        if lineage != cycle[scope + "_lineage"] or type(serial) is not int or serial < 0:
            raise ContractError("DIAGNOSTIC_STATE_IDENTITY_SCOPE")
        validate_sha256(digest)
    return expected


class DiagnosticChecks:
    """Independent failures accumulate; dependent or unsafe work is explicitly blocked."""

    def __init__(self, clock: Clock, session: DiagnosticAwsSession) -> None:
        self.clock, self.session = clock, session
        self.checks: list[DiagnosticCheck] = []

    def run(
        self,
        name: str,
        collect: Callable[[], tuple[DiagnosticStatus, str, dict[str, object]]],
        *,
        dependencies: tuple[str, ...] = (),
        mandatory: bool = True,
        remote: bool = False,
    ) -> None:
        if (
            getattr(self.session, "prerequisite_correction", False)
            and name not in PREREQUISITE_CORRECTION_CHECK_IDS
        ):
            return
        known = {check.check_id: check for check in self.checks}
        if name in known or any(dependency not in known for dependency in dependencies):
            raise ContractError("DIAGNOSTIC_DEPENDENCY_GRAPH_INVALID")
        details: dict[str, object] = {}
        if any(
            known[dependency].status is not DiagnosticStatus.PASS for dependency in dependencies
        ):
            status, reason = DiagnosticStatus.BLOCKED, "REQUIRED_DEPENDENCY_UNRESOLVED"
            details["blocked_by"] = [
                dependency
                for dependency in dependencies
                if known[dependency].status is not DiagnosticStatus.PASS
            ]
        elif remote and self.session.fatal_reason is not None:
            status, reason = DiagnosticStatus.BLOCKED, "REMOTE_COLLECTION_STOPPED"
            details["stop_reason"] = diagnostic_failure_reason(
                DiagnosticFatalError(self.session.fatal_reason)
            )
        else:
            try:
                status, reason, details = collect()
                if remote and self.session.fatal_reason is not None:
                    status = DiagnosticStatus.FAIL
                    reason = diagnostic_failure_reason(
                        DiagnosticFatalError(self.session.fatal_reason)
                    )
            except DiagnosticFatalError as exc:
                status, reason = DiagnosticStatus.FAIL, diagnostic_failure_reason(exc)
                if self.session.fatal_reason is None:
                    self.session.fatal_reason = reason
            except (DiagnosticCollectionError, DiagnosticReadError) as exc:
                status, reason = DiagnosticStatus.INDETERMINATE, diagnostic_failure_reason(exc)
            except ContractError as exc:
                status = DiagnosticStatus.INDETERMINATE
                # Only fixed reviewed classifications may escape; never arbitrary error text.
                safe_reasons = {
                    "UNTAGGED_RESOURCE_OWNERSHIP_UNCLASSIFIED",
                    "PROJECT_RESOURCE_TAGS_INCOMPLETE",
                    "PROJECT_RESOURCE_CANNOT_BE_EXCLUDED",
                    "NATIVE_DISCOVERY_TAG_READ_INDETERMINATE",
                    "NATIVE_DISCOVERY_OWNERSHIP_TAGS_UNAVAILABLE",
                    "NATIVE_DISCOVERY_OWNERSHIP_INDETERMINATE",
                    "NATIVE_DISCOVERY_BUCKET_REGION_UNVERIFIED",
                    "NATIVE_DISCOVERY_BUCKET_REGION_MALFORMED",
                    "NATIVE_ASSERTION_FIELD_UNAVAILABLE",
                    "NATIVE_DISCOVERY_DETAIL_IDENTITY_INVALID",
                    "NATIVE_DISCOVERY_RESPONSE_INVALID",
                    "NATIVE_DISCOVERY_PAGINATION_INCOMPLETE",
                    "NATIVE_DISCOVERY_PAGINATION_INVALID",
                    "NATIVE_DISCOVERY_IDENTITY_INVALID",
                    "NATIVE_TAG_STRUCTURE_INVALID",
                    "QUERY_COST_BASIS_REQUIRED",
                    "NATIVE_DISCOVERY_PAGE_LIMIT",
                    "NATIVE_DISCOVERY_ITEM_LIMIT",
                    "DIAGNOSTIC_DISCOVERY_TOTAL_LIMIT",
                    "DIAGNOSTIC_UNCLASSIFIED_STATE_RESOURCE",
                    "DIAGNOSTIC_EXPIRY_SENTINEL_REQUIRED",
                    "NATIVE_STATE_REFERENCE_UNRESOLVED",
                    "CURRENT_LIFECYCLE_ACCOUNTING_EVIDENCE_REQUIRED",
                    "HISTORICAL_FAILURE_RESOLUTION_REQUIRED",
                    "RETAINED_PRICING_EVIDENCE_REQUIRED",
                }
                reason = (
                    str(exc) if str(exc) in safe_reasons else "COLLECTION_OR_CONTRACT_UNRESOLVED"
                )
            except Exception:
                # Exception messages, service responses and policies never become evidence.
                status, reason = DiagnosticStatus.INDETERMINATE, "COLLECTION_OR_CONTRACT_UNRESOLVED"
        self.checks.append(
            DiagnosticCheck(
                name,
                status,
                mandatory,
                reason,
                dependencies,
                self.clock.now().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                tuple(
                    (key, canonical_json_bytes(value).decode().rstrip("\n"))
                    for key, value in sorted(details.items())
                ),
            )
        )

    @property
    def exit_code(self) -> int:
        return int(
            any(
                check.mandatory and check.status is not DiagnosticStatus.PASS
                for check in self.checks
            )
        )


def diagnostic_scan_bundle(encoded: str) -> NativeScanBundle:
    """Apply the settled owner-managed role treatment, never the legacy role as well."""
    bundle = decode_operational_record(encoded.encode(), NativeScanBundle)
    role = (
        "iam",
        "arn:aws:iam::526338061652:role/aws-service-role/"
        "opensearchservice.amazonaws.com/AWSServiceRoleForAmazonOpenSearchService",
        "OWNER_MANAGED",
    )
    matching = tuple(item for item in bundle.excluded_identities if item[:2] == role[:2])
    if matching and matching != (role,):
        raise ContractError("DIAGNOSTIC_OWNER_ROLE_TREATMENT_CONFLICT")
    if matching:
        return bundle
    return replace(bundle, excluded_identities=tuple(sorted((*bundle.excluded_identities, role))))


class RepositoryDiagnosticCoordinator:
    """Production read-only path: no ledger, plan runner, pricing runner or mutation dispatch."""

    def __init__(
        self,
        configuration: DiagnosticRuntimeConfiguration,
        *,
        repository: Path,
        external: Path,
        clock: Clock,
        git: GitObservationRunner,
        session: DiagnosticAwsSession,
        runtime_identity: tuple[str, str] | None,
    ) -> None:
        self.configuration = configuration
        self.repository_root, self.external_root = repository, external
        self.clock, self.git, self.session = clock, git, session
        self.runtime_identity = runtime_identity
        self._started = False

    def identities(self, request: DiagnosticRequest) -> IdentityBundle:
        return observe_repository_identities(
            self.configuration,
            request,
            repository=self.repository_root,
            git=self.git,
            environment=dict(self.configuration.child_environment),
            runtime_identity=self.runtime_identity,
        )

    def execute_request(self, command: str, payload: bytes) -> tuple[int, str]:
        if command != "aws-verify" or self._started:
            raise ContractError("DIAGNOSTIC_SINGLE_READ_ONLY_DISPATCH_REQUIRED")
        request = decode_diagnostic_record(payload, DiagnosticRequest)
        if getattr(self.session, "prerequisite", False):
            return self._execute_prerequisite(request, payload)
        if getattr(self.session, "resolution_only", False):
            return self._execute_resolution(request, payload)
        if self.runtime_identity is None:
            raise ContractError("DIAGNOSTIC_RUNTIME_IDENTITY_REQUIRED")
        root = ensure_external_path(
            Path(request.operation_root),
            self.external_root,
            self.repository_root,
        )
        if (
            root
            != (
                self.external_root / "consolidated-remediation-001" / DIAGNOSTIC_OPERATION_DIRECTORY
            )
            or request.environment != "sandbox"
            or request.target != "platform"
            or request.operation_id != DIAGNOSTIC_OPERATION_ID
            or self.configuration.schema_version != DIAGNOSTIC_SCHEMA_VERSION
            or Path(self.runtime_identity[0]) != root / "inputs/diagnostic-runtime.json"
        ):
            raise ContractError("DIAGNOSTIC_EXACT_SCOPE_REQUIRED")
        expected = validate_diagnostic_state_bindings(request.expected_states)
        validate_diagnostic_profiles(self.configuration)
        verify_private_directory(root)
        if set(root.iterdir()) != {root / "inputs"} or set((root / "inputs").iterdir()) != {
            root / "inputs/diagnostic-request.json",
            root / "inputs/diagnostic-runtime.json",
        }:
            raise ContractError("DIAGNOSTIC_DIRECTORY_ALREADY_USED_OR_UNCLASSIFIED")
        if (root / "inputs/diagnostic-request.json").read_bytes() != payload:
            raise ContractError("DIAGNOSTIC_REQUEST_CHANGED")
        if self.identities(request) != request.approved_identities:
            raise ContractError("DIAGNOSTIC_SOURCE_IDENTITY_CHANGED")
        if (
            sha256_file(Path(self.configuration.bootstrap_backend_path))
            != self.configuration.bootstrap_backend_sha256
        ):
            raise ContractError("DIAGNOSTIC_BOOTSTRAP_BACKEND_CHANGED")
        reader = DiagnosticEvidenceReader(
            self.configuration.evidence_sources,
            self.external_root,
            self.repository_root,
        )
        reader.verify_all()
        self._started = True
        reserve_operation_directory(root / "run-001", self.external_root, self.repository_root)
        started = self.clock.now().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        checks = DiagnosticChecks(self.clock, self.session)
        private_states: dict[str, bytes] = {}
        inventories: dict[str, InventoryResult] = {}
        targets_by_scope: dict[str, tuple[NativeTarget, ...]] = {}
        discovered: set[tuple[str, str]] = set()

        def passed() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            return DiagnosticStatus.PASS, "VERIFIED", {}

        def identity() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            self.session.verify_identity()
            return passed()

        checks.run("aws_identity", identity, remote=True)
        bootstrap_state = Path(
            r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01"
            r"\terraform-state\bootstrap.tfstate"
        )

        def state(scope: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            raw = (
                read_private_state(
                    bootstrap_state,
                    approved_path=bootstrap_state,
                    repository=self.repository_root,
                )
                if scope == "bootstrap"
                else self.session.state_bytes()[0]
            )
            lineage, serial, addresses = state_inventory(raw)
            digest = sha256_bytes(raw)
            private_states[scope] = raw
            matches = (lineage, serial, digest) == expected[scope]
            rules = (
                self.configuration.bootstrap_rules
                if scope == "bootstrap"
                else self.configuration.platform_rules
            )
            governed = {rule.address: rule.resource_type for rule in rules}
            classified = [
                item for item in addresses if governed.get(item["address"]) == item["resource_type"]
            ]
            if len(classified) != len(addresses):
                matches = False
            if not matches:
                self.session.fatal_reason = "DIAGNOSTIC_STATE_IDENTITY_CHANGED"
            return (
                DiagnosticStatus.PASS if matches else DiagnosticStatus.FAIL,
                "STATE_IDENTITY_MATCH" if matches else "STATE_IDENTITY_CHANGED",
                {
                    "lineage": lineage,
                    "serial": serial,
                    "sha256": digest,
                    "identity_basis": (
                        "LOCAL_STATE_BYTES" if scope == "bootstrap" else "S3_OBJECT_BYTES"
                    ),
                    "managed_resources": classified,
                    "unclassified_managed_count": len(addresses) - len(classified),
                },
            )

        for scope in ("bootstrap", "platform"):

            def collect_state(
                scope: str = scope,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return state(scope)

            checks.run(
                scope + "_state",
                collect_state,
                dependencies=("aws_identity",),
                remote=scope == "platform",
            )

        def target_templates(scope: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            encoded = (
                self.configuration.bootstrap_targets_json
                if scope == "bootstrap"
                else self.configuration.native_targets_json
            )
            rules = (
                self.configuration.bootstrap_rules
                if scope == "bootstrap"
                else self.configuration.platform_rules
            )
            bundle = decode_operational_record(encoded.encode(), NativeTargetBundle)
            resources = {rule.address: rule.resource_type for rule in rules}
            if len(resources) != len(rules) or len(resources) != (
                11 if scope == "bootstrap" else 42
            ):
                raise ContractError("DIAGNOSTIC_GOVERNED_RESOURCE_COVERAGE")
            required = {
                address: kind for address, kind in resources.items() if kind != "terraform_data"
            }
            if {
                target.address: target.resource_type for target in bundle.targets
            } != required or len(bundle.targets) != len(required):
                raise ContractError("DIAGNOSTIC_TARGET_COVERAGE")
            if any(kind == "aws_iam_service_linked_role" for kind in resources.values()):
                raise ContractError("OWNER_MANAGED_ROLE_CANNOT_ENTER_TERRAFORM_STATE")
            _, _, state_addresses = state_inventory(private_states[scope])
            if any(
                resources.get(item["address"]) != item["resource_type"] for item in state_addresses
            ):
                raise ContractError("DIAGNOSTIC_UNCLASSIFIED_STATE_RESOURCE")
            projection = _state_identity_projection(private_states[scope])
            expiry = projection.get("terraform_data.owner_expiry_gate", {}).get("input")
            if not isinstance(expiry, str):
                raise ContractError("DIAGNOSTIC_EXPIRY_SENTINEL_REQUIRED")
            resolved = resolve_post_execution_targets(
                bundle.targets,
                private_states[scope],
                rules,
                None,
                frozen_expiry=expiry,
            )
            for target in resolved:
                for probe in (target.presence, *(item.probe for item in target.assertions)):
                    if (
                        not 1 <= probe.maximum_pages <= DIAGNOSTIC_LIMITS.pages
                        or not 1 <= probe.maximum_items <= DIAGNOSTIC_LIMITS.items_per_query
                    ):
                        raise ContractError("DIAGNOSTIC_NATIVE_LIMIT_INVALID")
            targets_by_scope[scope] = resolved
            return passed()

        def expiry(scope: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            selected = _state_identity_projection(private_states[scope])
            value = selected.get("terraform_data.owner_expiry_gate", {}).get("input")
            if not isinstance(value, str):
                raise ContractError("DIAGNOSTIC_EXPIRY_UNCLASSIFIED")
            expired = parse_utc_timestamp(value, "observed expiry") <= self.clock.now()
            return (
                DiagnosticStatus.FAIL if expired else DiagnosticStatus.PASS,
                "EXPIRED_RECONCILIATION_REQUIRES_SEPARATE_REVIEW" if expired else "EXPIRY_CURRENT",
                {
                    "expired": expired,
                    "resource_expiry": value,
                    "renewal_authorized": False,
                    "testing_maximum_minutes": 1365,
                    "teardown_maximum_minutes": 60,
                    "total_from_plan_preparation_minutes": 1425,
                    "preparation_and_deployment_reduce_available_testing": True,
                },
            )

        for scope in ("bootstrap", "platform"):

            def check_expiry(scope: str = scope) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return expiry(scope)

            def collect_templates(
                scope: str = scope,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return target_templates(scope)

            checks.run(
                scope + "_expiry",
                check_expiry,
                dependencies=(scope + "_state",),
            )
            checks.run(
                scope + "_templates",
                collect_templates,
                dependencies=(scope + "_state",),
            )
            entries: list[InventoryEntry] = []
            if scope not in targets_by_scope:
                rules = (
                    self.configuration.bootstrap_rules
                    if scope == "bootstrap"
                    else self.configuration.platform_rules
                )
                for rule in rules:
                    if rule.resource_type != "terraform_data":
                        checks.run(
                            scope + "/" + rule.address,
                            passed,
                            dependencies=(scope + "_templates",),
                            remote=True,
                        )
            for target in targets_by_scope.get(scope, ()):

                def observe(
                    target: NativeTarget = target,
                    scope: str = scope,
                    entries: list[InventoryEntry] = entries,
                ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                    result, assertions = diagnose_native_target(
                        self.session,
                        target,
                        operation_id=request.operation_id,
                        observed_at=self.clock.now()
                        .replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        valid_until=(
                            self.clock.now().replace(microsecond=0) + timedelta(minutes=15)
                        )
                        .isoformat()
                        .replace("+00:00", "Z"),
                    )
                    if result is None:
                        status = (
                            DiagnosticStatus.FAIL
                            if any(item.get("status") == "FAIL" for item in assertions)
                            else DiagnosticStatus.INDETERMINATE
                        )
                        return (
                            status,
                            "NATIVE_ASSERTIONS_UNRESOLVED",
                            {
                                "address": target.address,
                                "resource_type": target.resource_type,
                                "assertions": assertions,
                            },
                        )
                    entry = result.entries[0]
                    entries.append(entry)
                    required_missing = scope == "platform" and target.address in {
                        'module.opensearch.aws_cloudwatch_log_group.this["application"]',
                        'module.opensearch.aws_cloudwatch_log_group.this["audit"]',
                        'module.opensearch.aws_cloudwatch_log_group.this["index_slow"]',
                        'module.opensearch.aws_cloudwatch_log_group.this["search_slow"]',
                        "module.opensearch.aws_opensearch_domain.this",
                    }
                    acceptable = (entry.presence == "ABSENT" and required_missing) or (
                        entry.presence == "PRESENT"
                        and entry.configuration is Outcome.PASS
                        and (
                            entry.ownership == "PROJECT_MANAGED"
                            or (
                                entry.ownership == "SOURCE_BOUND_DIAGNOSTIC_ONLY"
                                and target.address
                                == "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch"
                            )
                        )
                    )
                    return (
                        DiagnosticStatus.PASS if acceptable else DiagnosticStatus.INDETERMINATE,
                        "PRESENCE_CLASSIFIED"
                        if acceptable
                        else "NATIVE_SECURITY_OR_PRESENCE_UNRESOLVED",
                        {
                            "address": target.address,
                            "resource_type": target.resource_type,
                            "presence": entry.presence,
                            "configuration": entry.configuration.value,
                            "ownership": entry.ownership,
                            "assertions": assertions,
                        },
                    )

                checks.run(
                    scope + "/" + target.address,
                    observe,
                    dependencies=(scope + "_templates",),
                    remote=True,
                )
            if scope in targets_by_scope:
                inventories[scope] = InventoryResult(
                    OPERATIONAL_SCHEMA_VERSION,
                    request.operation_id,
                    "526338061652",
                    "ap-southeast-1",
                    tuple(entries),
                    (),
                    (),
                    started,
                    (self.clock.now().replace(microsecond=0) + timedelta(minutes=15))
                    .isoformat()
                    .replace("+00:00", "Z"),
                )

        def scans() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            bundle = diagnostic_scan_bundle(self.configuration.native_scans_json)
            if {scan.coverage for scan in bundle.scans} != diagnostic_discovery_coverage() or len(
                bundle.scans
            ) != len(diagnostic_discovery_coverage()):
                raise ContractError("DIAGNOSTIC_DISCOVERY_COVERAGE")
            return passed()

        checks.run("discovery_templates", scans)
        template_check = next(
            check for check in checks.checks if check.check_id == "discovery_templates"
        )
        if template_check.status is DiagnosticStatus.PASS:
            bundle = diagnostic_scan_bundle(self.configuration.native_scans_json)
            for scan in sorted(bundle.scans, key=lambda item: item.coverage):

                def discover(
                    scan: object = scan,
                ) -> tuple[
                    DiagnosticStatus,
                    str,
                    dict[str, object],
                ]:
                    from .aws_inventory import NativeScanSpec

                    scan_bundle = replace(bundle, scans=(cast(NativeScanSpec, scan),))
                    found = discover_diagnostic_scan(
                        self.session.provider,
                        self.session.client,
                        scan_bundle,
                    )
                    discovered.update(found)
                    if len(discovered) > DIAGNOSTIC_LIMITS.discovery_items:
                        raise ContractError("DIAGNOSTIC_DISCOVERY_TOTAL_LIMIT")
                    return (
                        DiagnosticStatus.PASS,
                        "SERVICE_ENUMERATION_COMPLETE",
                        {"project_resource_count": len(found)},
                    )

                checks.run(
                    "discovery/" + scan.coverage,
                    discover,
                    dependencies=("aws_identity", "discovery_templates"),
                    remote=True,
                )

        def orphan_reconciliation() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            expected_native = {
                native_identity_key(
                    target.presence.service,
                    target.presence.expected_native_identity,
                )
                for values in targets_by_scope.values()
                for target in values
            }
            orphans = discovered - expected_native
            return (
                DiagnosticStatus.FAIL if orphans else DiagnosticStatus.PASS,
                "UNEXPECTED_PROJECT_RESOURCES" if orphans else "NO_UNEXPECTED_PROJECT_RESOURCES",
                {
                    "orphan_count": len(orphans),
                    "service_counts": {
                        service: sum(1 for kind, _ in orphans if kind == service)
                        for service, _ in sorted(orphans)
                    },
                },
            )

        discovery_dependencies = tuple(
            check.check_id for check in checks.checks if check.check_id.startswith("discovery/")
        )
        checks.run(
            "orphan_reconciliation",
            orphan_reconciliation,
            dependencies=(
                "bootstrap_templates",
                "platform_templates",
                "discovery_templates",
                *discovery_dependencies,
            ),
        )

        def role() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            result = self.session.service_role()
            present = result.get("presence") == "PRESENT"
            return (
                DiagnosticStatus.PASS if present else DiagnosticStatus.FAIL,
                "OWNER_ROLE_VERIFIED"
                if present
                else "OWNER_ROLE_CREATION_REQUIRES_SEPARATE_APPROVAL",
                dict(result),
            )

        checks.run("owner_managed_service_role", role, dependencies=("aws_identity",), remote=True)
        checks.run(
            "caller_policy_dependencies",
            lambda: (
                DiagnosticStatus.PASS,
                "POLICY_DEPENDENCIES_READ",
                self.session.caller_authorization_structure(),
            ),
            dependencies=("aws_identity",),
            remote=True,
        )
        log_names = tuple(
            "/aws/OpenSearchService/domains/enterprise-ai-sandbox/" + suffix
            for suffix in ("application-logs", "audit-logs", "index-slow-logs", "search-slow-logs")
        )
        self.session.bind_authorization_targets(log_names, "enterprise-ai-sandbox")
        for action in (
            "logs:CreateLogGroup",
            "logs:TagResource",
            "logs:AssociateKmsKey",
            "logs:PutRetentionPolicy",
            "logs:PutResourcePolicy",
            "es:CreateDomain",
            "iam:CreateServiceLinkedRole",
        ):

            def simulation(action: str = action) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                result = self.session.simulate(action)
                return (
                    DiagnosticStatus.PASS if result["allowed"] else DiagnosticStatus.FAIL,
                    "SIMULATION_ONLY_NOT_LIVE_AUTHORIZATION",
                    result,
                )

            checks.run(
                "simulation/" + action,
                simulation,
                dependencies=("aws_identity",),
                remote=True,
            )
        kms_identities = frozenset(
            value
            for raw in private_states.values()
            for address, fields in _state_identity_projection(raw).items()
            if ".aws_kms_key." in address or address.startswith("aws_kms_key.")
            for field, value in fields.items()
            if field in {"id", "arn"} and isinstance(value, str)
        )
        for event in (
            "CreateLogGroup",
            "AssociateKmsKey",
            "PutResourcePolicy",
            "CreateDomain",
            "CreateServiceLinkedRole",
            "CreateGrant",
        ):

            def collect_events(
                event: str = event,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return (
                    DiagnosticStatus.PASS,
                    "HISTORICAL_WINDOW_COLLECTED_NOT_CURRENT_AUTHORIZATION",
                    self.session.cloudtrail_failures(log_names, (event,), kms_identities),
                )

            checks.run(
                "cloudtrail/" + event,
                collect_events,
                dependencies=(
                    "aws_identity",
                    "platform_state",
                    "bootstrap_state",
                ),
                remote=True,
            )

        def resolution() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            from .contracts import APPROVER
            from .lifecycle_models import DiagnosticFailureResolution

            reference = self.configuration.failure_resolution
            if (
                reference is None
                or reference.kind != "historical-failure-resolution"
                or reference.operation_id != request.operation_id
            ):
                raise ContractError("HISTORICAL_FAILURE_RESOLUTION_REQUIRED")
            approved = decode_diagnostic_record(
                reader.read(reference.path, reference.sha256, reference.byte_count),
                DiagnosticFailureResolution,
            )
            if (
                approved.operation_id != request.operation_id
                or approved.account_id != "526338061652"
                or approved.region != "ap-southeast-1"
                or approved.approver != APPROVER
                or approved.platform_state_sha256 != sha256_bytes(private_states["platform"])
                or approved.historical_diagnostic_sha256
                != HISTORICAL_DEPENDENT_ACTION_DIAGNOSTIC_SHA256
                or approved.treatment != "CURRENT_PREREQUISITES_RECHECKED_NO_RETRY_WAIVER"
                or not parse_utc_timestamp(
                    approved.approved_at,
                    "resolution approval",
                )
                <= self.clock.now()
                < parse_utc_timestamp(
                    approved.valid_until,
                    "resolution expiry",
                )
            ):
                raise ContractError("HISTORICAL_FAILURE_RESOLUTION_UNBOUND")
            return (
                DiagnosticStatus.PASS,
                "OWNER_RESOLUTION_BOUND_CURRENT_CHECKS_REQUIRED",
                {"retry_authorized": False},
            )

        resolution_dependencies = tuple(
            check.check_id
            for check in checks.checks
            if check.check_id.startswith(("simulation/", "cloudtrail/"))
        )
        checks.run(
            "authorization_resolution",
            resolution,
            dependencies=(
                "platform_state",
                "owner_managed_service_role",
                "caller_policy_dependencies",
                *resolution_dependencies,
            ),
        )
        for kind in ("account", "project_tag", "tag_status"):

            def collect_billing(
                kind: str = kind,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return (
                    DiagnosticStatus.PASS,
                    "BILLING_QUERY_COMPLETE_NOT_ATTRIBUTION",
                    self.session.billing(self.clock.now(), kind),
                )

            checks.run(
                "billing/" + kind,
                collect_billing,
                dependencies=("aws_identity",),
                remote=True,
            )
        self._cost_checks(checks, request, reader, private_states, inventories)

        def preservation() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if self.identities(request) != request.approved_identities:
                self.session.reject("DIAGNOSTIC_FINAL_REPOSITORY_DRIFT")
            reader.verify_all()
            retained = self.configuration.retained_pricing
            if retained is not None:
                reference, source = retained
                path = ensure_external_path(Path(source), self.external_root, self.repository_root)
                BoundEvidenceReader(path.parent, self.repository_root).read(
                    path.name,
                    reference.sha256,
                    reference.byte_count,
                )
            if sha256_file(
                Path(self.configuration.bootstrap_backend_path)
            ) != self.configuration.bootstrap_backend_sha256 or (
                (root / "inputs/diagnostic-request.json").read_bytes() != payload
            ):
                self.session.reject("DIAGNOSTIC_FINAL_INPUT_DRIFT")
            return passed()

        checks.run("final_preservation", preservation)
        for scope in private_states:

            def unchanged(scope: str = scope) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                raw = (
                    read_private_state(
                        bootstrap_state,
                        approved_path=bootstrap_state,
                        repository=self.repository_root,
                    )
                    if scope == "bootstrap"
                    else self.session.state_bytes()[0]
                )
                if sha256_bytes(raw) != sha256_bytes(private_states[scope]):
                    self.session.reject("DIAGNOSTIC_FINAL_STATE_DRIFT")
                return (
                    DiagnosticStatus.PASS,
                    "FINAL_STATE_BYTES_UNCHANGED",
                    {
                        "identity_basis": (
                            "LOCAL_STATE_BYTES" if scope == "bootstrap" else "S3_OBJECT_BYTES"
                        ),
                        "sha256": sha256_bytes(raw),
                    },
                )

            checks.run(
                scope + "_state_preserved",
                unchanged,
                dependencies=(scope + "_state",),
                remote=scope == "platform",
            )
        report = DiagnosticReport(
            DIAGNOSTIC_SCHEMA_VERSION,
            request.operation_id,
            "526338061652",
            "ap-southeast-1",
            started,
            self.clock.now().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            tuple(checks.checks),
            checks.exit_code,
            sha256_bytes(payload),
            self.runtime_identity[1],
            self.session.requests,
            self.session.billing_requests,
        )
        if len(canonical_json_bytes(report)) > 8 * 1024 * 1024:
            raise ContractError("DIAGNOSTIC_REPORT_SIZE_LIMIT")
        digest = write_canonical_json_atomic(
            root / "run-001/diagnostic.json",
            report,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        write_canonical_json_atomic(
            root / "run-001/diagnostic-identity.json",
            {
                "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
                "operation_id": request.operation_id,
                "report_sha256": digest,
                "request_sha256": sha256_bytes(payload),
                "runtime_sha256": self.runtime_identity[1],
                "exit_code": checks.exit_code,
                "recovery_eligibility": "NOT_ESTABLISHED",
                "mutation_started": False,
            },
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        return checks.exit_code, (
            "DIAGNOSTIC_PREREQUISITES_RESOLVED"
            if not checks.exit_code
            else "DIAGNOSTIC_PREREQUISITES_UNRESOLVED"
        )

    def _execute_prerequisite(self, request: DiagnosticRequest, payload: bytes) -> tuple[int, str]:
        """Closed prerequisite graph using the existing checks, SDK session and private writers."""
        from dataclasses import asdict
        from decimal import Decimal

        correction = getattr(self.session, "prerequisite_correction", False)
        operation = PREREQUISITE_CORRECTION_OPERATION if correction else PREREQUISITE_OPERATION_ID
        directory = PREREQUISITE_CORRECTION_DIRECTORY if correction else PREREQUISITE_DIRECTORY

        root = ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )
        if (
            request.operation_id != operation
            or root != self.external_root / "consolidated-remediation-001" / directory
            or request.environment != "sandbox"
            or request.target != "platform"
            or self.runtime_identity is not None
            or self._started
            or root.exists()
        ):
            raise ContractError("PREREQUISITE_EXACT_SCOPE_OR_UNUSED_DIRECTORY_REQUIRED")
        validate_diagnostic_profiles(self.configuration)
        expected = validate_diagnostic_state_bindings(request.expected_states)
        previous: dict[str, dict[str, object]] = {}
        for name in ("resolution.json", "resolution-identity.json"):
            path = (
                root.parent
                / (PREREQUISITE_DIRECTORY if correction else RESOLUTION_FOLLOWUP_DIRECTORY)
                / name
            )
            rows = [
                row
                for row in self.configuration.input_files
                if row[0] == "prerequisite/previous/" + name and row[1] == str(path)
            ]
            if len(rows) != 1:
                raise ContractError("PREREQUISITE_RETAINED_EVIDENCE_REQUIRED")
            validate_original_ancestors(path)
            raw = path.read_bytes()
            if sha256_bytes(raw) != rows[0][2]:
                raise ContractError("PREREQUISITE_RETAINED_EVIDENCE_CHANGED")
            value = decode_json_strict(raw, maximum_bytes=8 * 1024 * 1024)
            if not isinstance(value, dict) or (
                value.get("operation_id")
                != (PREREQUISITE_OPERATION_ID if correction else RESOLUTION_FOLLOWUP_OPERATION_ID)
                or value.get("schema_version")
                != (
                    "w5-004.prerequisite-resolution.v1"
                    if correction
                    else "w5-004.targeted-resolution.v2"
                )
            ):
                raise ContractError("PREREQUISITE_PREVIOUS_OPERATION_INVALID")
            previous[name] = value
        previous_hash = next(
            row[2]
            for row in self.configuration.input_files
            if row[0] == "prerequisite/previous/resolution.json"
        )
        if previous["resolution-identity.json"].get("report_sha256") != previous_hash:
            raise ContractError("PREREQUISITE_PREVIOUS_REPORT_IDENTITY")
        retained_checks = previous["resolution.json"].get("checks")
        if not isinstance(retained_checks, list):
            raise ContractError("PREREQUISITE_PREVIOUS_CHECKS_INVALID")
        unresolved: set[str] = set()
        for check in retained_checks:
            if not isinstance(check, dict):
                raise ContractError("PREREQUISITE_PREVIOUS_CHECKS_INVALID")
            details = dict(check.get("details", []))
            if "resources" in details:
                resources = decode_json_strict(details["resources"].encode())
                if not isinstance(resources, list):
                    raise ContractError("PREREQUISITE_PREVIOUS_TARGETS_INVALID")
                for row in resources:
                    if isinstance(row, dict) and row.get("relationship") == "INSUFFICIENT_EVIDENCE":
                        resource = row.get("resource")
                        if not isinstance(resource, str):
                            raise ContractError("PREREQUISITE_PREVIOUS_TARGETS_INVALID")
                        unresolved.add(resource)
        if not correction and unresolved != {
            *PREREQUISITE_ROLES,
            PREREQUISITE_POLICY,
            PREREQUISITE_ROUTES[1],
        }:
            raise ContractError("PREREQUISITE_EXACT_FOURTEEN_TARGETS_REQUIRED")
        declaration = None
        charging = None
        if correction:
            from .contracts import validate_recovery_scope_declaration
            from .lifecycle_io import decode_record
            from .lifecycle_models import CycleChargingEvidence, RecoveryScopeDeclaration

            input_values = {}
            for name in ("owner-decisions.json", "charging-basis.json", "input-identity.json"):
                entries = [
                    row for row in self.configuration.input_files if row[0] == "correction/" + name
                ]
                if len(entries) != 1:
                    raise ContractError("CORRECTION_INPUT_MISSING")
                path = Path(entries[0][1])
                if (
                    path != root.parent / "prerequisite-correction-inputs-001" / name
                    or sha256_file(path) != entries[0][2]
                ):
                    raise ContractError("CORRECTION_INPUT_IDENTITY")
                input_values[name] = load_json_strict(path)
            owner = input_values["owner-decisions.json"]
            if not isinstance(owner, dict):
                raise ContractError("CORRECTION_INPUT_SHAPE")
            declaration = decode_record(owner.get("scope"), RecoveryScopeDeclaration)
            validate_recovery_scope_declaration(declaration)
            if sha256_file(Path(declaration.approval_path)) != declaration.approval_sha256:
                raise ContractError("CORRECTION_APPROVAL_IDENTITY")
            identities = input_values["input-identity.json"]
            if not isinstance(identities, dict) or any(
                identities.get(name)
                != sha256_file(root.parent / "prerequisite-correction-inputs-001" / name)
                for name in ("owner-decisions.json", "charging-basis.json")
            ):
                raise ContractError("CORRECTION_INPUT_IDENTITY")
            charging = decode_record(input_values["charging-basis.json"], CycleChargingEvidence)
        if self.identities(request) != request.approved_identities:
            raise ContractError("PREREQUISITE_SOURCE_IDENTITY_CHANGED")
        verify_private_directory(root.parent)
        reserve_operation_directory(root, self.external_root, self.repository_root)
        self._started = True
        started = self.clock.now().isoformat()
        checks = DiagnosticChecks(self.clock, self.session)
        states: dict[str, bytes] = {}
        state_ids: dict[str, dict[str, object]] = {}
        projections: dict[str, dict[str, dict[str, object]]] = {}
        observations: dict[str, dict[str, object]] = {}
        bootstrap = Path(
            r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01\terraform-state\bootstrap.tfstate"
        )
        terms = PrerequisiteTerms()

        def result(
            detail: dict[str, object],
            *,
            known: bool = True,
            reason: str = "VERIFIED",
        ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            return (
                DiagnosticStatus.PASS if known else DiagnosticStatus.INDETERMINATE,
                reason,
                detail,
            )

        def caller() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            self.session.verify_identity()
            return result({"account": "526338061652", "caller": "MATCH"})

        checks.run("aws_identity", caller, remote=True)

        def state(scope: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            raw = (
                read_private_state(
                    bootstrap, approved_path=bootstrap, repository=self.repository_root
                )
                if scope == "bootstrap"
                else self.session.state_bytes()[0]
            )
            lineage, serial, _ = state_inventory(raw)
            if (lineage, serial, sha256_bytes(raw)) != expected[scope]:
                self.session.reject("DIAGNOSTIC_STATE_IDENTITY_CHANGED")
            states[scope] = raw
            projections[scope] = _state_identity_projection(raw)
            state_ids[scope] = {"lineage": lineage, "serial": serial, "sha256": sha256_bytes(raw)}
            return result(state_ids[scope])

        for scope in ("bootstrap", "platform"):

            def collect_state(
                scope: str = scope,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return state(scope)

            checks.run(
                scope + "_state",
                collect_state,
                dependencies=("aws_identity",),
                remote=scope == "platform",
            )

        def bind() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            specs = {
                "bootstrap_bucket": ("bootstrap", "aws_s3_bucket.terraform_state", "id"),
                "platform_bucket": ("platform", "module.storage.aws_s3_bucket.this", "id"),
                "dynamodb": ("bootstrap", "aws_dynamodb_table.terraform_lock", "id"),
                "ecr": ("platform", "module.ecr.aws_ecr_repository.this", "name"),
                "kms": ("platform", "module.kms.aws_kms_key.this", "arn"),
            }
            for name, (scope, address, field) in specs.items():
                value = projections[scope].get(address, {}).get(field)
                if not isinstance(value, str) or not value:
                    raise ContractError("PREREQUISITE_STATE_SELECTOR_UNAVAILABLE")
                self.session.prerequisite_targets[name] = value
            if not self.session.prerequisite_targets["kms"].startswith(
                "arn:aws:kms:ap-southeast-1:526338061652:key/"
            ):
                self.session.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
            return result({"selectors": "BOUND_TO_EXACT_STATE_ADDRESSES"})

        checks.run("state_selectors", bind, dependencies=("bootstrap_state", "platform_state"))

        def retention() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            validate_prerequisite_terms(terms, self.clock.now())
            if (state_ids["bootstrap"]["lineage"], state_ids["bootstrap"]["serial"]) != (
                terms.bootstrap_lineage,
                terms.bootstrap_serial,
            ):
                self.session.reject("DIAGNOSTIC_STATE_IDENTITY_CHANGED")
            expiry = (
                projections["bootstrap"].get("terraform_data.owner_expiry_gate", {}).get("input")
            )
            if not isinstance(expiry, str):
                raise ContractError("DIAGNOSTIC_EXPIRY_SENTINEL_REQUIRED")
            return result(
                {
                    "classification": terms.retention_classification,
                    "state_expiry": expiry,
                    "deadline": terms.retention_deadline,
                    "cleanup_owner": terms.cleanup_owner,
                    "renewal": "NOT_RUN",
                    "destruction_authorized": False,
                }
            )

        checks.run("bootstrap_retention", retention, dependencies=("bootstrap_state",))

        def envelope() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            validate_prerequisite_terms(terms, self.clock.now())
            possible = self.clock.now() + timedelta(seconds=terms.operating_seconds) < (
                parse_utc_timestamp(terms.retention_deadline, "retention")
            )
            return result(
                {
                    "T": None,
                    "fresh_expiry": "NOT_GENERATED",
                    "decision_b": "UNCHANGED",
                    "four_hour_window_can_still_fit": possible,
                    "teardown_authorized": False,
                },
                known=possible,
                reason="APPROVED_NOT_EXECUTED" if possible else "OPERATING_WINDOW_CANNOT_FIT",
            )

        checks.run("operating_envelope", envelope)

        def routes() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            response = self.session.call(
                "ec2", "describe_route_tables", {"RouteTableIds": list(PREREQUISITE_ROUTES)}
            )
            rows = response.get("RouteTables")
            if (
                not isinstance(rows, list)
                or len(rows) != 2
                or {row.get("RouteTableId") for row in rows if isinstance(row, dict)}
                != set(PREREQUISITE_ROUTES)
            ):
                raise ContractError("PREREQUISITE_ROUTE_RESPONSE_INVALID")
            candidate = next(row for row in rows if row["RouteTableId"] == PREREQUISITE_ROUTES[1])
            expected_vpc = projections["platform"]["module.network.aws_vpc.this"].get("id")
            if candidate.get("OwnerId") != "526338061652" or candidate.get("VpcId") != expected_vpc:
                return result(
                    {"resource": PREREQUISITE_ROUTES[1], "relationship": "MISMATCH"},
                    known=False,
                    reason="CURRENT_ROUTE_RELATIONSHIP_DIFFERS",
                )
            associations = candidate.get("Associations")
            if not isinstance(associations, list) or any(
                not isinstance(row, dict) for row in associations
            ):
                raise ContractError("PREREQUISITE_ROUTE_ASSOCIATIONS_INVALID")
            main = any(row.get("Main") is True for row in associations)
            private = {
                projections["platform"].get(f"module.network.aws_subnet.private[{i}]", {}).get("id")
                for i in (0, 1)
            }
            if len(private) != 2 or any(not isinstance(value, str) for value in private):
                raise ContractError("PREREQUISITE_SUBNET_IDENTITIES_UNAVAILABLE")
            if any("Main" in row and type(row["Main"]) is not bool for row in associations):
                raise ContractError("PREREQUISITE_ROUTE_ASSOCIATIONS_INVALID")
            conflict = any(row.get("SubnetId") in private for row in associations)
            return result(
                {
                    "resource": PREREQUISITE_ROUTES[1],
                    "ownership": "NOT_ASSERTED",
                    "relationship": "SHARED_VPC_DEFAULT" if main and not conflict else "UNRESOLVED",
                    "private_subnet_conflict": conflict,
                },
                known=main and not conflict,
                reason="EXACT_VPC_MAIN_RELATIONSHIP"
                if main and not conflict
                else "RELATIONSHIP_UNRESOLVED",
            )

        checks.run("relationship/route", routes, dependencies=("platform_state",), remote=True)

        def recovery_reference(name: str) -> tuple[str, ...]:
            matches = [
                "bound_" + scope + "_state" for scope, raw in states.items() if name.encode() in raw
            ]
            for relative in ("infra/environments/sandbox/main.tf", "infra/modules/iam/main.tf"):
                candidate = self.repository_root / relative
                if candidate.is_file() and name.encode() in candidate.read_bytes():
                    matches.append(relative)
            for logical, filename, digest in self.configuration.input_files:
                if logical == "diagnostic/platform.tfvars.json":
                    raw = Path(filename).read_bytes()
                    if sha256_bytes(raw) != digest:
                        self.session.reject("DIAGNOSTIC_FINAL_REPOSITORY_DRIFT")
                    if name.encode() in raw:
                        matches.append(logical)
            return tuple(matches)

        for role in PREREQUISITE_ROLES:

            def role_read(role: str = role) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                if correction:
                    if declaration is None:
                        raise ContractError("CORRECTION_DECLARATION_REQUIRED")
                    references = recovery_reference(role)
                    referenced = bool(references)
                    return result(
                        {
                            "resource": role,
                            "ownership": "NOT_ESTABLISHED",
                            "state_managed_identity_match": any(
                                value.get("name") == role
                                for scope in projections.values()
                                for value in scope.values()
                            ),
                            "relationship": "OBSERVED_POTENTIAL_DEPENDENCY"
                            if referenced
                            else "OUTSIDE_RECOVERY_OPERATION_BY_SCOPE",
                            "declaration_sha256": declaration.approval_sha256,
                            "reference_sources": references,
                            "account_wide_nonrelationship_certified": False,
                        },
                        known=not referenced,
                        reason="OBSERVED_REFERENCE_REQUIRES_REVIEW"
                        if referenced
                        else "SCOPED_OWNER_INTENT_AND_BOUND_STATE",
                    )
                row = self.session.call("iam", "get_role", {"RoleName": role}).get("Role")
                if (
                    not isinstance(row, dict)
                    or row.get("RoleName") != role
                    or not isinstance(row.get("Arn"), str)
                ):
                    raise ContractError("PREREQUISITE_ROLE_RESPONSE_INVALID")
                arn = cast(str, row["Arn"])
                if not arn.startswith("arn:aws:iam::526338061652:role/"):
                    self.session.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
                direct = any(
                    value.get("arn") == arn
                    for scope in projections.values()
                    for value in scope.values()
                )
                return result(
                    {
                        "resource": role,
                        "ownership": "NOT_ESTABLISHED",
                        "state_managed_identity_match": direct,
                        "relationship": "EXACT_STATE_IDENTITY"
                        if direct
                        else "INSUFFICIENT_EVIDENCE",
                        "minimum_missing_evidence": "OWNER_WORKLOAD_RELATIONSHIP_RECORD",
                        "unknown_is_orphan": False,
                    },
                    known=direct,
                    reason="EXACT_STATE_IDENTITY"
                    if direct
                    else "OWNER_RELATIONSHIP_RECORD_UNAVAILABLE",
                )

            checks.run(
                "relationship/role/" + role,
                role_read,
                dependencies=("state_selectors",),
                remote=not correction,
            )

        for usage in ("PermissionsPolicy", "PermissionsBoundary"):

            def policy_read(usage: str = usage) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                rows, complete = self.session.prerequisite_policy_entities(usage)
                names = [row["name"] for row in rows if row["entity_type"] == "Role"]
                safe = [name for name in names if name in PREREQUISITE_ROLES]
                relevant = [
                    row
                    for row in rows
                    if (row["entity_type"] == "User" and row["name"] == "finopsinfra")
                    or recovery_reference(row["name"])
                ]
                if correction:
                    rows = [
                        dict(
                            row,
                            relationship=(
                                "OBSERVED_POTENTIAL_DEPENDENCY"
                                if row in relevant
                                else "ATTACHMENT_OBSERVED_OUTSIDE_DECLARED_OPERATION"
                            ),
                            ownership="NOT_ESTABLISHED",
                        )
                        for row in rows
                    ]
                return result(
                    {
                        "resource": PREREQUISITE_POLICY,
                        "usage": usage,
                        "attached_retained_roles": safe,
                        "entities": rows,
                        "observed_potential_dependencies": relevant,
                        "other_role_count": len(names) - len(safe),
                        "enumeration_complete": complete,
                        "ownership": "NOT_ESTABLISHED",
                        "relationship": "OBSERVED_POTENTIAL_DEPENDENCY"
                        if relevant
                        else "OUTSIDE_RECOVERY_OPERATION_BY_SCOPE"
                        if declaration is not None
                        else "OWNER_RELATIONSHIP_EVIDENCE_REQUIRED",
                    },
                    known=correction and declaration is not None and complete and not relevant,
                    reason="SCOPED_RELATIONSHIP_CLASSIFICATION"
                    if complete
                    else "RELATIONSHIP_EVIDENCE_INCOMPLETE",
                )

            checks.run(
                "relationship/policy/" + usage,
                policy_read,
                dependencies=("state_selectors",),
                remote=True,
            )

        def user() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            row = self.session.call("iam", "get_user", {"UserName": "finopsinfra"}).get("User")
            if (
                not isinstance(row, dict)
                or row.get("Arn") != "arn:aws:iam::526338061652:user/finopsinfra"
            ):
                self.session.reject("DIAGNOSTIC_AWS_IDENTITY_MISMATCH")
            return result({"caller": "MATCH", "boundary_present": "PermissionsBoundary" in row})

        checks.run("authorization/caller", user, dependencies=("aws_identity",), remote=True)

        def context() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            from .aws_live import safe_context_names

            response = self.session.call(
                "iam",
                "get_context_keys_for_principal_policy",
                {"PolicySourceArn": "arn:aws:iam::526338061652:user/finopsinfra"},
            )
            keys = response.get("ContextKeyNames")
            if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
                raise ContractError("PREREQUISITE_CONTEXT_RESPONSE_INVALID")
            values = {
                "aws:RequestedRegion": ("string", "ap-southeast-1"),
                "aws:PrincipalArn": ("string", "arn:aws:iam::526338061652:user/finopsinfra"),
                "aws:PrincipalAccount": ("string", "526338061652"),
                "aws:username": ("string", "finopsinfra"),
                "aws:CurrentTime": ("date", self.clock.now().isoformat()),
                "aws:SecureTransport": ("boolean", "true"),
            }
            self.session.prerequisite_context = [
                {
                    "ContextKeyName": key,
                    "ContextKeyType": values[key][0],
                    "ContextKeyValues": [values[key][1]],
                }
                for key in sorted(set(keys))
                if key in values
            ]
            return result(
                {
                    "required_context_count": len(set(keys)),
                    "supplied_context_count": len(self.session.prerequisite_context),
                    "required_context_keys": safe_context_names(keys),
                    "unmapped_context_keys": safe_context_names(sorted(set(keys) - set(values))),
                    "context_types_from_aws": "NOT_PROVIDED_BY_API",
                    "future_expiry_context": "NOT_FABRICATED",
                }
            )

        checks.run(
            "authorization/context", context, dependencies=("authorization/caller",), remote=True
        )
        simulation_results: dict[str, bool | None] = {}
        for action in PREREQUISITE_LOG_ACTIONS:

            def simulate(action: str = action) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                arns = [
                    "arn:aws:logs:ap-southeast-1:526338061652:log-group:"
                    + name
                    + ("" if action == "logs:TagResource" else ":*")
                    for name in PREREQUISITE_LOG_NAMES
                ]
                args: dict[str, object] = {
                    "PolicySourceArn": "arn:aws:iam::526338061652:user/finopsinfra",
                    "ActionNames": [action],
                    "ResourceArns": arns,
                    "MaxItems": 100,
                }
                if self.session.prerequisite_context:
                    args["ContextEntries"] = self.session.prerequisite_context
                rows, complete = self.session.prerequisite_enumerate(
                    "iam", "simulate_principal_policy", args, "EvaluationResults"
                )
                from .aws_live import normalize_simulation_results

                normalized = normalize_simulation_results(rows, action, arns, complete=complete)
                simulation_results[action] = cast(bool | None, normalized["allowed"])
                return result(
                    normalized,
                    known=normalized["coverage_complete"] is True,
                    reason="SIMULATION_RESULT_NOT_LIVE_AUTHORIZATION"
                    if normalized["coverage_complete"]
                    else "SIMULATION_COVERAGE_INCOMPLETE",
                )

            checks.run(
                "authorization/" + action,
                simulate,
                dependencies=("authorization/context",),
                remote=True,
            )

        def auth_summary() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            tag_values = [
                simulation_results.get(action)
                for action in ("logs:TagResource", "logs:TagLogGroup")
            ]
            tagging = (
                True
                if True in tag_values
                else False
                if all(v is False for v in tag_values)
                else None
            )
            other_values = [
                simulation_results.get(action)
                for action in (
                    "logs:CreateLogGroup",
                    "logs:AssociateKmsKey",
                    "logs:PutRetentionPolicy",
                )
            ]
            other = (
                False
                if False in other_values
                else True
                if all(v is True for v in other_values)
                else None
            )
            return result(
                {
                    "tagging_either_permission": tagging,
                    "other_actions_allowed": other,
                    "historical_denials": "PRESERVED_UNRESOLVED",
                    "permission_grant": "NOT_PROPOSED",
                    "live_authorization_guarantee": False,
                },
                known=tagging is True and other is True,
                reason="CURRENT_SIMULATION_ONLY"
                if tagging and other
                else "CURRENT_AUTHORIZATION_UNRESOLVED",
            )

        checks.run("authorization/summary", auth_summary)

        def kms() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            key = self.session.prerequisite_targets["kms"]
            metadata = self.session.call("kms", "describe_key", {"KeyId": key}).get("KeyMetadata")
            response = self.session.call(
                "kms", "get_key_policy", {"KeyId": key, "PolicyName": "default"}
            )
            policy = response.get("Policy")
            if not isinstance(metadata, dict):
                raise ContractError("PREREQUISITE_KMS_RESPONSE_INVALID")
            if metadata.get("Arn") != key or metadata.get("AWSAccountId") != "526338061652":
                self.session.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
            native = None
            native_status = "MISSING"
            if isinstance(policy, str):
                try:
                    native = decode_json_strict(policy.encode())
                    native_status = (
                        "AVAILABLE"
                        if isinstance(native, dict)
                        and isinstance(native.get("Statement"), (list, dict))
                        else "MALFORMED"
                    )
                except ContractError:
                    native_status = "MALFORMED"
            comparison: dict[str, object] = {}
            expected_status = "AVAILABLE"
            try:
                expected_policy = expected_platform_kms_policy(
                    states["platform"], cast(str, state_ids["platform"]["sha256"]), key
                )
                if native_status == "AVAILABLE":
                    comparison = private_policy_comparison(expected_policy, native)
            except ContractError as exc:
                expected_status = (
                    str(exc)
                    if str(exc).startswith("KMS_EXPECTED_")
                    else "KMS_EXPECTED_POLICY_MALFORMED"
                )
            matches = comparison.get("equal")
            ready = (
                metadata.get("KeyState") == "Enabled"
                and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
                and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
            )
            structural = _has_exact_opensearch_log_kms_statement(native)
            return result(
                {
                    "resource": "module.kms.aws_kms_key.this",
                    "metadata_ready": ready,
                    "policy_matches_bound_state": matches,
                    "expected_policy_status": expected_status,
                    "native_policy_status": native_status,
                    "comparison": comparison,
                    "exact_logs_statement": structural,
                    "live_service_use_guarantee": False,
                },
                known=bool(ready and matches and structural),
                reason="EXACT_KMS_STRUCTURE_VERIFIED"
                if ready and matches and structural
                else "KMS_SERVICE_AUTHORIZATION_UNRESOLVED",
            )

        checks.run("authorization/kms", kms, dependencies=("state_selectors",), remote=True)

        for scope in ("bootstrap", "platform"):
            for kind in ("versions", "uploads"):

                def storage(
                    scope: str = scope, kind: str = kind
                ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                    bucket = self.session.prerequisite_targets[scope + "_bucket"]
                    method = (
                        "list_object_versions" if kind == "versions" else "list_multipart_uploads"
                    )
                    args = {
                        "Bucket": bucket,
                        "ExpectedBucketOwner": "526338061652",
                        "MaxKeys" if kind == "versions" else "MaxUploads": 1000,
                    }
                    rows, complete = self.session.prerequisite_enumerate(
                        "s3", method, args, "Versions" if kind == "versions" else "Uploads"
                    )
                    sizes: list[object] = []
                    if kind == "uploads":
                        if len(rows) > 2 or not complete:
                            return result(
                                {"scope": scope, "upload_count": len(rows), "bytes": None},
                                known=False,
                                reason="MULTIPART_COLLECTION_LIMIT",
                            )
                        for row in rows:
                            key, upload = row.get("Key"), row.get("UploadId")
                            if not isinstance(key, str) or not isinstance(upload, str):
                                raise ContractError("PREREQUISITE_UPLOAD_IDENTITY_INVALID")
                            self.session.prerequisite_uploads.add((bucket, key, upload))
                            parts, done = self.session.prerequisite_enumerate(
                                "s3",
                                "list_parts",
                                {
                                    "Bucket": bucket,
                                    "ExpectedBucketOwner": "526338061652",
                                    "Key": key,
                                    "UploadId": upload,
                                    "MaxParts": 1000,
                                },
                                "Parts",
                            )
                            complete = complete and done
                            sizes.extend(part.get("Size") for part in parts)
                    else:
                        sizes.extend(row.get("Size") for row in rows)
                    if any(type(size) is not int or size < 0 for size in sizes):
                        raise ContractError("PREREQUISITE_STORAGE_SIZE_INVALID")
                    detail = {
                        "scope": scope,
                        "kind": kind,
                        "count": len(rows),
                        "bytes": sum(cast(list[int], sizes)),
                        "complete": complete,
                        "historical_lifetime": "UNKNOWN",
                        "keys_retained": False,
                    }
                    observations[scope + "/" + kind] = detail
                    return result(
                        detail, known=complete, reason="CURRENT_QUANTITY_NOT_HISTORICAL_SPENDING"
                    )

                checks.run(
                    "storage/" + scope + "/" + kind,
                    storage,
                    dependencies=("state_selectors",),
                    remote=True,
                )

        def images() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            rows, complete = self.session.prerequisite_enumerate(
                "ecr",
                "describe_images",
                {
                    "registryId": "526338061652",
                    "repositoryName": self.session.prerequisite_targets["ecr"],
                    "maxResults": 1000,
                },
                "imageDetails",
            )
            sizes = [row.get("imageSizeInBytes") for row in rows]
            if any(type(size) is not int or size < 0 for size in sizes):
                raise ContractError("PREREQUISITE_IMAGE_SIZE_INVALID")
            detail = {
                "resource": "module.ecr.aws_ecr_repository.this",
                "images": len(rows),
                "reported_image_bytes_sum": sum(cast(list[int], sizes)),
                "layer_deduplication": "NOT_SUBTRACTED",
                "historical_lifetime": "UNKNOWN",
                "complete": complete,
            }
            observations["ecr"] = detail
            return result(detail, known=complete)

        checks.run("storage/ecr", images, dependencies=("state_selectors",), remote=True)

        def table() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            value = self.session.call(
                "dynamodb",
                "describe_table",
                {"TableName": self.session.prerequisite_targets["dynamodb"]},
            ).get("Table")
            if (
                not isinstance(value, dict)
                or value.get("TableName") != self.session.prerequisite_targets["dynamodb"]
            ):
                raise ContractError("PREREQUISITE_TABLE_IDENTITY_INVALID")
            size = value.get("TableSizeBytes")
            if type(size) is not int or size < 0:
                raise ContractError("PREREQUISITE_TABLE_SIZE_INVALID")
            return result(
                {
                    "resource": "aws_dynamodb_table.terraform_lock",
                    "reported_bytes": size,
                    "measurement_freshness": "SERVICE_ESTIMATE_NOT_CURRENT_BILL",
                }
            )

        checks.run("storage/lock_table", table, dependencies=("state_selectors",), remote=True)

        def billing() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            rows, complete = self.session.prerequisite_enumerate(
                "ce",
                "get_cost_and_usage",
                {
                    "TimePeriod": {
                        "Start": RESOLUTION_BILLING_START,
                        "End": RESOLUTION_BILLING_END,
                    },
                    "Granularity": "DAILY",
                    "Metrics": ["UnblendedCost"],
                    "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["526338061652"]}},
                    "GroupBy": [
                        {"Type": "DIMENSION", "Key": "SERVICE"},
                        {"Type": "DIMENSION", "Key": "RECORD_TYPE"},
                    ],
                },
                "ResultsByTime",
            )
            safe_rows = []
            intervals: set[str] = set()
            seen_groups: set[tuple[str, str, str]] = set()
            gross, offsets = Decimal("0"), Decimal("0")
            for day in rows:
                interval = day.get("TimePeriod")
                groups = day.get("Groups")
                if not isinstance(interval, dict) or not isinstance(groups, list):
                    raise ContractError("PREREQUISITE_BILLING_STRUCTURE")
                start, end = interval.get("Start"), interval.get("End")
                if (
                    not isinstance(start, str)
                    or not "2026-09-08" <= start < "2026-09-13"
                    or end != (datetime.fromisoformat(start) + timedelta(days=1)).date().isoformat()
                    or type(day.get("Estimated")) is not bool
                ):
                    raise ContractError("PREREQUISITE_BILLING_INTERVAL_INVALID")
                intervals.add(start)
                for group in groups:
                    if not isinstance(group, dict):
                        raise ContractError("PREREQUISITE_BILLING_STRUCTURE")
                    keys = group.get("Keys")
                    metric = group.get("Metrics", {}).get("UnblendedCost", {})
                    amount = Decimal(metric.get("Amount", "NaN"))
                    if (
                        not isinstance(keys, list)
                        or len(keys) != 2
                        or any(not isinstance(key, str) or not key for key in keys)
                        or not amount.is_finite()
                        or metric.get("Unit") != "USD"
                    ):
                        raise ContractError("PREREQUISITE_BILLING_STRUCTURE")
                    identity = (start, keys[0], keys[1])
                    if identity in seen_groups:
                        raise ContractError("PREREQUISITE_BILLING_DUPLICATE_GROUP")
                    seen_groups.add(identity)
                    if amount >= 0:
                        gross += amount
                    else:
                        offsets += amount
                    safe_rows.append(
                        {
                            "start": interval.get("Start"),
                            "end": interval.get("End"),
                            "service": keys[0],
                            "record_type": keys[1],
                            "usd": str(amount),
                            "estimated": day.get("Estimated") is True,
                        }
                    )
            detail = {
                "scope": "ACCOUNT_NOT_PROJECT_ACTUAL",
                "rows": safe_rows,
                "complete": complete,
                "reported_account_positive_usd": str(gross),
                "reported_account_negative_usd": str(offsets),
                "reported_account_net_usd": str(gross + offsets),
                "gross_is_proven_upper_bound": False,
                "purpose": "GROSS_AND_OFFSETS_SEPARATED_NOT_CURRENT_HEADROOM",
                "later_exposure_uncovered_from": "2026-09-13T00:00:00Z",
            }
            observations["billing"] = detail
            return result(
                detail, known=complete and len(intervals) == 5, reason="ACCOUNT_SCOPE_ONLY"
            )

        checks.run(
            "billing/gross_and_offsets", billing, dependencies=("aws_identity",), remote=True
        )
        checks.run(
            "lifecycle_bound",
            lambda: result(
                {
                    "total_cycle_ceiling_usd": "30.00",
                    "monthly_treatment": "INFORMATIONAL_W5_CYCLE_A_ONLY",
                    "planning_allocations_usd": ["15", "10", "2", "3"],
                    "allocations_are_bounds": False,
                    "attributable_incurred_usd": None,
                    "supported_total_bound_usd": None,
                    "available_headroom_usd": None,
                    "missing": [
                        "LATER_EXPOSURE_AND_BILLING_LAG_BOUND",
                        "VERIFIED_CHARGING_MINIMA",
                        "FINITE_RETAINED_TAIL_DISPOSITION",
                        "HISTORICAL_STORAGE_LIFETIMES",
                    ],
                    "diagnostic_requests_this_attempt": self.session.requests,
                    "observed_quantity_scopes": sorted(observations),
                    "nonoverlapping_ledger": [
                        {
                            "category": category,
                            "start": start,
                            "end": end,
                            "upper_bound_usd": None,
                            "scope": scope,
                            "limitation": limitation,
                        }
                        for category, start, end, scope, limitation in (
                            (
                                "HISTORICAL_ACCOUNT_RESERVATION",
                                "2026-09-08T00:00:00Z",
                                "2026-09-13T00:00:00Z",
                                "ACCOUNT_NOT_PROJECT_ACTUAL",
                                "ESTIMATED_GROSS_AND_OFFSETS_NOT_A_LAG_ADJUSTED_BOUND",
                            ),
                            (
                                "POST_CUTOFF_FIXED",
                                "2026-09-13T00:00:00Z",
                                "2026-09-14T12:00:00Z",
                                "W5_CYCLE_A",
                                "COVERS_FIXED_EXPOSURE_THROUGH_RETENTION_NOT_ADDITIONAL_TEST_HOURS",
                            ),
                            (
                                "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
                                "2026-09-13T00:00:00Z",
                                "2026-09-14T12:00:00Z",
                                "W5_CYCLE_A",
                                "INCLUDES_DIAGNOSTICS_AND_TEARDOWN_VARIABLE_CHARGES_ONCE",
                            ),
                            (
                                "RETAINED_TAIL",
                                "2026-09-14T12:00:00Z",
                                None,
                                "W5_CYCLE_A",
                                "TERMINAL_ARCHIVE_AND_KMS_DISPOSITION_UNRESOLVED",
                            ),
                        )
                    ],
                },
                known=False,
                reason="SUPPORTED_TOTAL_CYCLE_BOUND_UNAVAILABLE",
            ),
        )
        self.session.preservation_phase = True
        for scope in ("bootstrap", "platform"):

            def preserve_state(
                scope: str = scope,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                raw = (
                    read_private_state(
                        bootstrap, approved_path=bootstrap, repository=self.repository_root
                    )
                    if scope == "bootstrap"
                    else self.session.state_bytes()[0]
                )
                if raw != states[scope]:
                    self.session.reject("DIAGNOSTIC_FINAL_STATE_DRIFT")
                return result({"sha256": sha256_bytes(raw)})

            checks.run(
                scope + "_state_preserved",
                preserve_state,
                dependencies=(scope + "_state",),
                remote=scope == "platform",
            )
        checks.run("final_caller", caller, dependencies=("aws_identity",), remote=True)

        def preserve_source() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if self.identities(request) != request.approved_identities:
                self.session.reject("DIAGNOSTIC_FINAL_REPOSITORY_DRIFT")
            return result({"repository_and_inputs": "UNCHANGED"})

        if correction:
            from .cost import calculate_cycle_charges
            from .lifecycle_io import DiagnosticEvidenceReader

            checks.checks = [row for row in checks.checks if row.check_id != "lifecycle_bound"]

            def cost_bound() -> tuple[DiagnosticStatus, str, dict[str, object]]:
                calculated = calculate_cycle_charges(
                    charging,
                    reader=DiagnosticEvidenceReader(
                        self.configuration.evidence_sources,
                        self.external_root,
                        self.repository_root,
                    ),
                    now=self.clock.now(),
                    final_requests=self.session.requests,
                )
                return (
                    DiagnosticStatus.PASS
                    if calculated["status"] == "PASS"
                    else DiagnosticStatus.FAIL
                    if calculated["status"] == "FAIL"
                    else DiagnosticStatus.INDETERMINATE,
                    "CALCULATED_LIFECYCLE_BOUND",
                    calculated,
                )

            checks.run("lifecycle_bound", cost_bound)
        checks.run("final_preservation", preserve_source)
        report = {
            "schema_version": "w5-004.prerequisite-resolution.v2"
            if correction
            else "w5-004.prerequisite-resolution.v1",
            "operation_id": operation,
            "previous_report_sha256": previous_hash,
            "account_id": "526338061652",
            "region": "ap-southeast-1",
            "started_at": started,
            "completed_at": self.clock.now().isoformat(),
            "terms": asdict(terms),
            "states": state_ids,
            "checks": tuple(checks.checks),
            "limits": self.session.limits,
            "aws_requests": self.session.requests,
            "billing_requests": self.session.billing_requests,
            "enumeration_pages": tuple(sorted(self.session.enumeration_pages.values())),
            "requests_by_api": tuple(sorted(self.session.request_counts.items())),
            "exit_code": checks.exit_code,
            "recovery_eligibility": "NOT_ESTABLISHED",
            "mutation_started": False,
            "terraform": "NOT_RUN",
            "pricing": "NOT_RUN",
        }
        if len(canonical_json_bytes(report)) > 8 * 1024 * 1024:
            raise ContractError("RESOLUTION_REPORT_SIZE_LIMIT")
        digest = write_canonical_json_atomic(
            root / "resolution.json",
            report,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        write_canonical_json_atomic(
            root / "resolution-identity.json",
            {
                "schema_version": report["schema_version"],
                "operation_id": operation,
                "report_sha256": digest,
                "request_sha256": sha256_bytes(payload),
                "runtime_sha256": sha256_bytes(canonical_json_bytes(self.configuration)),
                "source": request.approved_identities,
                "inputs": self.configuration.input_files,
                "states": state_ids,
                "output_root": str(root),
                "exit_code": checks.exit_code,
                "recovery_eligibility": "NOT_ESTABLISHED",
            },
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        return (
            checks.exit_code,
            "PREREQUISITES_UNRESOLVED" if checks.exit_code else "PREREQUISITES_COMPLETE",
        )

    def _execute_resolution(self, request: DiagnosticRequest, payload: bytes) -> tuple[int, str]:
        """Targeted graph on the same coordinator, session, identity and private adapters."""
        from decimal import Decimal

        from .lifecycle_io import approved_lifecycle_exception, load_lifecycle_config

        root = ensure_external_path(
            Path(request.operation_root), self.external_root, self.repository_root
        )
        followup = self.session.resolution_followup
        operation_id = RESOLUTION_FOLLOWUP_OPERATION_ID if followup else RESOLUTION_OPERATION_ID
        directory = RESOLUTION_FOLLOWUP_DIRECTORY if followup else RESOLUTION_DIRECTORY
        if (
            request.operation_id != operation_id
            or root != self.external_root / "consolidated-remediation-001" / directory
            or request.environment != "sandbox"
            or request.target != "platform"
            or self.runtime_identity is not None
            or self._started
        ):
            raise ContractError("RESOLUTION_EXACT_SCOPE_REQUIRED")
        if root.exists():
            raise ContractError("RESOLUTION_DIRECTORY_ALREADY_USED")
        validate_diagnostic_profiles(self.configuration)
        bundle = decode_operational_record(
            self.configuration.native_targets_json.encode(), NativeTargetBundle
        )
        endpoints = tuple(
            target
            for target in bundle.targets
            if target.address.startswith("module.network.aws_vpc_endpoint.interface[")
        )
        if len(endpoints) != 8:
            raise ContractError("RESOLUTION_ENDPOINT_PROFILE_INVALID")
        expected = validate_diagnostic_state_bindings(request.expected_states)
        config = load_lifecycle_config(self.repository_root / "configs/lifecycle/w5-004.json")
        if (
            cast(dict[str, object], config["cost"]).get("lifecycle_exception")
            != approved_lifecycle_exception()
        ):
            raise ContractError("RESOLUTION_CYCLE_POLICY_CHANGED")
        retained_binding = (
            "resolution/completed-diagnostic.json",
            str(
                self.external_root
                / "consolidated-remediation-001"
                / "codex-diagnostic-001/attempt-002/run-001/diagnostic.json"
            ),
            RESOLUTION_EVIDENCE_SHA256,
        )
        if retained_binding not in self.configuration.input_files:
            raise ContractError("RESOLUTION_RETAINED_EVIDENCE_BINDING_REQUIRED")
        if followup:
            retained_bytes = []
            for name, digest in (
                ("resolution.json", RESOLUTION_FOLLOWUP_EVIDENCE_SHA256),
                ("resolution-identity.json", RESOLUTION_FOLLOWUP_IDENTITY_SHA256),
            ):
                path = root.parent / RESOLUTION_DIRECTORY / name
                if (
                    "resolution/previous/" + name,
                    str(path),
                    digest,
                ) not in self.configuration.input_files:
                    raise ContractError("RESOLUTION_RETAINED_EVIDENCE_BINDING_REQUIRED")
                validate_original_ancestors(path)
                raw = path.read_bytes()
                if sha256_bytes(raw) != digest:
                    raise ContractError("RESOLUTION_RETAINED_EVIDENCE_CHANGED")
                retained_bytes.append(raw)
            self.session.bind_followup_evidence(*retained_bytes)
        if self.identities(request) != request.approved_identities:
            raise ContractError("RESOLUTION_SOURCE_IDENTITY_CHANGED")
        verify_private_directory(root.parent)
        reserve_operation_directory(root, self.external_root, self.repository_root)
        self._started = True
        started = self.clock.now().isoformat().replace("+00:00", "Z")
        checks = DiagnosticChecks(self.clock, self.session)
        states: dict[str, bytes] = {}
        identities: dict[str, dict[str, object]] = {}
        bootstrap_state = Path(
            r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01\terraform-state\bootstrap.tfstate"
        )

        def passed(
            details: dict[str, object] | None = None,
        ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            return DiagnosticStatus.PASS, "VERIFIED", details or {}

        def identity() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            self.session.verify_identity()
            return passed()

        checks.run("aws_identity", identity, remote=True)

        def state(scope: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            raw = (
                read_private_state(
                    bootstrap_state, approved_path=bootstrap_state, repository=self.repository_root
                )
                if scope == "bootstrap"
                else self.session.state_bytes()[0]
            )
            lineage, serial, addresses = state_inventory(raw)
            if (lineage, serial, sha256_bytes(raw)) != expected[scope]:
                self.session.reject("DIAGNOSTIC_STATE_IDENTITY_CHANGED")
            states[scope] = raw
            identities[scope] = {"lineage": lineage, "serial": serial, "sha256": sha256_bytes(raw)}
            rules = (
                self.configuration.bootstrap_rules
                if scope == "bootstrap"
                else self.configuration.platform_rules
            )
            governed = {rule.address: rule.resource_type for rule in rules}
            if any(governed.get(row["address"]) != row["resource_type"] for row in addresses):
                self.session.reject("DIAGNOSTIC_STATE_IDENTITY_CHANGED")
            return passed(identities[scope])

        for scope in ("bootstrap", "platform"):

            def collect_state(
                scope: str = scope,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return state(scope)

            checks.run(
                scope + "_state",
                collect_state,
                dependencies=("aws_identity",),
                remote=scope == "platform",
            )

        def expiry() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            value = (
                _state_identity_projection(states["platform"])
                .get("terraform_data.owner_expiry_gate", {})
                .get("input")
            )
            if not isinstance(value, str):
                raise ContractError("DIAGNOSTIC_EXPIRY_SENTINEL_REQUIRED")
            expired = parse_utc_timestamp(value, "state expiry") <= self.clock.now()
            return (
                DiagnosticStatus.FAIL if expired else DiagnosticStatus.PASS,
                "EXPIRED_REQUIRES_SEPARATE_SANDBOX_RECONCILIATION" if expired else "UNEXPIRED",
                {
                    "scope": "platform",
                    "state_sentinel_expiry": value,
                    "native_tag_reverification": "NOT_RUN",
                    "bootstrap_redeployment": "NOT_AUTHORIZED",
                    "renewal_performed": False,
                },
            )

        checks.run("sandbox_expiry", expiry, dependencies=("platform_state",))
        if followup:

            def bootstrap_expiry() -> tuple[DiagnosticStatus, str, dict[str, object]]:
                value = (
                    _state_identity_projection(states["bootstrap"])
                    .get("terraform_data.owner_expiry_gate", {})
                    .get("input")
                )
                if not isinstance(value, str):
                    raise ContractError("DIAGNOSTIC_EXPIRY_SENTINEL_REQUIRED")
                expired = parse_utc_timestamp(value, "bootstrap expiry") <= self.clock.now()
                return (
                    DiagnosticStatus.FAIL if expired else DiagnosticStatus.PASS,
                    "BOOTSTRAP_RETENTION_DECISION_REQUIRED" if expired else "UNEXPIRED",
                    {
                        "state_sentinel_expiry": value,
                        "infrastructure_changed": False,
                        "retention_accepted": False,
                        "full_diagnostic_expiry_gate": "FAIL" if expired else "PASS",
                        "operational_tag_gate": "EXACT_MATCH_AND_PARSEABLE_NOT_FUTURE_TIMESTAMP",
                        "fresh_cost_inventory_still_required": True,
                    },
                )

            checks.run(
                "bootstrap_expiry_disposition", bootstrap_expiry, dependencies=("bootstrap_state",)
            )
        native_endpoints: dict[str, dict[str, object]] = {}

        def endpoint_read() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            projection = _state_identity_projection(states["platform"])
            values = [projection.get(target.address, {}).get("id") for target in endpoints]
            if (
                any(not isinstance(value, str) or not value.startswith("vpce-") for value in values)
                or len(set(values)) != 8
            ):
                self.session.reject("RESOLUTION_ENDPOINT_STATE_BINDING")
            self.session.resolution_endpoints = frozenset(cast(list[str], values))
            if followup:
                vpc = projection.get("module.network.aws_vpc.this", {}).get("id")
                if (
                    not isinstance(vpc, str)
                    or vpc not in self.session.followup_targets["describe_vpcs"]
                ):
                    self.session.reject("RESOLUTION_ENDPOINT_STATE_BINDING")
                self.session.followup_vpc = vpc
            rows = self.session.pages(
                "ec2",
                "describe_vpc_endpoints",
                {
                    "VpcEndpointIds": sorted(self.session.resolution_endpoints),
                },
                result_key="VpcEndpoints",
            )
            for row in rows:
                key = row.get("VpcEndpointId")
                if (
                    not isinstance(key, str)
                    or key not in self.session.resolution_endpoints
                    or key in native_endpoints
                ):
                    self.session.reject("RESOLUTION_ENDPOINT_RESPONSE_BINDING")
                native_endpoints[key] = row
            if followup:
                self.session.followup_endpoint_rows = native_endpoints
                eni_ids = set(self.session.followup_targets["describe_network_interfaces"])
                for row in native_endpoints.values():
                    ids = row.get("NetworkInterfaceIds")
                    if not isinstance(ids, list) or any(
                        not isinstance(item, str) or not item.startswith("eni-") for item in ids
                    ):
                        raise ContractError("RESOLUTION_ENDPOINT_ENI_BINDING_UNAVAILABLE")
                    eni_ids.update(ids)
                if len(eni_ids) > 32:
                    self.session.reject("RESOLUTION_ENDPOINT_STATE_BINDING")
                self.session.followup_targets["describe_network_interfaces"] = sorted(eni_ids)
            return passed({"returned_count": len(rows)})

        checks.run(
            "endpoint_collection", endpoint_read, dependencies=("platform_state",), remote=True
        )
        for target in endpoints:

            def compare_endpoint(
                target: NativeTarget = target,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                resource_id = _state_identity_projection(states["platform"])[target.address]["id"]
                native = native_endpoints.get(cast(str, resource_id))
                if native is None:
                    return (
                        DiagnosticStatus.INDETERMINATE,
                        "ENDPOINT_NOT_RETURNED",
                        {"address": target.address},
                    )
                documents = [
                    cast(
                        dict[str, object],
                        decode_json_strict(assertion.expected_fields_json.encode()),
                    )
                    for assertion in target.assertions
                ]
                expected_policies = [
                    row["PolicyDocument.@diagnostic_policy_sha256"]
                    for row in documents
                    if "PolicyDocument.@diagnostic_policy_sha256" in row
                ]
                if len(expected_policies) != 1:
                    raise ContractError("RESOLUTION_EXPECTED_POLICY_UNAVAILABLE")
                result = resolution_policy_differences(
                    expected_policies[0],
                    native.get("PolicyDocument"),
                    approved_default_endpoint=True,
                )
                return (
                    DiagnosticStatus.PASS
                    if result["classification"] == "SEMANTIC_MATCH"
                    else DiagnosticStatus.FAIL,
                    cast(str, result["classification"]),
                    {"address": target.address, **result},
                )

            checks.run(
                "endpoint/" + target.address,
                compare_endpoint,
                dependencies=("endpoint_collection",),
            )

        governed = frozenset(
            value
            for raw in states.values()
            for attributes in _state_identity_projection(raw).values()
            for key, value in attributes.items()
            if key != "input" and isinstance(value, str)
        )
        for category in (
            "EC2_NETWORK",
            "EC2_SECURITY_GROUPS",
            "EC2_SUBNETS",
            "EC2_ROUTES",
            "ENI",
            "IAM_ROLES",
            "IAM_POLICIES",
            "KMS",
            "S3",
        ):

            def discover(
                category: str = category,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                result = self.session.resolution_discovery(category, governed)
                known = {
                    "GOVERNED_STATE_MANAGED",
                    "AWS_MANAGED",
                    "SHARED_DEPENDENCY",
                    "AWS_SERVICE_MANAGED",
                    "OUTSIDE_APPROVED_SANDBOX_NETWORK",
                }
                rows = cast(list[dict[str, object]], result["resources"])
                complete = result["enumeration_complete"] and all(
                    row["classification"] in known for row in rows
                )
                return (
                    DiagnosticStatus.PASS if complete else DiagnosticStatus.INDETERMINATE,
                    "DISCOVERY_CLASSIFIED" if complete else "DISCOVERY_REQUIRES_RESOLUTION",
                    result,
                )

            checks.run(
                "discovery/" + category,
                discover,
                dependencies=("bootstrap_state", "platform_state")
                + (("endpoint_collection",) if followup and category == "ENI" else ()),
                remote=True,
            )

        def role() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            name = "AWSServiceRoleForAmazonOpenSearchService"
            try:
                response = self.session.call("iam", "get_role", {"RoleName": name})
            except DiagnosticReadError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
                return (
                    DiagnosticStatus.FAIL,
                    "OWNER_MANAGED_SERVICE_ROLE_ABSENT",
                    {
                        "role": name,
                        "presence": "ABSENT",
                        "ownership": "OWNER_MANAGED",
                        "creation_authorized": False,
                        "role_creation_would_fix_log_failure": "NOT_ESTABLISHED",
                    },
                )
            row = response.get("Role")
            arn = (
                "arn:aws:iam::526338061652:role/aws-service-role/opensearchservice.amazonaws.com/"
                + name
            )
            if not isinstance(row, dict) or row.get("Arn") != arn:
                self.session.reject("RESOLUTION_ROLE_IDENTITY")
            return passed(
                {
                    "role": name,
                    "presence": "PRESENT",
                    "ownership": "OWNER_MANAGED",
                    "permission_policy_verification": "NOT_RUN",
                    "creation_authorized": False,
                }
            )

        checks.run("owner_managed_service_role", role, dependencies=("aws_identity",), remote=True)

        def history() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            names = {
                cast(
                    dict[str, object], decode_json_strict(target.presence.arguments_json.encode())
                ).get("logGroupNamePrefix"): target.address
                for target in bundle.targets
                if target.resource_type == "aws_cloudwatch_log_group"
            }
            events = self.session.pages(
                "cloudtrail",
                "lookup_events",
                {
                    "LookupAttributes": [
                        {"AttributeKey": "EventName", "AttributeValue": "CreateLogGroup"}
                    ],
                    "StartTime": parse_utc_timestamp(RESOLUTION_EVENTS_START, "start"),
                    "EndTime": parse_utc_timestamp(RESOLUTION_EVENTS_END, "end"),
                    **({"MaxResults": 50} if followup else {}),
                },
                result_key="Events",
            )
            findings: list[dict[str, object]] = []
            for event in events:
                raw = event.get("CloudTrailEvent")
                if not isinstance(raw, str):
                    raise ContractError("RESOLUTION_EVENT_UNAVAILABLE")
                value = decode_json_strict(raw.encode())
                if not isinstance(value, dict):
                    raise ContractError("RESOLUTION_EVENT_MALFORMED")
                parameters = value.get("requestParameters")
                if not isinstance(parameters, dict) or parameters.get("logGroupName") not in names:
                    continue
                caller = value.get("userIdentity")
                if (
                    not isinstance(caller, dict)
                    or caller.get("arn") != "arn:aws:iam::526338061652:user/finopsinfra"
                    or value.get("recipientAccountId") != "526338061652"
                    or value.get("awsRegion") != "ap-southeast-1"
                ):
                    self.session.reject("RESOLUTION_EVENT_IDENTITY")
                code = value.get("errorCode")
                event_time = value.get("eventTime")
                if (
                    not isinstance(event_time, str)
                    or not parse_utc_timestamp(RESOLUTION_EVENTS_START, "start")
                    <= parse_utc_timestamp(event_time, "event time")
                    <= parse_utc_timestamp(RESOLUTION_EVENTS_END, "end")
                    or value.get("eventName") != "CreateLogGroup"
                    or value.get("eventSource") != "logs.amazonaws.com"
                ):
                    self.session.reject("DIAGNOSTIC_EVENT_INTERVAL")
                safe = (
                    code
                    if code
                    in {
                        "AccessDenied",
                        "AccessDeniedException",
                        "InvalidParameterException",
                        "ServiceUnavailableException",
                        "ThrottlingException",
                    }
                    else "UNCLASSIFIED"
                )
                message = value.get("errorMessage")
                message_text = message.casefold() if isinstance(message, str) else ""
                classification = "INDETERMINATE"
                if safe in {"AccessDenied", "AccessDeniedException"}:
                    classification = "AUTHORIZATION_DENIED"
                if "kms" in message_text and any(
                    token in message_text
                    for token in ("access", "permission", "not allowed", "not authorized")
                ):
                    classification = "KMS_AUTHORIZATION_REPORTED_CAUSE_UNPROVEN"
                elif "logs:tagresource" in message_text and any(
                    token in message_text for token in ("denied", "not authorized", "not allowed")
                ):
                    classification = "TAG_AUTHORIZATION_REPORTED_CAUSE_UNPROVEN"
                findings.append(
                    {
                        "event_time": value.get("eventTime"),
                        "address": names[parameters["logGroupName"]],
                        "event": "CreateLogGroup",
                        "caller": "MATCH",
                        "error_code": safe,
                        "classification": classification,
                        **(self.session.followup_denial_details(value) if followup else {}),
                        "role_creation_would_fix_failure": "NOT_ESTABLISHED",
                    }
                )
            return (
                DiagnosticStatus.INDETERMINATE,
                "HISTORICAL_FAILURE_REQUIRES_REVIEW",
                {
                    "events": findings,
                    "matched_count": len(findings),
                    "expected_resource_count": 4,
                    "matched_resource_count": len({row["address"] for row in findings}),
                    **(
                        {
                            "exact_four_unique_events": (
                                len(findings) == 4
                                and len({row["address"] for row in findings}) == 4
                                and all(row.get("event_identity") is not None for row in findings)
                                and len({row.get("event_identity") for row in findings}) == 4
                            )
                        }
                        if followup
                        else {}
                    ),
                },
            )

        checks.run("historical_log_failures", history, dependencies=("aws_identity",), remote=True)
        billing: dict[str, dict[str, object]] = {}
        for kind in ("usage",) if followup else ("account", "service", "usage"):

            def collect_billing(
                kind: str = kind,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                result = self.session.resolution_billing(kind)
                billing[kind] = result
                return (
                    DiagnosticStatus.PASS if result["complete"] else DiagnosticStatus.INDETERMINATE,
                    "ACCOUNT_SCOPE_ONLY" if result["complete"] else "BILLING_PAGINATION_UNCOVERED",
                    result,
                )

            checks.run(
                "billing/" + kind, collect_billing, dependencies=("aws_identity",), remote=True
            )

        def accounting() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if followup:
                from dataclasses import asdict

                from .cost import resolution_cost_ledger

                return (
                    DiagnosticStatus.INDETERMINATE,
                    "ATTRIBUTION_AND_UNCOVERED_EXPOSURE_UNRESOLVED",
                    asdict(
                        resolution_cost_ledger(
                            billing.get("usage", {}),
                            self.clock.now(),
                            self.session.billing_requests,
                        )
                    ),
                )
            account = billing.get("account", {})
            days = cast(list[dict[str, object]], account.get("days", []))
            total = (
                sum(
                    (
                        Decimal(cast(str, row["unblended_usd"]))
                        for day in days
                        for row in cast(list[dict[str, object]], day["amounts"])
                    ),
                    Decimal("0"),
                )
                if account.get("complete") is True
                else None
            )
            return (
                DiagnosticStatus.INDETERMINATE,
                "ATTRIBUTION_AND_UNCOVERED_EXPOSURE_UNRESOLVED",
                {
                    "cycle": "W5-CYCLE-A",
                    "total_cycle_ceiling_usd": "30.00",
                    "monthly_treatment": "INFORMATIONAL",
                    "reported_account_usd": str(total) if total is not None else None,
                    "attributable_incurred_usd": None,
                    "available_headroom_usd": None,
                    "uncovered_from": "2026-09-13T00:00:00Z",
                    "uncovered_through": self.clock.now().isoformat(),
                    "billing_lag_seconds": None,
                    "remaining_execution_testing_usd": None,
                    "teardown_and_retained_usd": None,
                    "diagnostic_actual_charge_usd": None,
                    "billing_requests_this_attempt": self.session.billing_requests,
                    "planning_allowances_are_actual_charges": False,
                    "overlapping_billing_views_added": False,
                    "execution_cost_approval": "NOT_ESTABLISHED",
                },
            )

        checks.run("lifecycle_accounting", accounting)
        self.session.preservation_phase = True
        for scope in ("bootstrap", "platform"):

            def unchanged(scope: str = scope) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                raw = (
                    read_private_state(
                        bootstrap_state,
                        approved_path=bootstrap_state,
                        repository=self.repository_root,
                    )
                    if scope == "bootstrap"
                    else self.session.state_bytes()[0]
                )
                if raw != states[scope]:
                    self.session.reject("DIAGNOSTIC_FINAL_STATE_DRIFT")
                return passed({"sha256": sha256_bytes(raw)})

            checks.run(
                scope + "_state_preserved",
                unchanged,
                dependencies=(scope + "_state",),
                remote=scope == "platform",
            )

        def preservation() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if self.identities(request) != request.approved_identities:
                self.session.reject("DIAGNOSTIC_FINAL_REPOSITORY_DRIFT")
            return passed()

        checks.run("final_preservation", preservation)
        report = {
            "schema_version": "w5-004.targeted-resolution.v2"
            if followup
            else "w5-004.targeted-resolution.v1",
            "operation_id": operation_id,
            "account_id": "526338061652",
            "region": "ap-southeast-1",
            "started_at": started,
            "completed_at": self.clock.now().isoformat(),
            "checks": tuple(checks.checks),
            "limits": self.session.limits,
            "aws_requests": self.session.requests,
            "billing_requests": self.session.billing_requests,
            "enumeration_pages": tuple(sorted(self.session.enumeration_pages.values())),
            "requests_by_api": tuple(sorted(self.session.request_counts.items())),
            "billing_interval": {
                "start": RESOLUTION_BILLING_START,
                "end_exclusive": RESOLUTION_BILLING_END,
            },
            "cloudtrail_interval": {"start": RESOLUTION_EVENTS_START, "end": RESOLUTION_EVENTS_END},
            "exit_code": checks.exit_code,
            "recovery_eligibility": "NOT_ESTABLISHED",
            "mutation_started": False,
            "terraform": "NOT_RUN",
            "pricing": "NOT_RUN",
        }
        if len(canonical_json_bytes(report)) > 8 * 1024 * 1024:
            raise ContractError("RESOLUTION_REPORT_SIZE_LIMIT")
        digest = write_canonical_json_atomic(
            root / "resolution.json",
            report,
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        write_canonical_json_atomic(
            root / "resolution-identity.json",
            {
                "schema_version": "w5-004.targeted-resolution.v2"
                if followup
                else "w5-004.targeted-resolution.v1",
                "operation_id": operation_id,
                "report_sha256": digest,
                "request_sha256": sha256_bytes(payload),
                "runtime_sha256": sha256_bytes(canonical_json_bytes(self.configuration)),
                "source": request.approved_identities,
                "inputs": self.configuration.input_files,
                "states": identities,
                "output_root": str(root),
                "exit_code": checks.exit_code,
                "recovery_eligibility": "NOT_ESTABLISHED",
            },
            allowed_root=self.external_root,
            repository_root=self.repository_root,
        )
        return (
            checks.exit_code,
            "RESOLUTION_PREREQUISITES_UNRESOLVED" if checks.exit_code else "RESOLUTION_COMPLETE",
        )

    def _cost_checks(
        self,
        checks: DiagnosticChecks,
        request: DiagnosticRequest,
        reader: DiagnosticEvidenceReader,
        states: dict[str, bytes],
        inventories: dict[str, InventoryResult],
    ) -> None:
        from .cost import (
            diagnostic_exposure_totals,
            diagnostic_pricing_summary,
            diagnostic_query_exposure,
            reconcile_charging_bases,
            reconcile_exposure_basis,
            reconcile_incurred_coverage,
            validate_cost_result_v2,
        )

        def pricing() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            retained = self.configuration.retained_pricing
            if retained is None:
                raise ContractError("RETAINED_PRICING_EVIDENCE_REQUIRED")
            reference, source = retained
            path = ensure_external_path(Path(source), self.external_root, self.repository_root)
            raw = BoundEvidenceReader(path.parent, self.repository_root).read(
                path.name,
                reference.sha256,
                reference.byte_count,
            )
            result = diagnostic_pricing_summary(
                raw,
                {rule.address: rule.resource_type for rule in self.configuration.platform_rules},
            )
            result["monthly_treatment_for_review"] = "INFORMATIONAL_W5_CYCLE_A_ONLY"
            return DiagnosticStatus.PASS, "HISTORICAL_DISCLOSURE_NOT_COST_APPROVAL", result

        checks.run("historical_pricing_disclosure", pricing, mandatory=False)
        terms = self.configuration.exposure
        query_allowance: list[object] = []

        def accounting_binding() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if (
                terms is None
                or terms.operation_id != request.operation_id
                or (
                    terms.schema_version != DIAGNOSTIC_SCHEMA_VERSION
                    or terms.state_sha256 != sha256_bytes(states["platform"])
                    or terms.bootstrap_state_sha256 != sha256_bytes(states["bootstrap"])
                    or terms.reviewed_cost.raw_estimate.operation_id != request.operation_id
                )
            ):
                raise ContractError("CURRENT_LIFECYCLE_ACCOUNTING_EVIDENCE_REQUIRED")
            desired = {
                (scope, rule.address)
                for scope, rules in (
                    ("platform", self.configuration.platform_rules),
                    (
                        "bootstrap",
                        self.configuration.bootstrap_rules,
                    ),
                )
                for rule in rules
                if scope == "platform" or rule.resource_type != "terraform_data"
            }
            covered = {(entry.scope, entry.address) for entry in terms.reviewed_cost.coverage}
            if desired != covered or len(covered) != len(terms.reviewed_cost.coverage):
                raise ContractError("LIFECYCLE_RESOURCE_COVERAGE_INCOMPLETE")
            return (
                DiagnosticStatus.PASS,
                "CURRENT_ACCOUNTING_INPUTS_BOUND",
                diagnostic_exposure_totals(
                    terms.reviewed_cost,
                    reader=reader,
                    now=self.clock.now(),
                    state_lineage=state_inventory(states["platform"])[0],
                    configuration_sha256=dict(request.approved_identities.inputs).get(
                        "configs/lifecycle/w5-004.json"
                    ),
                ),
            )

        checks.run(
            "accounting_evidence",
            accounting_binding,
            dependencies=("platform_state", "bootstrap_state"),
        )

        def reconcile(kind: str) -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if terms is None:
                raise ContractError("ACCOUNTING_TERMS_REQUIRED")
            cost = terms.reviewed_cost
            if kind == "charging":
                reconcile_charging_bases(cost, reader, self.clock.now())
            elif kind == "exposure":
                reconcile_exposure_basis(cost, reader, self.clock.now())
            elif kind == "incurred":
                for scope, rules in (
                    ("platform", self.configuration.platform_rules),
                    ("bootstrap", self.configuration.bootstrap_rules),
                ):
                    native = inventories.get(scope)
                    if native is None or len(native.entries) != len(rules) - 1:
                        raise ContractError("INCURRED_NATIVE_COVERAGE_INCOMPLETE")
                    if any(entry.presence not in {"PRESENT", "ABSENT"} for entry in native.entries):
                        raise ContractError("INCURRED_NATIVE_STATE_UNKNOWN")
                proofs = tuple(
                    item for item in cost.assumptions if item.kind == "current-bootstrap-inventory"
                )
                if len(proofs) != 1:
                    raise ContractError("INCURRED_BOOTSTRAP_INVENTORY_REQUIRED")
                proof = proofs[0]
                supplied = decode_operational_record(
                    reader.read(proof.path, proof.sha256, proof.byte_count), InventoryResult
                )
                if (
                    supplied.operation_id != request.operation_id
                    or supplied.account_id != "526338061652"
                    or supplied.region != "ap-southeast-1"
                    or len(supplied.entries) != len(inventories["bootstrap"].entries)
                    or {replace(entry, observed_at="") for entry in supplied.entries}
                    != {
                        replace(entry, observed_at="") for entry in inventories["bootstrap"].entries
                    }
                    or not 0
                    <= (
                        self.clock.now()
                        - parse_utc_timestamp(
                            supplied.observed_at, "bootstrap inventory observation"
                        )
                    ).total_seconds()
                    <= 900
                    or parse_utc_timestamp(supplied.valid_until, "bootstrap inventory expiry")
                    <= self.clock.now()
                ):
                    raise ContractError("INCURRED_BOOTSTRAP_INVENTORY_NOT_CURRENT")
                reconcile_incurred_coverage(cost, inventories["platform"], "platform", reader)
            else:
                from decimal import Decimal

                exposure = diagnostic_exposure_totals(
                    cost,
                    reader=reader,
                    now=self.clock.now(),
                    state_lineage=state_inventory(states["platform"])[0],
                    configuration_sha256=dict(request.approved_identities.inputs).get(
                        "configs/lifecycle/w5-004.json"
                    ),
                )
                total = exposure["supported_total_usd"]
                ceiling = Decimal(cast(str, exposure["lifecycle_ceiling_usd"]))
                if not isinstance(total, str) or not query_allowance:
                    raise ContractError("QUERY_EXPOSURE_UNRESOLVED")
                if Decimal(total) + cast(Decimal, query_allowance[0]) > ceiling:
                    reason = "LIFECYCLE_CEILING_REPLACEMENT_REQUIRES_OWNER_APPROVAL"
                    return (
                        DiagnosticStatus.FAIL,
                        reason,
                        {
                            "supported_total_including_query_allowance_usd": str(
                                Decimal(total) + cast(Decimal, query_allowance[0])
                            ),
                            "ceiling_usd": str(ceiling),
                            "headroom_usd": str(
                                ceiling - Decimal(total) - cast(Decimal, query_allowance[0])
                            ),
                        },
                    )
                validate_cost_result_v2(
                    cost,
                    cost.saved_plan_sha256,
                    self.clock.now(),
                    reader=reader,
                    state_lineage=state_inventory(states["platform"])[0],
                    configuration_sha256=dict(request.approved_identities.inputs).get(
                        "configs/lifecycle/w5-004.json"
                    ),
                )
            return DiagnosticStatus.PASS, "ACCOUNTING_COMPONENT_RECONCILED", {}

        for kind in ("charging", "exposure", "incurred"):

            def reconcile_component(
                kind: str = kind,
            ) -> tuple[DiagnosticStatus, str, dict[str, object]]:
                return reconcile(kind)

            checks.run(
                "accounting/" + kind,
                reconcile_component,
                dependencies=("accounting_evidence",),
            )

        def query_cost() -> tuple[DiagnosticStatus, str, dict[str, object]]:
            if terms is None:
                return (
                    DiagnosticStatus.INDETERMINATE,
                    "QUERY_COST_BASIS_REQUIRED",
                    {
                        "requests": self.session.billing_requests,
                        "actual_query_charges": "NOT_VERIFIED",
                        "query_allowance_usd": None,
                    },
                )
            allowance = diagnostic_query_exposure(
                terms.query_cost_basis,
                reader,
                self.clock.now(),
                request.operation_id,
            )
            query_allowance.append(allowance)
            reason = "SOURCE_BACKED_QUERY_EXPOSURE_RESERVED_NOT_ACTUAL_SPENDING"
            return (
                DiagnosticStatus.PASS,
                reason,
                {
                    "requests": self.session.billing_requests,
                    "query_allowance_usd": str(allowance),
                    "actual_query_charges": "NOT_VERIFIED",
                },
            )

        checks.run("billing_query_exposure", query_cost)
        checks.run(
            "lifecycle_cost_eligibility",
            lambda: reconcile("eligibility"),
            dependencies=(
                "accounting/charging",
                "accounting/exposure",
                "accounting/incurred",
                "billing_query_exposure",
            ),
        )


def production_coordinator(
    runtime_path: Path,
    runtime_sha256: str,
    *,
    request_payload: bytes,
    repository: Path,
    clock: Clock,
) -> RepositoryLifecycleCoordinator | RepositoryDiagnosticCoordinator:
    """Compose the real adapters only for an explicit hash-bound CLI execution request."""
    from .lifecycle_io import (
        load_lifecycle_config,
        reserve_operation_directory,
        verify_private_directory,
    )

    config = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
    external_paths = cast(dict[str, str], config["external_paths"])
    external = Path(external_paths["temporary_root"])
    runtime = ensure_external_path(runtime_path, external, repository)
    if not runtime.is_file() or runtime.stat().st_size > 1024 * 1024:
        raise ContractError("RUNTIME_CONFIGURATION_SIZE_OR_TYPE")
    raw = runtime.read_bytes()
    if sha256_bytes(raw) != runtime_sha256:
        raise ContractError("RUNTIME_CONFIGURATION_HASH_MISMATCH")
    runtime_value = decode_json_strict(raw)
    diagnostic = (
        isinstance(runtime_value, dict)
        and runtime_value.get("schema_version") == DIAGNOSTIC_SCHEMA_VERSION
    )
    configuration = (
        decode_diagnostic_record(
            raw,
            DiagnosticRuntimeConfiguration,
        )
        if diagnostic
        else decode_operational_record(raw, RuntimeConfiguration)
    )
    request = decode_json_strict(request_payload)
    if not isinstance(request, dict) or not isinstance(request.get("operation_root"), str):
        raise ContractError("REQUEST_OPERATION_ROOT_REQUIRED")
    root = ensure_external_path(Path(request["operation_root"]), external, repository)
    approved_parent = external / "consolidated-remediation-001"
    expected_diagnostic_root = approved_parent / DIAGNOSTIC_OPERATION_DIRECTORY
    if (diagnostic and root != expected_diagnostic_root) or (
        not diagnostic and (root.parent != approved_parent or root == approved_parent)
    ):
        raise ContractError("SINGLE_USE_OPERATION_ROOT_REQUIRED")
    if not approved_parent.exists():
        if diagnostic:
            raise ContractError("DIAGNOSTIC_PRIVATE_PARENT_REQUIRED")
        reserve_operation_directory(approved_parent, external, repository)
    verify_private_directory(approved_parent)
    if diagnostic:
        verify_private_directory(root.parent)
        verify_private_directory(root)
    tool_map = {
        name: (path, version, digest) for name, path, version, digest in configuration.tools
    }
    if "git" not in tool_map:
        raise ContractError("GIT_RUNTIME_IDENTITY_REQUIRED")
    process = SubprocessCommandRunner(repository_root=repository, external_root=approved_parent)
    git_path, git_version, git_digest = tool_map["git"]
    git = GitObservationRunner(
        Path(git_path),
        git_digest,
        git_version,
        process,
        repository,
        dict(configuration.child_environment),
    )
    aws = Boto3AwsInventoryProvider.from_profile(
        native_lister=None,
        profile="default",
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
        diagnostic_only=diagnostic,
    )
    if isinstance(configuration, DiagnosticRuntimeConfiguration):
        return RepositoryDiagnosticCoordinator(
            configuration,
            repository=repository,
            external=external,
            clock=clock,
            git=git,
            session=DiagnosticAwsSession(aws),
            runtime_identity=(str(runtime), runtime_sha256),
        )
    ledger_root = Path(external_paths["evidence_root"]) / "consolidated-remediation-001"
    ledger = OperationLedger(ledger_root, repository)
    services = ProductionReviewServices(
        configuration,
        repository=repository,
        external=external,
        ledger=ledger,
        clock=clock,
        process=process,
        identity_runner=git,
        aws=aws,
    )
    services._operation_root = root
    services._runtime_identity = (str(runtime), runtime_sha256)
    return RepositoryLifecycleCoordinator(services, services, purge_adapter=aws.bounded_purge())


def observe_repository_identities(
    configuration: RuntimeConfiguration | DiagnosticRuntimeConfiguration,
    request: ReviewRequest | DiagnosticRequest,
    *,
    repository: Path,
    git: GitObservationRunner,
    environment: dict[str, str],
    runtime_identity: tuple[str, str] | None,
) -> IdentityBundle:
    """Observe raw content and index separately; never adopt a differing digest."""
    from .lifecycle_io import (
        LIFECYCLE_ADMITTED_FILES,
        LIFECYCLE_BASELINE_HEAD,
        LIFECYCLE_PROTECTED_DIRTY,
        LIFECYCLE_PROTECTED_PATHS,
        LIFECYCLE_TRACKED_EDITS,
        lifecycle_scope,
        parse_git_index,
        parse_git_status,
        unique_paths,
        working_manifest,
    )
    from .lifecycle_models import CONTENT_SCOPE_VERSION

    if (
        git.read("branch") != b"main\n"
        or git.read("head") != (LIFECYCLE_BASELINE_HEAD + "\n").encode()
    ):
        raise ContractError("REPOSITORY_BASELINE_CHANGED")
    scope = lifecycle_scope(git.read("tree"))
    status = parse_git_status(git.read("status"))
    permitted_status = {
        *(("??", name, None) for name in LIFECYCLE_ADMITTED_FILES),
        *((" M", name, None) for name in (*LIFECYCLE_TRACKED_EDITS, *LIFECYCLE_PROTECTED_DIRTY)),
    }
    if set(status) != permitted_status:
        raise ContractError("COLUMN_L_STATUS_BOUNDARY_CHANGED")
    if status != tuple(sorted(configuration.authorized_status, key=lambda row: row[1])):
        raise ContractError("WORKTREE_AUTHORIZATION_CHANGED")
    index = parse_git_index(git.read("index"))
    working = working_manifest(repository, scope)
    protected = unique_paths(tuple(path for path, _ in configuration.protected_files))
    if set(protected) != set(LIFECYCLE_PROTECTED_PATHS):
        raise ContractError("PROTECTED_MANIFEST_INCOMPLETE")
    governance = working_manifest(repository, protected)
    expected = dict(configuration.protected_files)
    if any(kind != "FILE" or expected[name] != digest for name, kind, _, digest in governance):
        raise ContractError("PROTECTED_GOVERNANCE_CHANGED")
    inputs: dict[str, str] = {}
    terraform_root = repository / (
        "infra/bootstrap" if request.target == "bootstrap" else "infra/environments/sandbox"
    )
    inputs["runtime/terraform-root"] = sha256_bytes(canonical_json_bytes(str(terraform_root)))
    inputs["runtime/terraform-environment"] = sha256_bytes(
        canonical_json_bytes(
            controlled_environment(
                {
                    **environment,
                    "TF_DATA_DIR": str(
                        Path(configuration.terraform_data_root) / terraform_root.name
                    ),
                    "TF_IN_AUTOMATION": "1",
                },
                cost_child=False,
            )
        )
    )
    if runtime_identity is not None:
        runtime_path, runtime_hash = runtime_identity
        if sha256_file(Path(runtime_path)) != runtime_hash:
            raise ContractError("RUNTIME_CONFIGURATION_CHANGED")
        inputs["runtime/configuration.json"] = runtime_hash
    for logical, source, digest in configuration.input_files:
        bounded_relative_path(logical)
        candidate = Path(source)
        validate_original_ancestors(candidate)
        if logical in inputs or sha256_file(candidate) != digest:
            raise ContractError("INPUT_MANIFEST_CHANGED")
        inputs[logical] = digest
    for _name, path, version, digest in configuration.tools:
        validate_original_ancestors(Path(path))
        if not version or not Path(path).is_absolute() or sha256_file(Path(path)) != digest:
            raise ContractError("TOOL_IDENTITY_CHANGED")
    if sha256_file(Path(request.backend_path)) != request.backend_sha256:
        raise ContractError("BACKEND_INPUT_CHANGED")
    for name in (
        "configs/lifecycle/w5-004.json",
        "policies/opa/terraform_plan.rego",
        "policies/opa/exceptions.json",
        "tools/platformctl/destroy.py",
    ):
        inputs[name] = sha256_file(repository / name)
    authorization = {
        "status": status,
        "index": index,
        "content": working_manifest(repository, unique_paths(tuple(row[1] for row in status))),
    }
    return IdentityBundle(
        CONTENT_SCOPE_VERSION,
        sha256_bytes(canonical_json_bytes(working)),
        sha256_bytes(canonical_json_bytes(index)),
        sha256_bytes(canonical_json_bytes(authorization)),
        sha256_bytes(canonical_json_bytes(governance)),
        LIFECYCLE_BASELINE_HEAD,
        configuration.tools,
        tuple(sorted(inputs.items())),
        request.backend_sha256,
    )
