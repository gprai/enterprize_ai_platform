PYTHON ?= python
TERRAFORM ?= terraform
CHECKOV ?= E:/AI/.venvs/enterprise-ai-platform-checkov-3.3.16/Scripts/python.exe E:/AI/.venvs/enterprise-ai-platform-checkov-3.3.16/Scripts/checkov
TFLINT ?= E:/AI/.tools/tflint/0.60.0/tflint.exe
TFLINT_PLUGIN_DIR ?= E:/AI/.tflint-cache/enterprise-ai-platform-w5-001
export TFLINT_PLUGIN_DIR
OPA ?= E:/AI/.tools/opa/1.20.0/opa.exe
ACTIONLINT ?= E:/AI/.tools/actionlint/1.7.12/actionlint.exe
TRIVY ?= E:/AI/.tools/trivy/0.74.0/trivy.exe
GRYPE ?= E:/AI/.tools/grype/0.118.0/grype.exe
SYFT ?= E:/AI/.tools/syft/1.51.1/syft.exe
COSIGN ?= E:/AI/.tools/cosign/3.1.2/cosign.exe
CHAINCTL ?= E:/AI/.tools/chainctl/0.2.346/chainctl.exe
UV ?= E:/AI/.tools/uv/0.12.9/uv-x86_64-unknown-linux-gnu/uv
INFRACOST ?= E:/AI/.tools/infracost/0.10.45/infracost.exe
PROMTOOL ?= owner-must-supply-promtool-3.5.0
W5_004_CONFIG = configs/lifecycle/w5-004.json
W5_004_APPROVAL ?= owner-must-supply-exact-external-approval.json
W5_004_CONFIRMATION ?= owner-must-supply-exact-typed-confirmation
W5_004_ARTIFACT_SHA256 ?= owner-must-supply-exact-lowercase-sha256
W5_004_TARGET ?= owner-must-supply-exact-target
W5_004_EXECUTION_FLAGS ?=
W5_002_CONFIG = configs/ci/w5-002.json
W5_002_REPORTS = reports/w5-002
W5_002_OCI ?= owner-must-supply-exact-external-w5-002-py313-candidate.oci
W5_002_RAW_DIR ?= owner-must-supply-exact-external-w5-002-py313-raw-directory
W5_002_OCI_LAYOUT = $(W5_002_RAW_DIR)/oci-layout
W5_002_BUILDER = enterprise-ai-platform-w5-002-py313
W5_002_BUILDER_IMAGE = cgr.dev/vayunetrix.com/python:3.13.15-dev@sha256:023795336613750af2cd86cf06503b5b74370c6a561d2a22219a2e80c6fe4811
W5_002_RUNTIME_IMAGE = cgr.dev/vayunetrix.com/python:3.13.15@sha256:f7cc453a5d7ac0cf86f585e22b6e404eaa10f69db5d00da50f9940e2806358fa
W5_002_TRIVY_DB_IDENTITY ?= sha256:owner-must-supply-exact-trivy-database-identity
W5_002_GRYPE_DB_IDENTITY ?= sha256:owner-must-supply-exact-grype-database-identity
W2_004_COMPOSE = docker compose -p enterprise-ai-w2-004a -f docker-compose.yml -f docker-compose.w2-004.yml --profile local-retrieval
W2_004_RUNNER_IMAGE = enterprise-ai-w2-004a-local_retrieval_runner:latest
W6_001_TEMPLATE = deploy/k8s
W6_001_BINDING ?= owner-must-supply-exact-external-w6-001-release-binding.json
W6_001_RELEASE_ROOT ?= owner-must-supply-exact-external-w6-001-release-root
W6_003_CONFIG = configs/readiness/local-integrated-readiness.yaml
W6_003_EVIDENCE_ROOT ?= E:/AI/.runtime/enterprise_ai_platform/w6-003/owner-test-01
W6_003_LOCAL_PROOF ?= $(W6_003_EVIDENCE_ROOT)/local-proof.json
W6_003_LOCAL_ROLLBACK ?= $(W6_003_EVIDENCE_ROOT)/local-rollback-rehearsal.json
W6_003_HANDOVER ?= $(W6_003_EVIDENCE_ROOT)/w6-004-readiness-manifest.json
W6_004_CONFIG = configs/lifecycle/w6-004.json
W7_001_CONFIG = configs/ingestion/governed-data-foundation.yaml
W7_002_CONFIG = configs/processing/document-quality-replay.yaml
W7_003_CONFIG = configs/ingestion/privacy-retention-lifecycle.yaml

.PHONY: help validate test test-unit test-integration test-feature test-smoke test-security test-teardown evaluate local-retrieval-config local-retrieval-build local-retrieval-inspect local-retrieval-up local-retrieval-ingest local-retrieval-query local-retrieval-regression rollback-local local-retrieval-remove stop-local destroy-local verify-clean-local rollback-release smoke terraform-fmt-check terraform-validate-bootstrap terraform-validate-sandbox tflint-bootstrap tflint-sandbox checkov-config checkov-terraform opa-policy-check opa-terraform-policy w5-policy-tests w5-policy-rollback bedrock-owner-dry-run w5-static-tests w5-002-validate-config w5-002-validate-locks w5-002-static w5-002-workflow-contract w5-002-build w5-002-scan w5-002-sbom w5-002-clean-runtime w5-002-reconcile w5-002-rollback-identity w5-002-clean w5-002-verify-clean
.PHONY: plan-sandbox w5-004-bootstrap-plan w5-004-bootstrap-apply w5-004-platform-plan w5-004-policy-review w5-004-cost-review w5-004-platform-apply w5-004-aws-verify w5-004-infrastructure-rollback w5-004-destroy-plan w5-004-purge-sandbox w5-004-platform-destroy w5-004-bootstrap-destroy w5-004-verify-clean
.PHONY: w6-001-template-validate w6-001-policy w6-001-checkov w6-001-tests w6-001-release-bind w6-001-release-validate
.PHONY: w6-002-validate w6-002-promtool w6-002-tests
.PHONY: w6-003-validate w6-003-source-identity w6-003-tests w6-003-evidence-validate
.PHONY: w6-004-source-validate w6-004-tests w7-001-tests w7-002-tests w7-003-tests w7-004-tests

help:
	@echo "Available targets include W5-002 supply-chain controls and separately owner-gated W5-004 plan, apply, rollback, destroy, and cleanliness phases."

w7-003-tests:
	$(PYTHON) -B -m pytest -q tests/unit/test_w7_003_privacy_lifecycle.py tests/contract/test_w7_003_privacy_lifecycle_contract.py tests/integration/test_w7_003_privacy_lifecycle_composition.py tests/feature/test_w7_003_privacy_lifecycle.py tests/security/test_w7_003_privacy_lifecycle_security.py tests/rollback/test_w7_003_privacy_lifecycle_rollback.py tests/teardown/test_w7_003_privacy_lifecycle_cleanliness.py

w7-004-tests:
	$(if $(strip $(W7_004_PYTEST_BASETEMP)),,$(error W7_004_PYTEST_BASETEMP must name a unique external path))
	$(PYTHON) -B -m pytest --basetemp "$(W7_004_PYTEST_BASETEMP)" -q -p no:cacheprovider tests/contract/test_w7_004_feature_management_decision.py tests/feature/test_feature_matrix.py

validate:
	$(PYTHON) -m tools.platformctl validate

test: test-unit test-integration test-feature test-smoke test-security test-teardown

test-unit:
	$(PYTHON) -m unittest tests.unit.test_platformctl

test-integration:
	$(PYTHON) -m unittest tests.integration.test_repository_layout

test-feature:
	$(PYTHON) -m unittest tests.feature.test_feature_matrix

test-smoke:
	$(PYTHON) -m unittest tests.smoke.test_platformctl_help

test-security:
	$(PYTHON) -m unittest tests.security.test_repository_security

test-teardown:
	$(PYTHON) -m unittest tests.teardown.test_repository_cleanliness

evaluate:
	$(PYTHON) -B tools/evaluationctl.py candidate --config configs/eval/cited-rag-evaluation-policy.yaml --dataset configs/eval/golden.jsonl --baseline configs/eval/baselines/w3-002-v1.json --out reports/eval.json

local-retrieval-config:
	$(W2_004_COMPOSE) config --quiet

local-retrieval-build:
	$(W2_004_COMPOSE) build local_retrieval_runner

local-retrieval-inspect:
	docker image inspect $(W2_004_RUNNER_IMAGE) --format '{{.Os}}/{{.Architecture}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} labels={{json .Config.Labels}} size={{.Size}}'

local-retrieval-up:
	$(W2_004_COMPOSE) up -d --wait --wait-timeout 60 qdrant

local-retrieval-ingest:
	$(W2_004_COMPOSE) run --rm -e W2_004_PHASE=ingest local_retrieval_runner tests/feature/test_local_retrieval.py::test_real_ingestion_is_initially_absent_and_idempotent -q

local-retrieval-query:
	$(W2_004_COMPOSE) run --rm -e W2_004_PHASE=query local_retrieval_runner tests/feature/test_local_retrieval.py::test_real_authorized_top_five_and_isolation -q

local-retrieval-regression:
	$(W2_004_COMPOSE) run --rm -e W2_004_PHASE=regression -e W2_004_EXPECTED_SOURCE_OVERRIDE=DOC-RESTRICTED-TEST local_retrieval_runner tests/feature/test_local_retrieval.py::test_real_authorized_top_five_and_isolation -q

rollback-local:
	$(W2_004_COMPOSE) run --rm -e W2_004_PHASE=rollback local_retrieval_runner tests/rollback/test_w2_004_local_rollback.py::test_real_rollback_revalidates_the_known_good_state -q

local-retrieval-remove:
	$(W2_004_COMPOSE) run --rm -e W2_004_PHASE=remove local_retrieval_runner tests/feature/test_local_retrieval.py::test_remove_only_the_exact_w2_004_collection -q

stop-local:
	$(W2_004_COMPOSE) stop --timeout 20 qdrant

destroy-local:
	$(W2_004_COMPOSE) down --volumes --remove-orphans --rmi local --timeout 20

verify-clean-local:
	$(PYTHON) -B -m tools.verify_w2_004_local

rollback-release:
	$(PYTHON) -B tools/releasectl.py rollback-release

smoke:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/smoke/test_w4_011_release_smoke.py tests/feature/test_health_contract.py tests/feature/test_w3_001_cited_rag.py tests/feature/test_w3_002_offline_evaluation.py tests/feature/test_w3_003_guardrails.py tests/feature/test_agent_failures.py tests/security/test_api_authorization.py tests/feature/test_trace_correlation.py tests/security/test_telemetry_redaction.py tests/feature/test_api_load_smoke.py tests/security/test_w4_011_release_rollback_security.py
	$(PYTHON) -B tools/releasectl.py smoke
	$(PYTHON) -B tools/releasectl.py verify-clean

terraform-fmt-check:
	$(TERRAFORM) fmt -check -recursive infra

terraform-validate-bootstrap:
	$(TERRAFORM) -chdir=infra/bootstrap validate

terraform-validate-sandbox:
	$(TERRAFORM) -chdir=infra/environments/sandbox validate

tflint-bootstrap:
	$(TFLINT) --chdir=infra/bootstrap --config=$(CURDIR)/.tflint.hcl

tflint-sandbox:
	$(TFLINT) --chdir=infra/environments/sandbox --config=$(CURDIR)/.tflint.hcl

checkov-config:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/integration/test_dependency_contract.py tests/security/test_policy_pack.py

checkov-terraform:
	$(CHECKOV) --config-file .checkov.yml -d infra

opa-policy-check:
	$(OPA) check --strict policies/opa

opa-terraform-policy:
	$(OPA) test policies/opa --verbose

w5-policy-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/contract/test_policy_exception_contract.py tests/feature/test_policy_gate.py tests/security/test_policy_pack.py

w5-policy-rollback:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/rollback/test_policy_pack_rollback.py tests/teardown/test_policy_pack_cleanliness.py

bedrock-owner-dry-run:
	$(PYTHON) -B tools/bedrock_owner_verify.py --config configs/verification/bedrock-owner-test.json --mode dry-run

w5-static-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/contract/test_terraform_module_contract.py tests/security/test_terraform_security.py tests/feature/test_terraform_sandbox_plan.py tests/teardown/test_terraform_state_boundary.py tests/unit/test_bedrock_owner_verify.py tests/security/test_bedrock_owner_verify_security.py tests/teardown/test_bedrock_owner_verify_cleanliness.py

w5-002-validate-config:
	$(PYTHON) -B tools/w5_002_ci.py validate-config --config $(W5_002_CONFIG)

w5-002-validate-locks:
	$(PYTHON) -B tools/w5_002_ci.py validate-locks --runtime requirements-runtime.lock --ci requirements-ci.lock --checkov requirements-checkov.lock

w5-002-static:
	$(ACTIONLINT) .github/workflows/ci.yml .github/workflows/plan-sandbox.yml .github/workflows/security-scan.yml
	$(TERRAFORM) fmt -check -recursive infra
	$(CHECKOV) --config-file .checkov.yml -d infra
	$(OPA) check --strict policies/opa
	$(OPA) test policies/opa --verbose

w5-002-workflow-contract:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/contract/test_w5_002_workflow_contract.py

w5-002-build:
	docker buildx build --builder $(W5_002_BUILDER) --platform linux/amd64 --file docker/application.Dockerfile --output type=oci,dest=$(W5_002_OCI) --provenance=false --sbom=false .
	$(PYTHON) -B tools/w5_002_ci.py write-image-identity --output $(W5_002_REPORTS)/image-identity.json --repository-root . --oci-archive $(W5_002_OCI)

w5-002-scan:
	$(TRIVY) filesystem --format json --output $(W5_002_RAW_DIR)/trivy-filesystem.json --scanners vuln,secret .
	powershell -NoProfile -Command "if (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)') { throw 'W5-002 OCI layout already exists' }; New-Item -ItemType Directory -Path '$(W5_002_OCI_LAYOUT)' -ErrorAction Stop | Out-Null; try { tar.exe -xf '$(W5_002_OCI)' -C '$(W5_002_OCI_LAYOUT)'; if ($$LASTEXITCODE -ne 0) { throw 'W5-002 OCI extraction failed' }; if (-not (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)/index.json' -PathType Leaf) -or -not (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)/oci-layout' -PathType Leaf)) { throw 'W5-002 OCI layout markers are missing' }; & '$(TRIVY)' image --input '$(W5_002_OCI_LAYOUT)' --format json --output '$(W5_002_RAW_DIR)/trivy-image.json'; if ($$LASTEXITCODE -ne 0) { throw 'W5-002 Trivy OCI scan failed' } } finally { Remove-Item -LiteralPath '$(W5_002_OCI_LAYOUT)' -Recurse -Force -ErrorAction SilentlyContinue }"
	$(GRYPE) oci-archive:$(W5_002_OCI) -o json > $(W5_002_RAW_DIR)/grype-image.json
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/trivy-filesystem.json --output $(W5_002_REPORTS)/trivy-filesystem.json --image-identity $(W5_002_REPORTS)/image-identity.json --scanner-database-identity $(W5_002_TRIVY_DB_IDENTITY) --scanner trivy --scope filesystem
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/trivy-image.json --output $(W5_002_REPORTS)/trivy-image.json --image-identity $(W5_002_REPORTS)/image-identity.json --scanner-database-identity $(W5_002_TRIVY_DB_IDENTITY) --scanner trivy --scope oci
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/grype-image.json --output $(W5_002_REPORTS)/grype-image.json --image-identity $(W5_002_REPORTS)/image-identity.json --scanner-database-identity $(W5_002_GRYPE_DB_IDENTITY) --scanner grype --scope oci
	powershell -NoProfile -Command "Remove-Item -LiteralPath '$(W5_002_RAW_DIR)/trivy-filesystem.json','$(W5_002_RAW_DIR)/trivy-image.json','$(W5_002_RAW_DIR)/grype-image.json' -Force -ErrorAction Stop"

w5-002-sbom:
	$(SYFT) oci-archive:$(W5_002_OCI) -o spdx-json=$(W5_002_REPORTS)/sbom.spdx.json
	$(SYFT) oci-archive:$(W5_002_OCI) -o cyclonedx-json=$(W5_002_REPORTS)/sbom.cyclonedx.json

w5-002-clean-runtime:
	docker buildx rm $(W5_002_BUILDER)
	powershell -NoProfile -Command "Remove-Item -LiteralPath '$(W5_002_OCI)' -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '$(W5_002_RAW_DIR)' -Recurse -Force -ErrorAction SilentlyContinue"
	powershell -NoProfile -Command "if (Test-Path -LiteralPath '$(W5_002_OCI)') { throw 'W5-002 OCI archive remains' }; if (Test-Path -LiteralPath '$(W5_002_RAW_DIR)') { throw 'W5-002 raw scanner directory remains' }; if (docker buildx inspect '$(W5_002_BUILDER)' 2>$$null) { throw 'W5-002 migration builder remains' }"
	$(PYTHON) -B tools/w5_002_ci.py write-cleanup-retention --output $(W5_002_REPORTS)/cleanup-retention.json

w5-002-reconcile:
	$(PYTHON) -B tools/w5_002_ci.py reconcile-supply-chain --reports-dir $(W5_002_REPORTS)
	$(PYTHON) -B tools/w5_002_ci.py validate-reports --reports-dir $(W5_002_REPORTS) --profile supply-chain

w5-002-rollback-identity:
	$(PYTHON) -B tools/w5_002_ci.py validate-report --input $(W5_002_REPORTS)/rollback-identity.json

w5-002-clean:
	docker buildx rm $(W5_002_BUILDER)
	powershell -NoProfile -Command "Remove-Item -LiteralPath '$(W5_002_OCI)' -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '$(W5_002_RAW_DIR)' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '$(W5_002_REPORTS)' -Recurse -Force -ErrorAction SilentlyContinue"

w5-002-verify-clean:
	powershell -NoProfile -Command "if (Test-Path -LiteralPath '$(W5_002_OCI)') { throw 'W5-002 OCI archive remains' }; if (Test-Path -LiteralPath '$(W5_002_RAW_DIR)') { throw 'W5-002 raw scanner directory remains' }; if (Test-Path -LiteralPath '$(W5_002_REPORTS)') { throw 'W5-002 report directory remains' }; if (docker buildx inspect '$(W5_002_BUILDER)' 2>$$null) { throw 'W5-002 migration builder remains' }"

w5-004-bootstrap-plan:
	# Intent only. Execution uses a separately bound v2 request and owner approval.
	$(PYTHON) -B -m tools.platformctl bootstrap-plan --environment sandbox --target bootstrap $(W5_004_EXECUTION_FLAGS)

w5-004-bootstrap-apply:
	$(PYTHON) -B -m tools.platformctl bootstrap-apply --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target bootstrap --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-platform-plan:
	$(PYTHON) -B -m tools.platformctl platform-plan --environment sandbox --target platform $(W5_004_EXECUTION_FLAGS)

plan-sandbox: w5-004-platform-plan

w5-004-policy-review:
	$(PYTHON) -B -m tools.platformctl policy-review --environment sandbox --target $(W5_004_TARGET) $(W5_004_EXECUTION_FLAGS)

w5-004-cost-review:
	$(PYTHON) -B -m tools.platformctl cost-review --environment sandbox --target $(W5_004_TARGET) $(W5_004_EXECUTION_FLAGS)

w5-004-platform-apply:
	$(PYTHON) -B -m tools.platformctl platform-apply --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target platform --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-aws-verify:
	$(PYTHON) -B -m tools.platformctl aws-verify --environment sandbox --target $(W5_004_TARGET) $(W5_004_EXECUTION_FLAGS)

w5-004-infrastructure-rollback:
	$(PYTHON) -B -m tools.platformctl infrastructure-rollback --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target platform --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-destroy-plan:
	$(PYTHON) -B -m tools.platformctl destroy-plan --environment sandbox --target $(W5_004_TARGET) $(W5_004_EXECUTION_FLAGS)

w5-004-purge-sandbox:
	$(PYTHON) -B -m tools.platformctl purge-sandbox --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target $(W5_004_TARGET) --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-platform-destroy:
	$(PYTHON) -B -m tools.platformctl platform-destroy --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target platform --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-bootstrap-destroy:
	$(PYTHON) -B -m tools.platformctl bootstrap-destroy --environment sandbox --aws-account-id 526338061652 --aws-region ap-southeast-1 --target bootstrap --artifact-sha256 $(W5_004_ARTIFACT_SHA256) --approval-record $(W5_004_APPROVAL) --confirmation "$(W5_004_CONFIRMATION)" --executor Gyan-Prakash-Rai $(W5_004_EXECUTION_FLAGS)

w5-004-verify-clean:
	$(PYTHON) -B -m tools.platformctl verify-clean --environment sandbox $(W5_004_EXECUTION_FLAGS)

# Thin owner launch interface; no hashes, decisions or PASS markers are synthesized here.
.PHONY: w5-004-request-help
w5-004-request-help:
	$(PYTHON) -B -m tools.platformctl platform-plan --help

w6-001-template-validate:
	$(PYTHON) -B -m tools.w6_001_k8s validate-template --template-root $(W6_001_TEMPLATE)

w6-001-policy:
	$(OPA) check --strict policies/opa
	$(OPA) test policies/opa/terraform_plan.rego policies/opa/terraform_plan_test.rego policies/opa/exceptions.json --verbose
	$(OPA) test policies/opa/kubernetes.rego policies/opa/kubernetes_test.rego --verbose

w6-001-checkov:
	$(CHECKOV) --config-file .checkov.yml -d deploy/k8s --framework kubernetes

w6-001-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w6_001_k8s.py tests/contract/test_w6_001_k8s_contract.py tests/integration/test_w6_001_kubernetes_composition.py tests/feature/test_w6_001_eks.py tests/security/test_w6_001_kubernetes_security.py tests/rollback/test_w6_001_kubernetes_rollback.py tests/teardown/test_w6_001_kubernetes_cleanliness.py

# Owner supplies the typed input and an external single-use private output root.
w6-001-release-bind:
	$(PYTHON) -B -m tools.w6_001_k8s bind-release --template-root $(W6_001_TEMPLATE) --binding $(W6_001_BINDING) --repository-root .

w6-001-release-validate:
	$(PYTHON) -B -m tools.w6_001_k8s validate-release --release-root $(W6_001_RELEASE_ROOT) --template-root $(W6_001_TEMPLATE)

w6-002-validate:
	$(PYTHON) -B -m tools.w6_002_observability validate --root .

# Owner supplies the pinned Prometheus 3.5.0 promtool binary; this target downloads nothing.
w6-002-promtool:
	$(PROMTOOL) check rules observability/alerts.yml

w6-002-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w6_002_observability.py tests/contract/test_w6_002_observability_contract.py tests/integration/test_w6_002_telemetry_composition.py tests/feature/test_failure_modes.py tests/security/test_w6_002_observability_security.py tests/rollback/test_w6_002_observability_rollback.py tests/teardown/test_w6_002_observability_cleanliness.py

w6-003-validate:
	$(PYTHON) -B -m tools.w6_003_readiness validate-config --root . --config $(W6_003_CONFIG)

w6-003-source-identity:
	$(PYTHON) -B -m tools.w6_003_readiness source-identity --root .

w6-003-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w6_003_readiness.py tests/contract/test_w6_003_readiness_contract.py tests/integration/test_w6_003_platform_composition.py tests/feature/test_w6_003_integrated_readiness.py tests/smoke/test_w6_003_local_smoke.py tests/security/test_w6_003_readiness_security.py tests/rollback/test_w6_003_local_rollback.py tests/teardown/test_w6_003_readiness_cleanliness.py

# Owner supplies the three canonical private evidence files after all local gates pass.
w6-003-evidence-validate:
	$(PYTHON) -B -m tools.w6_003_readiness validate-evidence --local-proof $(W6_003_LOCAL_PROOF) --local-rollback $(W6_003_LOCAL_ROLLBACK) --handover $(W6_003_HANDOVER)

w6-004-source-validate:
	$(PYTHON) -B -m tools.platformctl w6-004-validate-source --config $(W6_004_CONFIG)

w6-004-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w6_004_lifecycle.py tests/contract/test_w6_004_lifecycle_contract.py tests/integration/test_w6_004_platform_composition.py tests/feature/test_w6_004_full_lifecycle.py tests/smoke/test_w6_004_live_smoke.py tests/security/test_w6_004_lifecycle_security.py tests/rollback/test_w6_004_full_rollback.py tests/teardown/test_w6_004_cleanliness.py

w7-001-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w7_001_data_foundation.py tests/contract/test_w7_001_data_contract.py tests/integration/test_w7_001_ingestion_composition.py tests/feature/test_w7_001_data_platform.py tests/security/test_w7_001_data_security.py tests/rollback/test_w7_001_data_rollback.py tests/teardown/test_w7_001_data_cleanliness.py

w7-002-tests:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/unit/test_w7_002_processing.py tests/contract/test_w7_002_processing_contract.py tests/integration/test_w7_002_processing_composition.py tests/feature/test_w7_002_data_quality.py tests/security/test_w7_002_processing_security.py tests/rollback/test_w7_002_processing_rollback.py tests/teardown/test_w7_002_processing_cleanliness.py
