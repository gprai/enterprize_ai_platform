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
W5_002_CONFIG = configs/ci/w5-002.json
W5_002_REPORTS = reports/w5-002
W5_002_OCI ?= E:/AI/.runtime/enterprise_ai_platform/w5-002/owner-test-01/candidate.oci
W5_002_RAW_DIR ?= E:/AI/.runtime/enterprise_ai_platform/w5-002/owner-test-01/raw
W5_002_OCI_LAYOUT = $(W5_002_RAW_DIR)/oci-layout
W5_002_DIGEST ?= sha256:owner-must-supply-the-exact-oci-archive-digest
W5_002_SOURCE ?= owner-must-supply-the-exact-40-character-source-commit
W2_004_COMPOSE = docker compose -p enterprise-ai-w2-004a -f docker-compose.yml -f docker-compose.w2-004.yml --profile local-retrieval
W2_004_RUNNER_IMAGE = enterprise-ai-w2-004a-local_retrieval_runner:latest

.PHONY: help validate test test-unit test-integration test-feature test-smoke test-security test-teardown evaluate local-retrieval-config local-retrieval-build local-retrieval-inspect local-retrieval-up local-retrieval-ingest local-retrieval-query local-retrieval-regression rollback-local local-retrieval-remove stop-local destroy-local verify-clean-local rollback-release smoke terraform-fmt-check terraform-validate-bootstrap terraform-validate-sandbox tflint-bootstrap tflint-sandbox checkov-config checkov-terraform opa-policy-check opa-terraform-policy w5-policy-tests w5-policy-rollback bedrock-owner-dry-run w5-static-tests w5-002-validate-config w5-002-static w5-002-workflow-contract w5-002-build w5-002-scan w5-002-sbom w5-002-reconcile w5-002-clean w5-002-verify-clean

help:
	@echo "Available targets: validate, test, test-unit, test-integration, test-feature, test-smoke, test-security, test-teardown, evaluate, local-retrieval-config, local-retrieval-build, local-retrieval-inspect, local-retrieval-up, local-retrieval-ingest, local-retrieval-query, local-retrieval-regression, rollback-local, local-retrieval-remove, stop-local, destroy-local, verify-clean-local, rollback-release, smoke, terraform-fmt-check, terraform-validate-bootstrap, terraform-validate-sandbox, tflint-bootstrap, tflint-sandbox, checkov-config, checkov-terraform, opa-policy-check, opa-terraform-policy, w5-policy-tests, w5-policy-rollback, bedrock-owner-dry-run, w5-static-tests, w5-002-validate-config, w5-002-static, w5-002-workflow-contract, w5-002-build, w5-002-scan, w5-002-sbom, w5-002-reconcile, w5-002-clean, w5-002-verify-clean"

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
	$(PYTHON) -B tools/evaluationctl.py candidate --config configs/eval/w3-002.yaml --dataset configs/eval/golden.jsonl --baseline configs/eval/baselines/w3-002-v1.json --out reports/eval.json

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

w5-002-static:
	$(ACTIONLINT) .github/workflows/ci.yml .github/workflows/plan-sandbox.yml .github/workflows/security-scan.yml
	$(TERRAFORM) fmt -check -recursive infra
	$(CHECKOV) --config-file .checkov.yml -d infra
	$(OPA) check --strict policies/opa
	$(OPA) test policies/opa --verbose

w5-002-workflow-contract:
	$(PYTHON) -B -m pytest -q -p no:cacheprovider tests/contract/test_w5_002_workflow_contract.py

w5-002-build:
	docker buildx build --builder enterprise-ai-platform-w5-002 --platform linux/amd64 --file docker/application.Dockerfile --output type=oci,dest=$(W5_002_OCI) --provenance=false --sbom=false .

w5-002-scan:
	$(TRIVY) filesystem --format json --output $(W5_002_RAW_DIR)/trivy-filesystem.json --scanners vuln,secret .
	powershell -NoProfile -Command "if (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)') { throw 'W5-002 OCI layout already exists' }; New-Item -ItemType Directory -Path '$(W5_002_OCI_LAYOUT)' -ErrorAction Stop | Out-Null; try { tar.exe -xf '$(W5_002_OCI)' -C '$(W5_002_OCI_LAYOUT)'; if ($$LASTEXITCODE -ne 0) { throw 'W5-002 OCI extraction failed' }; if (-not (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)/index.json' -PathType Leaf) -or -not (Test-Path -LiteralPath '$(W5_002_OCI_LAYOUT)/oci-layout' -PathType Leaf)) { throw 'W5-002 OCI layout markers are missing' }; & '$(TRIVY)' image --input '$(W5_002_OCI_LAYOUT)' --format json --output '$(W5_002_RAW_DIR)/trivy-image.json'; if ($$LASTEXITCODE -ne 0) { throw 'W5-002 Trivy OCI scan failed' } } finally { Remove-Item -LiteralPath '$(W5_002_OCI_LAYOUT)' -Recurse -Force -ErrorAction SilentlyContinue }"
	$(GRYPE) oci-archive:$(W5_002_OCI) -o json > $(W5_002_RAW_DIR)/grype-image.json
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/trivy-filesystem.json --output $(W5_002_REPORTS)/trivy-filesystem.json --source-commit $(W5_002_SOURCE) --image-digest $(W5_002_DIGEST) --scanner trivy --scope filesystem
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/trivy-image.json --output $(W5_002_REPORTS)/trivy-image.json --source-commit $(W5_002_SOURCE) --image-digest $(W5_002_DIGEST) --scanner trivy --scope oci
	$(PYTHON) -B tools/w5_002_ci.py write-scan-summary --input $(W5_002_RAW_DIR)/grype-image.json --output $(W5_002_REPORTS)/grype-image.json --source-commit $(W5_002_SOURCE) --image-digest $(W5_002_DIGEST) --scanner grype --scope oci
	powershell -NoProfile -Command "Remove-Item -LiteralPath '$(W5_002_RAW_DIR)/trivy-filesystem.json','$(W5_002_RAW_DIR)/trivy-image.json','$(W5_002_RAW_DIR)/grype-image.json' -Force -ErrorAction Stop"

w5-002-sbom:
	$(SYFT) oci-archive:$(W5_002_OCI) -o spdx-json=$(W5_002_REPORTS)/sbom.spdx.json
	$(SYFT) oci-archive:$(W5_002_OCI) -o cyclonedx-json=$(W5_002_REPORTS)/sbom.cyclonedx.json

w5-002-reconcile:
	$(PYTHON) -B tools/w5_002_ci.py reconcile-supply-chain --reports-dir $(W5_002_REPORTS) --source-commit $(W5_002_SOURCE) --image-digest $(W5_002_DIGEST)
	$(PYTHON) -B tools/w5_002_ci.py validate-reports --reports-dir $(W5_002_REPORTS) --profile supply-chain

w5-002-clean:
	docker buildx rm enterprise-ai-platform-w5-002
	powershell -NoProfile -Command "Remove-Item -LiteralPath '$(W5_002_OCI)' -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '$(W5_002_RAW_DIR)' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '$(W5_002_REPORTS)' -Recurse -Force -ErrorAction SilentlyContinue"

w5-002-verify-clean:
	powershell -NoProfile -Command "if (Test-Path -LiteralPath '$(W5_002_OCI)') { throw 'W5-002 OCI archive remains' }; if (Test-Path -LiteralPath '$(W5_002_RAW_DIR)') { throw 'W5-002 raw scanner directory remains' }; if (Test-Path -LiteralPath '$(W5_002_REPORTS)') { throw 'W5-002 report directory remains' }; if (docker buildx ls | Select-String -SimpleMatch 'enterprise-ai-platform-w5-002') { throw 'W5-002 builder remains' }"
