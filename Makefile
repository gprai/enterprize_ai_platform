PYTHON ?= python
W2_004_COMPOSE = docker compose -p enterprise-ai-w2-004a -f docker-compose.yml -f docker-compose.w2-004.yml --profile local-retrieval
W2_004_RUNNER_IMAGE = enterprise-ai-w2-004a-local_retrieval_runner:latest

.PHONY: help validate test test-unit test-integration test-feature test-smoke test-security test-teardown evaluate local-retrieval-config local-retrieval-build local-retrieval-inspect local-retrieval-up local-retrieval-ingest local-retrieval-query local-retrieval-regression rollback-local local-retrieval-remove stop-local destroy-local verify-clean-local rollback-release smoke

help:
	@echo "Available targets: validate, test, test-unit, test-integration, test-feature, test-smoke, test-security, test-teardown, evaluate, local-retrieval-config, local-retrieval-build, local-retrieval-inspect, local-retrieval-up, local-retrieval-ingest, local-retrieval-query, local-retrieval-regression, rollback-local, local-retrieval-remove, stop-local, destroy-local, verify-clean-local, rollback-release, smoke"

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
