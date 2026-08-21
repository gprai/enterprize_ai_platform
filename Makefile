PYTHON ?= python

.PHONY: help validate test test-unit test-integration test-feature test-smoke test-security test-teardown

help:
	@echo "Available targets: validate, test, test-unit, test-integration, test-feature, test-smoke, test-security, test-teardown"

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
