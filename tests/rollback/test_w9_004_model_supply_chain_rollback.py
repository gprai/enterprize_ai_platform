"""W9-004 rollback preserves the preceding registry contract."""

import inspect

from enterprise_ai_platform.model_registry.sagemaker import render_register_model_package_request
from enterprise_ai_platform.model_registry.service import ModelRegistryService


def test_w9_004_changes_do_not_expose_a_deploy_operation() -> None:
    assert not hasattr(ModelRegistryService, "deploy")
    source = inspect.getsource(render_register_model_package_request)
    assert '"submission_status": "NOT_AUTHORIZED"' in source
