package enterprise_ai.model_supply_chain.w9_004_test

import rego.v1
import data.enterprise_ai.model_supply_chain.w9_004 as model_supply_chain

passing := {
    "status": "PASS",
    "classification": "INTERNAL",
    "deployment_approval": "NOT_AUTHORIZED",
    "inventory": {"status": "PASS"},
    "source_license": {"status": "PASS"},
    "provenance": {"status": "PASS"},
    "scanners": [
        {"status": "PASS", "critical_findings": 0},
        {"status": "PASS", "critical_findings": 0}
    ],
    "sboms": [{"status": "PASS"}, {"status": "PASS"}]
}

test_pass_evidence_is_allowed if {
    model_supply_chain.allow with input as passing
}

test_critical_finding_is_denied if {
    not model_supply_chain.allow with input as object.union(
        passing,
        {"scanners": [{"status": "FAIL", "critical_findings": 1}]}
    )
}

test_deployment_authority_is_not_inferred if {
    not model_supply_chain.allow with input as object.union(
        passing,
        {"deployment_approval": "AUTHORIZED"}
    )
}
