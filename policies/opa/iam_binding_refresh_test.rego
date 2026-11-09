package enterprise_ai.iam_refresh_test

import data.enterprise_ai.iam_refresh.allow
import rego.v1

sample := {
	"stage": "bootstrap-bind-complete",
	"source_state": {"id": "sv-exact", "serial": 25},
	"expires_at": "2026-11-01T18:00:00Z",
	"evaluation_time": "2026-11-01T12:00:00Z",
	"plan": {"terraform_version": "1.16.1", "resource_changes": [{"mode": "managed", "type": "aws_iam_policy", "change": {"actions": ["update"]}}]},
}

test_binding_update_allowed if allow with input as sample

test_create_and_destroy_denied if {
	every actions in [["create"], ["delete"], ["delete", "create"]] {
		changes := [{"mode": "managed", "type": "aws_iam_policy", "change": {"actions": actions}}]
		plan := object.union(sample.plan, {"resource_changes": changes})
		not allow with input as object.union(sample, {"plan": plan})
	}
}

test_expired_denied if {
	not allow with input as object.union(sample, {"evaluation_time": "2026-11-02T00:00:00Z"})
}

test_missing_state_denied if {
	not allow with input as object.remove(sample, {"source_state"})
}

test_foreign_stage_denied if {
	not allow with input as object.union(sample, {"stage": "base"})
}

test_unrelated_resource_denied if {
	changes := [{"mode": "managed", "type": "aws_ec2_instance", "change": {"actions": ["update"]}}]
	not allow with input as object.union(sample, {"plan": object.union(sample.plan, {"resource_changes": changes})})
}
