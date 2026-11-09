package enterprise_ai.iam_refresh

import rego.v1

# Python additionally requires exact source-template equality / binding-only deltas.
# This policy independently rejects creation, deletion, replacement and foreign types.
# It is not a general IAM policy deployment or adoption exception.
default allow := false

allow if {
	input.stage in {"bootstrap-bind-seed", "bootstrap-bind-complete"}
	input.plan.terraform_version == "1.16.1"
	regex.match("^sv-[A-Za-z0-9]+$", input.source_state.id)
	input.source_state.serial > 0
	time.parse_rfc3339_ns(input.expires_at) > time.parse_rfc3339_ns(input.evaluation_time)
	is_array(input.plan.resource_changes)
	every resource in input.plan.resource_changes {
		allowed_resource(resource)
	}
}

allowed_resource(resource) if resource.mode == "data"

allowed_resource(resource) if {
	resource.mode == "managed"
	resource.change.actions == ["no-op"]
	resource.change.before == resource.change.after
}

allowed_resource(resource) if {
	resource.mode == "managed"
	resource.change.actions == ["update"]
	resource.type in {"aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_dynamodb_table", "aws_kms_key", "aws_s3_bucket", "terraform_data"}
}
