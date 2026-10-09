package enterprise_ai.terraform.plan

import rego.v1

test_w6_004_resource_types_are_explicitly_supported if {
	every resource_type in {
		"aws_bedrock_model_invocation_logging_configuration",
		"aws_eks_cluster", "aws_eks_node_group", "aws_eks_addon",
		"aws_eks_pod_identity_association", "aws_fis_experiment_template",
		"aws_cloudwatch_metric_alarm", "aws_sns_topic",
	} {
		resource_type in supported_aws_resource_types
	}
}

test_w6_004_private_endpoint_inventory_is_exact if {
	approved_endpoint_services == {
		"com.amazonaws.ap-southeast-1.s3",
		"com.amazonaws.ap-southeast-1.dynamodb",
		"com.amazonaws.ap-southeast-1.ecr.api",
		"com.amazonaws.ap-southeast-1.ecr.dkr",
		"com.amazonaws.ap-southeast-1.eks",
		"com.amazonaws.ap-southeast-1.eks-auth",
		"com.amazonaws.ap-southeast-1.sts",
		"com.amazonaws.ap-southeast-1.logs",
		"com.amazonaws.ap-southeast-1.monitoring",
		"com.amazonaws.ap-southeast-1.ec2",
		"com.amazonaws.ap-southeast-1.xray",
		"com.amazonaws.ap-southeast-1.kms",
		"com.amazonaws.ap-southeast-1.secretsmanager",
		"com.amazonaws.ap-southeast-1.bedrock-runtime",
	}
	platform_interface_endpoint_addresses == {
		`module.network.aws_vpc_endpoint.interface["Bedrock Runtime"]`,
		`module.network.aws_vpc_endpoint.interface["CloudWatch Logs"]`,
		`module.network.aws_vpc_endpoint.interface["CloudWatch Monitoring"]`,
		`module.network.aws_vpc_endpoint.interface["EC2"]`,
		`module.network.aws_vpc_endpoint.interface["ECR API"]`,
		`module.network.aws_vpc_endpoint.interface["ECR DKR"]`,
		`module.network.aws_vpc_endpoint.interface["EKS"]`,
		`module.network.aws_vpc_endpoint.interface["EKS Auth"]`,
		`module.network.aws_vpc_endpoint.interface["KMS"]`,
		`module.network.aws_vpc_endpoint.interface["STS"]`,
		`module.network.aws_vpc_endpoint.interface["Secrets Manager"]`,
		`module.network.aws_vpc_endpoint.interface["X-Ray"]`,
	}
}

approved_tags := {
	"Project": "enterprise-ai-platform",
	"Environment": "sandbox",
	"Owner": "Gyan-Prakash-Rai",
	"ManagedBy": "terraform",
	"CostCenter": "Personal-Learning",
	"Feature": "MVP-001",
	"ExpiresAt": "2026-09-04T01:00:00Z",
	"Repository": "enterprise-ai-platform",
}

approved_context := {
	"evaluation_time": "2026-09-04T00:00:00Z",
	"policy_ids": policy_order,
}

safe_anchor := {
	"address": "aws_route_table_association.private[0]",
	"type": "aws_route_table_association",
	"change": {
		"actions": ["create"],
		"after": {"route_table_id": "rtb-synthetic", "subnet_id": "subnet-synthetic"},
	},
}

owner_expiry_gate := {
	"address": "terraform_data.owner_expiry_gate",
	"type": "terraform_data",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"input": "2026-09-04T01:00:00Z",
			"store": null,
			"triggers_replace": null,
		},
		"after_unknown": {"id": true, "output": true},
		"after_sensitive": {},
	},
}

w6_004_runtime_gate := {
	"address": "terraform_data.w6_004_runtime_gate[0]",
	"type": "terraform_data",
	"change": {
		"actions": ["create"],
		"before": null,
		"before_sensitive": {},
		"after": {
			"input": {
				"approval_issued_at": "2026-09-04T00:00:00Z",
				"deployment_start": "2026-09-04T00:00:00Z",
				"approval_expires_at": "2026-09-04T08:00:00Z",
			},
			"store": null,
			"triggers_replace": null,
		},
		"after_sensitive": {"input": {}, "output": {}},
		"after_unknown": {"id": true, "input": {}, "output": true},
	},
}

w6_004_node_attachment := {
	"address": `module.eks[0].aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]`,
	"type": "aws_iam_role_policy_attachment",
	"change": {
		"actions": ["create"],
		"before": null,
		"before_sensitive": {},
		"after": {
			"policy_arn": "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
			"role": "enterprise-ai-sandbox-node",
		},
		"after_sensitive": {},
		"after_unknown": {"id": true},
	},
}

w6_004_alert_subscription := {
	"address": `module.observability[0].aws_sns_topic_subscription.email["vayunetrix.aws.dev@zohomail.com"]`,
	"type": "aws_sns_topic_subscription",
	"change": {
		"actions": ["create"],
		"before": null,
		"before_sensitive": {},
		"after": {
			"confirmation_timeout_in_minutes": 1,
			"delivery_policy": null,
			"endpoint": "vayunetrix.aws.dev@zohomail.com",
			"endpoint_auto_confirms": false,
			"filter_policy": null,
			"protocol": "email",
			"raw_message_delivery": false,
			"redrive_policy": null,
			"region": "ap-southeast-1",
			"replay_policy": null,
			"subscription_role_arn": null,
		},
		"after_sensitive": {},
		"after_unknown": {"arn": true, "confirmation_was_authenticated": true, "filter_policy_scope": true, "id": true, "owner_id": true, "pending_confirmation": true, "topic_arn": true},
	},
}

approved_plan := {
	"format_version": "1.2",
	"terraform_version": "1.16.1",
	"variables": {"aws_region": {"value": "ap-southeast-1"}},
	"evaluation_context": approved_context,
	"resource_changes": [safe_anchor],
}

change(address, resource_type, values) := {
	"address": address,
	"type": resource_type,
	"change": {"actions": ["create"], "after": values},
}

plan_with_changes(changes) := object.union(approved_plan, {"resource_changes": changes})

findings_for(plan) := result if {
	result := findings with input as plan
}

policy_ids_for(plan) := {finding.policy_id | some finding in findings_for(plan)}

approved_kms_values := {
	"enable_key_rotation": true,
	"deletion_window_in_days": 7,
	"tags_all": approved_tags,
}

approved_ecr_values := {
	"image_tag_mutability": "IMMUTABLE",
	"image_scanning_configuration": [{"scan_on_push": true}],
	"encryption_configuration": [{"encryption_type": "KMS", "kms_key": "kms-synthetic"}],
	"tags_all": approved_tags,
}

approved_opensearch_security := {
	"vpc_options": [{"subnet_ids": ["subnet-synthetic"]}],
	"encrypt_at_rest": [{"enabled": true, "kms_key_id": "kms-synthetic"}],
	"node_to_node_encryption": [{"enabled": true}],
	"domain_endpoint_options": [{
		"enforce_https": true,
		"tls_security_policy": "Policy-Min-TLS-1-2-2019-07",
	}],
	"tags_all": approved_tags,
}

opensearch_sensitive_metadata := {
	"address": opensearch_domain_address,
	"type": "aws_opensearch_domain",
	"field_path": opensearch_password_field_path,
	"relationship": opensearch_sensitive_relationship,
	"source_address": opensearch_admin_role_address,
}

opensearch_role_change := {
	"address": opensearch_admin_role_address,
	"type": "aws_iam_role",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"name": "approved-role"},
		"after_unknown": {"arn": true},
		"after_sensitive": {},
	},
}

opensearch_domain_change := {
	"address": opensearch_domain_address,
	"type": "aws_opensearch_domain",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"advanced_security_options": [{
			"enabled": true,
			"internal_user_database_enabled": false,
			"master_user_options": [{
				"master_user_arn": null,
				"master_user_name": null,
			}],
		}]},
		"after_unknown": {"advanced_security_options": [{"master_user_options": [{"master_user_arn": true}]}]},
		"after_sensitive": {"advanced_security_options": [{"master_user_options": [{}]}]},
	},
}

opensearch_sensitive_metadata_plan := object.union(approved_plan, {
	"evaluation_context": object.union(approved_context, {"provider_sensitive_nulls": [opensearch_sensitive_metadata]}),
	"resource_changes": [opensearch_role_change, opensearch_domain_change],
})

opensearch_existing_sensitive_metadata := object.union(opensearch_sensitive_metadata, {"relationship": opensearch_existing_sensitive_relationship})

opensearch_existing_role_arn := "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-opensearch-admin"
opensearch_existing_trust_policy := `{"Statement":[],"Version":"2012-10-17"}`
opensearch_existing_previous_tags := object.union(approved_tags, {"ExpiresAt": "2026-09-03T23:00:00Z"})

opensearch_existing_role_before := {
	"arn": opensearch_existing_role_arn,
	"assume_role_policy": opensearch_existing_trust_policy,
	"name": "approved-role",
	"tags": opensearch_existing_previous_tags,
	"tags_all": opensearch_existing_previous_tags,
}

opensearch_existing_role_after := object.union(opensearch_existing_role_before, {
	"tags": approved_tags,
	"tags_all": approved_tags,
})

opensearch_existing_role_change := {
	"address": opensearch_admin_role_address,
	"type": "aws_iam_role",
	"change": {
		"actions": ["update"],
		"before": opensearch_existing_role_before,
		"after": opensearch_existing_role_after,
		"after_unknown": {},
		"after_sensitive": {},
	},
}

opensearch_existing_domain_change := object.union(opensearch_domain_change, {"change": object.union(opensearch_domain_change.change, {
	"after": {"advanced_security_options": [{
		"enabled": true,
		"internal_user_database_enabled": false,
		"master_user_options": [{
			"master_user_arn": opensearch_existing_role_arn,
			"master_user_name": null,
		}],
	}]},
	"after_unknown": {"advanced_security_options": [{"master_user_options": [{}]}]},
})})

opensearch_existing_sensitive_metadata_plan := object.union(approved_plan, {
	"evaluation_context": object.union(approved_context, {"provider_sensitive_nulls": [opensearch_existing_sensitive_metadata]}),
	"resource_changes": [
		opensearch_existing_role_change,
		opensearch_existing_domain_change,
		recovery_expiry_change,
	],
})

bootstrap_bucket_address := "aws_s3_bucket.terraform_state"
bootstrap_encryption_address := "aws_s3_bucket_server_side_encryption_configuration.terraform_state"
bootstrap_kms_address := "aws_kms_key.terraform_state"
bootstrap_policy_address := "aws_s3_bucket_policy.terraform_state_tls"

bootstrap_s3_context := object.union(approved_context, {
	"provider_computed_unknowns": [{
		"address": bootstrap_encryption_address,
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"unknown_paths": ["rule[].apply_server_side_encryption_by_default[].kms_master_key_id"],
	}],
	"s3_bucket_policy_bindings": [{
		"bucket_address": bootstrap_bucket_address,
		"policy_address": bootstrap_policy_address,
	}],
	"s3_kms_encryption_bindings": [{
		"bucket_address": bootstrap_bucket_address,
		"encryption_address": bootstrap_encryption_address,
		"kms_key_address": bootstrap_kms_address,
		"field_path": "rule[].apply_server_side_encryption_by_default[].kms_master_key_id",
	}],
})

bootstrap_s3_changes := [
	change(
		bootstrap_bucket_address,
		"aws_s3_bucket",
		{"bucket": "approved-bucket", "tags_all": approved_tags},
	),
	change(
		"aws_s3_bucket_public_access_block.terraform_state",
		"aws_s3_bucket_public_access_block",
		{
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	),
	change(
		bootstrap_encryption_address,
		"aws_s3_bucket_server_side_encryption_configuration",
		{"rule": [{
			"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
			"bucket_key_enabled": true,
		}]},
	),
	change(
		"aws_s3_bucket_versioning.terraform_state",
		"aws_s3_bucket_versioning",
		{"versioning_configuration": [{"status": "Enabled"}]},
	),
	change(
		"aws_s3_bucket_lifecycle_configuration.terraform_state",
		"aws_s3_bucket_lifecycle_configuration",
		{"rule": [{"abort_incomplete_multipart_upload": [{"days_after_initiation": 7}]}]},
	),
	change(
		bootstrap_policy_address,
		"aws_s3_bucket_policy",
		{"policy": `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`},
	),
	change(
		bootstrap_kms_address,
		"aws_kms_key",
		approved_kms_values,
	),
]

bootstrap_s3_plan := object.union(approved_plan, {
	"evaluation_context": bootstrap_s3_context,
	"resource_changes": bootstrap_s3_changes,
})

previous_tags := object.union(approved_tags, {"ExpiresAt": "2026-09-03T23:00:00Z"})

bootstrap_kms_policy_before := {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "AllowExactAccountStateCryptography",
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::526338061652:root"},
		"Action": ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt"],
		"Resource": "*",
	}],
}

bootstrap_kms_policy_after := object.union(bootstrap_kms_policy_before, {"Statement": array.concat(
	bootstrap_kms_policy_before.Statement,
	[approved_dynamodb_grant_statement],
)})

normalized_no_op(address, resource_type, values) := {
	"address": address,
	"type": resource_type,
	"change": {
		"actions": ["no-op"],
		"before": values,
		"after": values,
		"after_unknown": {},
		"after_sensitive": {},
	},
}

normalized_update(address, resource_type, before_values, after_values) := {
	"address": address,
	"type": resource_type,
	"change": {
		"actions": ["update"],
		"before": before_values,
		"after": after_values,
		"after_unknown": {},
		"after_sensitive": {},
	},
}

recovery_kms_before := {
	"description": "W5 sandbox Terraform state encryption",
	"enable_key_rotation": true,
	"deletion_window_in_days": 7,
	"policy": json.marshal(bootstrap_kms_policy_before),
	"tags": previous_tags,
	"tags_all": previous_tags,
}

recovery_kms_after(statement) := object.union(recovery_kms_before, {
	"policy": json.marshal(object.union(bootstrap_kms_policy_before, {"Statement": array.concat(bootstrap_kms_policy_before.Statement, [statement])})),
	"tags": approved_tags,
	"tags_all": approved_tags,
})

recovery_kms_change(statement) := normalized_update(
	bootstrap_recovery_kms_address,
	"aws_kms_key",
	recovery_kms_before,
	recovery_kms_after(statement),
)

recovery_bucket_before := {
	"bucket": "enterprise-ai-platform-sandbox-tfstate-526338061652-ap-southeast-1",
	"force_destroy": false,
	"policy": "",
	"tags": previous_tags,
	"tags_all": previous_tags,
}

recovery_bucket_after := object.union(recovery_bucket_before, {
	"tags": approved_tags,
	"tags_all": approved_tags,
})

recovery_bucket_change := normalized_update(
	bootstrap_recovery_bucket_address,
	"aws_s3_bucket",
	recovery_bucket_before,
	recovery_bucket_after,
)

recovery_expiry_change := {
	"address": bootstrap_recovery_expiry_address,
	"type": "terraform_data",
	"change": {
		"actions": ["update"],
		"before": {
			"id": "owner-expiry-gate-id",
			"input": previous_tags.ExpiresAt,
			"output": previous_tags.ExpiresAt,
			"store": null,
			"triggers_replace": null,
		},
		"after": {
			"id": "owner-expiry-gate-id",
			"input": approved_tags.ExpiresAt,
			"store": null,
			"triggers_replace": null,
		},
		"after_unknown": {"output": true},
		"after_sensitive": {},
	},
}

recovery_dynamodb_values := {
	"attribute": [{"name": "LockID", "type": "S"}],
	"billing_mode": "PAY_PER_REQUEST",
	"hash_key": "LockID",
	"point_in_time_recovery": [{"enabled": true}],
	"server_side_encryption": [{
		"enabled": true,
		"kms_key_arn": "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-2222-3333-4444-555555555555",
	}],
	"tags": approved_tags,
	"tags_all": approved_tags,
}

recovery_dynamodb_change := {
	"address": bootstrap_recovery_dynamodb_address,
	"type": "aws_dynamodb_table",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": recovery_dynamodb_values,
		"after_unknown": {},
		"after_sensitive": {},
	},
}

recovery_supporting_changes := [
	normalized_no_op(
		"aws_s3_bucket_public_access_block.terraform_state",
		"aws_s3_bucket_public_access_block",
		{
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	),
	normalized_no_op(
		bootstrap_encryption_address,
		"aws_s3_bucket_server_side_encryption_configuration",
		{"rule": [{
			"apply_server_side_encryption_by_default": [{
				"kms_master_key_id": "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-2222-3333-4444-555555555555",
				"sse_algorithm": "aws:kms",
			}],
			"bucket_key_enabled": true,
		}]},
	),
	normalized_no_op(
		"aws_s3_bucket_versioning.terraform_state",
		"aws_s3_bucket_versioning",
		{"versioning_configuration": [{"status": "Enabled"}]},
	),
	normalized_no_op(
		"aws_s3_bucket_lifecycle_configuration.terraform_state",
		"aws_s3_bucket_lifecycle_configuration",
		{"rule": [{"abort_incomplete_multipart_upload": [{"days_after_initiation": 7}]}]},
	),
	normalized_no_op(
		bootstrap_policy_address,
		"aws_s3_bucket_policy",
		{"policy": `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`},
	),
]

recovery_plan(kms_change, bucket_change, expiry_change, dynamodb_change, extras) := object.union(
	approved_plan,
	{
		"evaluation_context": object.union(approved_context, {
			"s3_bucket_policy_bindings": [{
				"bucket_address": bootstrap_recovery_bucket_address,
				"policy_address": bootstrap_policy_address,
			}],
			"s3_kms_encryption_bindings": [],
		}),
		"resource_changes": array.concat(
			[dynamodb_change, kms_change, bucket_change, expiry_change],
			array.concat(recovery_supporting_changes, extras),
		),
	},
)

approved_recovery_plan := recovery_plan(
	recovery_kms_change(approved_dynamodb_grant_statement),
	recovery_bucket_change,
	recovery_expiry_change,
	recovery_dynamodb_change,
	[],
)

normalized_create(address, resource_type, after_values) := {
	"address": address,
	"type": resource_type,
	"change": {
		"actions": ["create"],
		"before": null,
		"after": after_values,
		"after_unknown": {},
		"after_sensitive": {},
	},
}

platform_recovery_create_changes := [
normalized_create(address, resource_type, {}) |
	some address, resource_type in platform_recovery_create_resources
]

platform_recovery_update_changes := [
normalized_update(
	address,
	resource_type,
	{"tags": previous_tags, "tags_all": previous_tags},
	{"tags": approved_tags, "tags_all": approved_tags},
) |
	some address, resource_type in platform_recovery_update_resources
	address != bootstrap_recovery_expiry_address
	address != platform_runtime_policy_address
]

runtime_policy_document(expires_at) := {
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "InvokeExactGlobalInferenceProfile",
			"Effect": "Allow",
			"Action": "bedrock:InvokeModel",
			"Resource": "arn:aws:bedrock:ap-southeast-1:526338061652:inference-profile/global.amazon.nova-2-lite-v1:0",
			"Condition": {
				"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"},
				"DateLessThan": {"aws:CurrentTime": expires_at},
				"StringEquals": {
					"aws:PrincipalAccount": "526338061652",
					"aws:RequestedRegion": "ap-southeast-1",
				},
			},
		},
		{
			"Sid": "InvokeExactGlobalInferenceProfileRegionalModel",
			"Effect": "Allow",
			"Action": "bedrock:InvokeModel",
			"Resource": "arn:aws:bedrock:ap-southeast-1::foundation-model/amazon.nova-2-lite-v1:0",
			"Condition": {
				"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"},
				"DateLessThan": {"aws:CurrentTime": expires_at},
				"StringEquals": {
					"aws:PrincipalAccount": "526338061652",
					"aws:RequestedRegion": "ap-southeast-1",
					"bedrock:InferenceProfileArn": "arn:aws:bedrock:ap-southeast-1:526338061652:inference-profile/global.amazon.nova-2-lite-v1:0",
				},
			},
		},
		{
			"Sid": "InvokeExactGlobalInferenceProfileGlobalModel",
			"Effect": "Allow",
			"Action": "bedrock:InvokeModel",
			"Resource": "arn:aws:bedrock:::foundation-model/amazon.nova-2-lite-v1:0",
			"Condition": {
				"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"},
				"DateLessThan": {"aws:CurrentTime": expires_at},
				"StringEquals": {
					"aws:PrincipalAccount": "526338061652",
					"aws:RequestedRegion": "unspecified",
					"bedrock:InferenceProfileArn": "arn:aws:bedrock:ap-southeast-1:526338061652:inference-profile/global.amazon.nova-2-lite-v1:0",
				},
			},
		},
		{
			"Sid": "RuntimeReadPlatformObjects",
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::enterprise-ai-platform-sandbox/*",
		},
	],
}

platform_runtime_policy_recovery_change := normalized_update(
	platform_runtime_policy_address,
	"aws_iam_role_policy",
	{
		"name": "enterprise-ai-sandbox-runtime",
		"policy": json.marshal(runtime_policy_document(previous_tags.ExpiresAt)),
		"role": "enterprise-ai-sandbox-runtime",
	},
	{
		"name": "enterprise-ai-sandbox-runtime",
		"policy": json.marshal(runtime_policy_document(approved_tags.ExpiresAt)),
		"role": "enterprise-ai-sandbox-runtime",
	},
)

approved_platform_recovery_plan := object.union(approved_plan, {"resource_changes": array.concat(
	platform_recovery_create_changes,
	array.concat(
		platform_recovery_update_changes,
		[platform_runtime_policy_recovery_change, recovery_expiry_change],
	),
)})

platform_recovery_without_address(address) := object.union(
	approved_platform_recovery_plan,
	{"resource_changes": [
	change |
		some change in approved_platform_recovery_plan.resource_changes
		change.address != address
	]},
)

platform_recovery_replacing(address, replacement) := object.union(
	approved_platform_recovery_plan,
	{"resource_changes": array.concat(
		[
		change |
			some change in approved_platform_recovery_plan.resource_changes
			change.address != address
		],
		[replacement],
	)},
)

active_exception(policy_id, resource_address) := {
	"exception_id": "W5-EXC-OWNER-001",
	"policy_id": policy_id,
	"resource_addresses": [resource_address],
	"owner": "Gyan Prakash Rai",
	"approver": "Gyan Prakash Rai",
	"rationale": "Bounded synthetic owner review",
	"evidence_reference": "W5-003-owner-review",
	"issued_at": "2026-09-03T23:00:00Z",
	"expires_at": "2026-09-05T00:00:00Z",
	"status": "ACTIVE",
}

test_approved_inline_plan_has_no_denials if {
	count(findings_for(approved_plan)) == 0
}

test_wrong_region_is_denied if {
	plan := object.union(approved_plan, {"variables": {"aws_region": {"value": "us-east-1"}}})
	policy_ids_for(plan) == {"W5-REG-001"}
}

test_public_subnet_is_denied if {
	subnet := change(
		"aws_subnet.public",
		"aws_subnet",
		{"map_public_ip_on_launch": true, "tags_all": approved_tags},
	)
	policy_ids_for(plan_with_changes([subnet])) == {"W5-NET-001"}
}

test_nat_gateway_is_denied if {
	gateway := change("aws_nat_gateway.unapproved", "aws_nat_gateway", {})
	policy_ids_for(plan_with_changes([gateway])) == {"W5-NET-001"}
}

test_missing_mandatory_tag_is_denied if {
	values := object.union(
		object.remove(approved_kms_values, {"tags_all"}),
		{"tags_all": object.remove(approved_tags, {"Owner"})},
	)
	key := change("aws_kms_key.invalid", "aws_kms_key", values)
	policy_ids_for(plan_with_changes([key])) == {"W5-TAG-001"}
}

test_unencrypted_ecr_is_denied if {
	values := object.union(approved_ecr_values, {"encryption_configuration": [{"encryption_type": "AES256"}]})
	repository := change("aws_ecr_repository.invalid", "aws_ecr_repository", values)
	policy_ids_for(plan_with_changes([repository])) == {"W5-ECR-001"}
}

test_exact_policy_inventory_order_and_severity if {
	policy_order == [
		"W5-PLAN-001",
		"W5-REG-001",
		"W5-TAG-001",
		"W5-TAG-002",
		"W5-PLAN-002",
		"W5-S3-001",
		"W5-S3-002",
		"W5-S3-003",
		"W5-S3-004",
		"W5-KMS-001",
		"W5-IAM-001",
		"W5-IAM-002",
		"W5-NET-001",
		"W5-NET-002",
		"W5-OS-001",
		"W5-OS-002",
		"W5-ECR-001",
		"W5-ECR-002",
		"W5-SEC-001",
		"W5-EXC-001",
	]
	count({entry.policy_id | some entry in policy_inventory; entry.severity == "CRITICAL"}) == 14
	count({entry.policy_id | some entry in policy_inventory; entry.severity == "HIGH"}) == 6
}

test_malformed_or_empty_input_fails_closed if {
	policy_ids_for({}) == {"W5-PLAN-001"}
}

test_genuine_noop_plan_is_valid if {
	plan := object.union(approved_plan, {"resource_changes": []})
	count(findings_for(plan)) == 0
}

test_missing_context_fails_closed if {
	plan := object.remove(approved_plan, {"evaluation_context"})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_unsupported_aws_change_fails_closed if {
	unsupported := change("aws_lambda_function.unapproved", "aws_lambda_function", {})
	policy_ids_for(plan_with_changes([unsupported])) == {"W5-PLAN-001"}
}

test_unknown_after_value_fails_closed if {
	body := object.union(safe_anchor.change, {"after_unknown": {"subnet_id": true}})
	change_with_unknown := object.union(safe_anchor, {"change": body})
	policy_ids_for(plan_with_changes([change_with_unknown])) == {"W5-PLAN-001"}
}

test_duplicate_resource_change_addresses_fail_closed if {
	policy_ids_for(plan_with_changes([safe_anchor, safe_anchor])) == {"W5-PLAN-001"}
}

test_exact_module_resource_reference_binding_satisfies_input_contract if {
	vpc := change(
		"module.network.aws_vpc.this",
		"aws_vpc",
		{
			"enable_dns_support": true,
			"enable_dns_hostnames": true,
			"tags_all": approved_tags,
		},
	)
	consumer := change(
		"module.network.aws_default_security_group.restricted",
		"aws_default_security_group",
		{"ingress": [], "egress": [], "tags_all": approved_tags},
	)
	context := object.union(approved_context, {"resource_reference_unknowns": [{
		"address": consumer.address,
		"type": consumer.type,
		"unknown_paths": ["vpc_id"],
		"source_addresses": [vpc.address],
		"relationship": "network-vpc-reference",
	}]})
	plan := object.union(
		plan_with_changes([vpc, consumer]),
		{"evaluation_context": context},
	)
	not "W5-PLAN-001" in policy_ids_for(plan)
}

test_exact_ecr_kms_reference_binding_is_structurally_valid if {
	source := {
		"address": platform_kms_address,
		"type": "aws_kms_key",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": approved_kms_values,
			"after_unknown": {"arn": true},
			"after_sensitive": {},
		},
	}
	values := object.union(approved_ecr_values, {"encryption_configuration": [{"encryption_type": "KMS", "kms_key": null}]})
	repository := change("module.ecr.aws_ecr_repository.this", "aws_ecr_repository", values)
	binding := {
		"address": repository.address,
		"type": repository.type,
		"unknown_paths": ["encryption_configuration[].kms_key"],
		"source_addresses": [source.address],
		"relationship": "platform-ecr-kms-key-reference",
	}
	context := object.union(approved_context, {"resource_reference_unknowns": [binding]})
	plan := object.union(plan_with_changes([source, repository]), {"evaluation_context": context})

	valid_resource_reference_unknown(binding) with input as plan
	ecr_security_valid(repository) with input as plan
}

test_forged_ecr_kms_reference_source_fails_closed if {
	source := {
		"address": platform_kms_address,
		"type": "aws_kms_key",
		"change": {
			"actions": ["no-op"],
			"before": approved_kms_values,
			"after": approved_kms_values,
			"after_unknown": {"arn": true},
			"after_sensitive": {},
		},
	}
	repository := change(
		"module.ecr.aws_ecr_repository.this",
		"aws_ecr_repository",
		object.union(approved_ecr_values, {"encryption_configuration": [{"encryption_type": "KMS", "kms_key": null}]}),
	)
	binding := {
		"address": repository.address,
		"type": repository.type,
		"unknown_paths": ["encryption_configuration[].kms_key"],
		"source_addresses": [source.address],
		"relationship": "platform-ecr-kms-key-reference",
	}
	context := object.union(approved_context, {"resource_reference_unknowns": [binding]})
	plan := object.union(plan_with_changes([source, repository]), {"evaluation_context": context})

	not valid_resource_reference_unknown(binding) with input as plan
}

test_null_ecr_kms_key_without_binding_fails_security_contract if {
	repository := change(
		"module.ecr.aws_ecr_repository.this",
		"aws_ecr_repository",
		object.union(approved_ecr_values, {"encryption_configuration": [{"encryption_type": "KMS", "kms_key": null}]}),
	)

	not ecr_security_valid(repository) with input as plan_with_changes([repository])
}

test_exact_opensearch_log_reference_binding_is_structurally_valid if {
	sources := [{
		"address": address,
		"type": "aws_cloudwatch_log_group",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"kms_key_id": "kms-approved", "retention_in_days": 30},
			"after_unknown": {"arn": true},
			"after_sensitive": {},
		},
	} |
		some address in platform_log_group_addresses
	]
	options := [{
		"enabled": true,
		"log_type": log_type,
		"cloudwatch_log_group_arn": null,
	} |
		some log_type in approved_log_types
	]
	values := object.union(approved_opensearch_security, {
		"access_policies": `{"Statement":[{"Principal":{"AWS":"526338061652"}}]}`,
		"log_publishing_options": options,
	})
	domain := change(opensearch_domain_address, "aws_opensearch_domain", values)
	binding := {
		"address": domain.address,
		"type": domain.type,
		"unknown_paths": ["log_publishing_options[].cloudwatch_log_group_arn"],
		"source_addresses": sort([address | some address in platform_log_group_addresses]),
		"relationship": "opensearch-log-groups-reference",
	}
	context := object.union(approved_context, {"resource_reference_unknowns": [binding]})
	plan := object.union(
		plan_with_changes(array.concat(sources, [domain])),
		{"evaluation_context": context},
	)

	valid_resource_reference_unknown(binding) with input as plan
	opensearch_logs_valid(domain) with input as plan
}

test_incomplete_opensearch_log_reference_binding_fails_closed if {
	sources := [{
		"address": address,
		"type": "aws_cloudwatch_log_group",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"kms_key_id": "kms-approved", "retention_in_days": 30},
			"after_unknown": {"arn": true},
			"after_sensitive": {},
		},
	} |
		some address in platform_log_group_addresses
	]
	domain := change(opensearch_domain_address, "aws_opensearch_domain", approved_opensearch_security)
	binding := {
		"address": domain.address,
		"type": domain.type,
		"unknown_paths": ["log_publishing_options[].cloudwatch_log_group_arn"],
		"source_addresses": [`module.opensearch.aws_cloudwatch_log_group.this["application"]`],
		"relationship": "opensearch-log-groups-reference",
	}
	context := object.union(approved_context, {"resource_reference_unknowns": [binding]})
	plan := object.union(
		plan_with_changes(array.concat(sources, [domain])),
		{"evaluation_context": context},
	)

	not valid_resource_reference_unknown(binding) with input as plan
}

test_null_opensearch_log_arn_without_binding_fails_operations_contract if {
	options := [{
		"enabled": true,
		"log_type": log_type,
		"cloudwatch_log_group_arn": null,
	} |
		some log_type in approved_log_types
	]
	values := object.union(approved_opensearch_security, {
		"access_policies": `{"Statement":[{"Principal":{"AWS":"526338061652"}}]}`,
		"log_publishing_options": options,
	})
	domain := change(opensearch_domain_address, "aws_opensearch_domain", values)

	not opensearch_logs_valid(domain) with input as plan_with_changes([domain])
}

test_exact_policy_document_binding_satisfies_input_contract if {
	policy := change(
		"module.iam.aws_iam_role_policy.runtime",
		"aws_iam_role_policy",
		{"policy": null},
	)
	data_change := {
		"address": "module.iam.data.aws_iam_policy_document.runtime",
		"type": "aws_iam_policy_document",
		"change": {
			"actions": ["read"],
			"before": null,
			"after": {},
			"after_unknown": {"json": true},
			"after_sensitive": {},
		},
	}
	binding := {
		"resource_address": policy.address,
		"resource_type": policy.type,
		"field_path": "policy",
		"policy_document_address": data_change.address,
		"relationship": "exact-policy-document",
	}
	context := object.union(approved_context, {"policy_document_bindings": [binding]})
	plan := object.union(
		plan_with_changes([policy, data_change]),
		{"evaluation_context": context},
	)
	not "W5-PLAN-001" in policy_ids_for(plan)
}

test_all_real_plan_policy_document_relationships_are_exactly_allowlisted if {
	expected := {
		{
			"resource_address": "module.iam.aws_iam_role.runtime",
			"resource_type": "aws_iam_role",
			"field_path": "assume_role_policy",
			"policy_document_address": "module.iam.data.aws_iam_policy_document.runtime_trust",
			"relationship": "exact-policy-document",
		},
		{
			"resource_address": "module.iam.aws_iam_role.ingestion",
			"resource_type": "aws_iam_role",
			"field_path": "assume_role_policy",
			"policy_document_address": "module.iam.data.aws_iam_policy_document.ingestion_trust",
			"relationship": "exact-policy-document",
		},
		{
			"resource_address": "module.iam.aws_iam_role.opensearch_administrator",
			"resource_type": "aws_iam_role",
			"field_path": "assume_role_policy",
			"policy_document_address": "module.iam.data.aws_iam_policy_document.administrator_trust",
			"relationship": "exact-policy-document",
		},
		{
			"resource_address": "module.iam.aws_iam_role.github_oidc",
			"resource_type": "aws_iam_role",
			"field_path": "assume_role_policy",
			"policy_document_address": "module.iam.data.aws_iam_policy_document.github_trust",
			"relationship": "exact-policy-document",
		},
		{
			"resource_address": "module.opensearch.aws_opensearch_domain.this",
			"resource_type": "aws_opensearch_domain",
			"field_path": "access_policies",
			"policy_document_address": "module.opensearch.data.aws_iam_policy_document.domain_access",
			"relationship": "exact-policy-document",
		},
		{
			"resource_address": "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
			"resource_type": "aws_cloudwatch_log_resource_policy",
			"field_path": "policy_document",
			"policy_document_address": "module.opensearch.data.aws_iam_policy_document.log_delivery",
			"relationship": "exact-policy-document",
		},
	}
	every relationship in expected {
		relationship in platform_policy_document_relationships
	}
}

test_allowlisted_interface_endpoint_address_with_spaces_is_valid_plan_input if {
	endpoint := change(
		`module.network.aws_vpc_endpoint.interface["Bedrock Runtime"]`,
		"aws_vpc_endpoint",
		{"vpc_endpoint_type": "Interface"},
	)
	not "W5-PLAN-001" in policy_ids_for(plan_with_changes([endpoint]))
}

test_unlisted_interface_endpoint_address_with_spaces_fails_closed if {
	endpoint := change(
		`module.network.aws_vpc_endpoint.interface["Unapproved Service"]`,
		"aws_vpc_endpoint",
		{"vpc_endpoint_type": "Interface"},
	)
	"W5-PLAN-001" in policy_ids_for(plan_with_changes([endpoint]))
}

test_altered_module_binding_fails_closed if {
	source := change("module.network.aws_vpc.other", "aws_vpc", {})
	consumer := change(
		"module.network.aws_default_security_group.restricted",
		"aws_default_security_group",
		{"ingress": [], "egress": []},
	)
	context := object.union(approved_context, {"resource_reference_unknowns": [{
		"address": consumer.address,
		"type": consumer.type,
		"unknown_paths": ["vpc_id"],
		"source_addresses": [source.address],
		"relationship": "network-vpc-reference",
	}]})
	plan := object.union(
		plan_with_changes([source, consumer]),
		{"evaluation_context": context},
	)
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_unbound_or_duplicate_structural_context_fails_closed if {
	invalid_provider := {
		"address": `module.network.aws_vpc_endpoint.interface["EKS"]`,
		"type": "aws_vpc_endpoint",
		"unknown_paths": ["policy", "vpc_id"],
	}
	context := object.union(approved_context, {"provider_computed_unknowns": [invalid_provider, invalid_provider]})
	plan := object.union(approved_plan, {"evaluation_context": context})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_non_policy_critical_computed_id_is_allowed if {
	body := object.union(safe_anchor.change, {"after_unknown": {"id": true}})
	computed_change := object.union(safe_anchor, {"change": body})
	count(findings_for(plan_with_changes([computed_change]))) == 0
}

test_exact_owner_expiry_gate_is_allowed if {
	count(findings_for(plan_with_changes([safe_anchor, owner_expiry_gate]))) == 0
}

test_w6_004_runtime_gate_is_exactly_allowed if {
	valid_w6_004_runtime_gate_change(w6_004_runtime_gate)

	invalid := object.union(w6_004_runtime_gate, {"change": object.union(w6_004_runtime_gate.change, {"after": object.union(w6_004_runtime_gate.change.after, {"input": object.union(w6_004_runtime_gate.change.after.input, {"approval_expires_at": "2026-09-05T00:00:01Z"})})})})
	not valid_w6_004_runtime_gate_change(invalid)
}

test_w6_004_node_attachment_is_exactly_allowed if {
	valid_w6_004_node_policy_attachment(w6_004_node_attachment)
	invalid := object.union(w6_004_node_attachment, {"change": object.union(w6_004_node_attachment.change, {"after": object.union(w6_004_node_attachment.change.after, {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})})})
	not valid_w6_004_node_policy_attachment(invalid)
}

test_w6_004_alert_subscription_is_exactly_allowed if {
	valid_w6_004_alert_subscription(w6_004_alert_subscription)
	invalid := object.union(w6_004_alert_subscription, {"change": object.union(w6_004_alert_subscription.change, {"after": object.union(w6_004_alert_subscription.change.after, {"protocol": "sms"})})})
	not valid_w6_004_alert_subscription(invalid)
}

test_other_terraform_data_resource_fails_closed if {
	invalid := object.union(owner_expiry_gate, {"address": "terraform_data.unapproved"})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_module_prefixed_owner_expiry_gate_fails_closed if {
	invalid := object.union(owner_expiry_gate, {"address": "module.bootstrap.terraform_data.owner_expiry_gate"})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_wrong_type_fails_closed if {
	invalid := object.union(owner_expiry_gate, {"type": "aws_route_table_association"})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_update_fails_closed if {
	body := object.union(owner_expiry_gate.change, {"actions": ["update"]})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_expired_timestamp_fails_closed if {
	values := object.union(owner_expiry_gate.change.after, {"input": "2026-09-03T23:59:59Z"})
	body := object.union(owner_expiry_gate.change, {"after": values})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_excessive_timestamp_fails_closed if {
	values := object.union(owner_expiry_gate.change.after, {"input": "2026-09-05T00:00:01Z"})
	body := object.union(owner_expiry_gate.change, {"after": values})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_malformed_timestamp_fails_closed if {
	values := object.union(owner_expiry_gate.change.after, {"input": "not-a-timestamp"})
	body := object.union(owner_expiry_gate.change, {"after": values})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_unexpected_after_field_fails_closed if {
	values := object.union(owner_expiry_gate.change.after, {"unexpected": true})
	body := object.union(owner_expiry_gate.change, {"after": values})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_additional_unknown_fails_closed if {
	body := object.union(owner_expiry_gate.change, {"after_unknown": {"id": true, "output": true, "tags": true}})
	invalid := object.union(owner_expiry_gate, {"change": body})
	policy_ids_for(plan_with_changes([invalid])) == {"W5-PLAN-001"}
}

test_owner_expiry_gate_sensitive_value_fails_closed if {
	body := object.union(owner_expiry_gate.change, {"after_sensitive": {"input": true}})
	invalid := object.union(owner_expiry_gate, {"change": body})
	"W5-PLAN-001" in policy_ids_for(plan_with_changes([invalid]))
}

test_missing_policy_id_fails_closed if {
	context := object.union(approved_context, {"policy_ids": array.slice(policy_order, 0, count(policy_order) - 1)})
	plan := object.union(approved_plan, {"evaluation_context": context})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_expires_at_outside_twenty_four_hours_is_isolated if {
	tags := object.union(approved_tags, {"ExpiresAt": "2026-09-06T00:00:00Z"})
	key := change(
		"aws_kms_key.expiry",
		"aws_kms_key",
		object.union(approved_kms_values, {"tags_all": tags}),
	)
	policy_ids_for(plan_with_changes([key])) == {"W5-TAG-002"}
}

test_delete_requires_explicit_owner_exception if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	policy_ids_for(plan_with_changes([destructive])) == {"W5-PLAN-002"}
}

test_update_requires_explicit_owner_review if {
	update := object.union(safe_anchor, {"change": {"actions": ["update"], "after": safe_anchor.change.after}})
	policy_ids_for(plan_with_changes([update])) == {"W5-PLAN-002"}
}

test_exact_partial_bootstrap_recovery_is_allowed if {
	count(findings_for(approved_recovery_plan)) == 0
}

test_partial_bootstrap_recovery_requires_exact_dynamodb_grant if {
	broader_statement := object.union(approved_dynamodb_grant_statement, {"Action": ["kms:CreateGrant", "kms:RetireGrant"]})
	plan := recovery_plan(
		recovery_kms_change(broader_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[],
	)
	count(policy_ids_for(plan) & {"W5-PLAN-001", "W5-PLAN-002"}) > 0
}

test_partial_bootstrap_recovery_requires_dynamodb_via_service if {
	conditions := object.remove(approved_dynamodb_grant_statement.Condition, {"StringLike"})
	statement := object.union(
		object.remove(approved_dynamodb_grant_statement, {"Condition"}),
		{"Condition": conditions},
	)
	plan := recovery_plan(
		recovery_kms_change(statement),
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[],
	)
	count(policy_ids_for(plan) & {"W5-PLAN-001", "W5-PLAN-002"}) > 0
}

test_partial_bootstrap_recovery_rejects_broad_grant_principal if {
	statement := object.union(approved_dynamodb_grant_statement, {"Principal": {"AWS": "*"}})
	plan := recovery_plan(
		recovery_kms_change(statement),
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[],
	)
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_non_expiry_kms_update if {
	changed_values := object.union(
		recovery_kms_after(approved_dynamodb_grant_statement),
		{"description": "unapproved change"},
	)
	kms_change := normalized_update(
		bootstrap_recovery_kms_address,
		"aws_kms_key",
		recovery_kms_before,
		changed_values,
	)
	plan := recovery_plan(
		kms_change,
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[],
	)
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_unexpected_update if {
	unexpected := normalized_update(
		"aws_route_table_association.private[0]",
		"aws_route_table_association",
		safe_anchor.change.after,
		safe_anchor.change.after,
	)
	plan := recovery_plan(
		recovery_kms_change(approved_dynamodb_grant_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[unexpected],
	)
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_replacement if {
	replacement_body := object.union(recovery_dynamodb_change.change, {
		"actions": ["delete", "create"],
		"before": recovery_dynamodb_values,
	})
	replacement := object.union(recovery_dynamodb_change, {"change": replacement_body})
	plan := recovery_plan(
		recovery_kms_change(approved_dynamodb_grant_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		replacement,
		[],
	)
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_deletion if {
	deletion := {
		"address": "aws_kms_alias.terraform_state",
		"type": "aws_kms_alias",
		"change": {
			"actions": ["delete"],
			"before": {"name": "alias/enterprise-ai-platform-sandbox-tfstate"},
			"after": null,
			"after_unknown": {},
			"after_sensitive": {},
		},
	}
	plan := recovery_plan(
		recovery_kms_change(approved_dynamodb_grant_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		recovery_dynamodb_change,
		[deletion],
	)
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_sensitive_table_value if {
	body := object.union(recovery_dynamodb_change.change, {"after_sensitive": {"server_side_encryption": true}})
	table := object.union(recovery_dynamodb_change, {"change": body})
	plan := recovery_plan(
		recovery_kms_change(approved_dynamodb_grant_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		table,
		[],
	)
	"W5-SEC-001" in policy_ids_for(plan)
}

test_partial_bootstrap_recovery_rejects_policy_critical_unknown if {
	body := object.union(recovery_dynamodb_change.change, {"after_unknown": {"tags": true}})
	table := object.union(recovery_dynamodb_change, {"change": body})
	plan := recovery_plan(
		recovery_kms_change(approved_dynamodb_grant_statement),
		recovery_bucket_change,
		recovery_expiry_change,
		table,
		[],
	)
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_exact_partial_platform_recovery_contract_is_valid if {
	partial_platform_recovery_plan_valid with input as approved_platform_recovery_plan
	not "W5-PLAN-002" in policy_ids_for(approved_platform_recovery_plan)
}

test_partial_platform_recovery_accepts_false_only_sensitive_shape if {
	address := opensearch_admin_role_address
	original := changes_by_address[address] with input as approved_platform_recovery_plan
	body := object.union(original.change, {"after_sensitive": {
		"inline_policy": [],
		"managed_policy_arns": [],
		"tags": {"ExpiresAt": false},
		"tags_all": {"ExpiresAt": false},
	}})
	plan := platform_recovery_replacing(address, object.union(original, {"change": body}))
	partial_platform_recovery_plan_valid with input as plan
	not "W5-PLAN-001" in policy_ids_for(plan)
	not "W5-PLAN-002" in policy_ids_for(plan)
	not "W5-SEC-001" in policy_ids_for(plan)
}

test_runtime_policy_recovery_requires_owner_expiry_value if {
	original := changes_by_address[platform_runtime_policy_address] with input as approved_platform_recovery_plan
	after_values := object.union(original.change.after, {"policy": json.marshal(runtime_policy_document("2026-09-04T00:30:00Z"))})
	body := object.union(original.change, {"after": after_values})
	plan := platform_recovery_replacing(
		platform_runtime_policy_address,
		object.union(original, {"change": body}),
	)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_runtime_policy_recovery_rejects_additional_policy_change if {
	original := changes_by_address[platform_runtime_policy_address] with input as approved_platform_recovery_plan
	after_document := runtime_policy_document(approved_tags.ExpiresAt)
	extra_statement := {
		"Sid": "UnapprovedDelete",
		"Effect": "Allow",
		"Action": "s3:DeleteObject",
		"Resource": "arn:aws:s3:::enterprise-ai-platform-sandbox/*",
	}
	changed_document := object.union(after_document, {"Statement": array.concat(after_document.Statement, [extra_statement])})
	after_values := object.union(original.change.after, {"policy": json.marshal(changed_document)})
	body := object.union(original.change, {"after": after_values})
	plan := platform_recovery_replacing(
		platform_runtime_policy_address,
		object.union(original, {"change": body}),
	)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_runtime_policy_recovery_rejects_unknown_and_sensitive_policy if {
	original := changes_by_address[platform_runtime_policy_address] with input as approved_platform_recovery_plan
	unknown_body := object.union(original.change, {"after_unknown": {"policy": true}})
	unknown_plan := platform_recovery_replacing(
		platform_runtime_policy_address,
		object.union(original, {"change": unknown_body}),
	)
	not partial_platform_recovery_plan_valid with input as unknown_plan
	"W5-PLAN-001" in policy_ids_for(unknown_plan)

	sensitive_body := object.union(original.change, {"after_sensitive": {"policy": true}})
	sensitive_plan := platform_recovery_replacing(
		platform_runtime_policy_address,
		object.union(original, {"change": sensitive_body}),
	)
	not partial_platform_recovery_plan_valid with input as sensitive_plan
	"W5-SEC-001" in policy_ids_for(sensitive_plan)
}

test_partial_platform_recovery_rejects_malformed_sensitive_shape if {
	address := "module.ecr.aws_ecr_repository.this"
	original := changes_by_address[address] with input as approved_platform_recovery_plan
	body := object.union(original.change, {"after_sensitive": []})
	plan := platform_recovery_replacing(address, object.union(original, {"change": body}))
	not partial_platform_recovery_plan_valid with input as plan
}

test_partial_platform_recovery_rejects_malformed_sensitive_leaves if {
	address := "module.ecr.aws_ecr_repository.this"
	original := changes_by_address[address] with input as approved_platform_recovery_plan
	every malformed_value in ["false", 0, null] {
		body := object.union(original.change, {"after_sensitive": {"tags": {"ExpiresAt": malformed_value}}})
		plan := platform_recovery_replacing(address, object.union(original, {"change": body}))
		not partial_platform_recovery_plan_valid with input as plan
	}
}

test_partial_platform_recovery_binds_all_tag_expiries_to_owner_gate if {
	address := "module.ecr.aws_ecr_repository.this"
	original := changes_by_address[address] with input as approved_platform_recovery_plan
	different_expiry := "2026-09-04T00:30:00Z"

	changed_tags := object.union(original.change.after.tags, {"ExpiresAt": different_expiry})
	tags_after := object.union(original.change.after, {"tags": changed_tags})
	tags_body := object.union(original.change, {"after": tags_after})
	tags_plan := platform_recovery_replacing(
		address,
		object.union(original, {"change": tags_body}),
	)
	not partial_platform_recovery_plan_valid with input as tags_plan

	changed_tags_all := object.union(original.change.after.tags_all, {"ExpiresAt": different_expiry})
	tags_all_after := object.union(original.change.after, {"tags_all": changed_tags_all})
	tags_all_body := object.union(original.change, {"after": tags_all_after})
	tags_all_plan := platform_recovery_replacing(
		address,
		object.union(original, {"change": tags_all_body}),
	)
	not partial_platform_recovery_plan_valid with input as tags_all_plan
}

test_partial_platform_recovery_requires_every_missing_create if {
	plan := platform_recovery_without_address(`module.opensearch.aws_cloudwatch_log_group.this["application"]`)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_platform_recovery_rejects_additional_create if {
	extra := normalized_create(
		"module.opensearch.aws_cloudwatch_log_group.unexpected",
		"aws_cloudwatch_log_group",
		{},
	)
	plan := object.union(approved_platform_recovery_plan, {"resource_changes": array.concat(
		approved_platform_recovery_plan.resource_changes,
		[extra],
	)})
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_platform_recovery_rejects_wrong_create_type if {
	replacement := normalized_create(
		opensearch_domain_address,
		"aws_cloudwatch_log_group",
		{},
	)
	plan := platform_recovery_replacing(opensearch_domain_address, replacement)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_platform_recovery_rejects_non_expiry_update if {
	address := "module.ecr.aws_ecr_repository.this"
	before_values := {"tags": previous_tags, "tags_all": previous_tags, "image_tag_mutability": "IMMUTABLE"}
	after_values := {"tags": approved_tags, "tags_all": approved_tags, "image_tag_mutability": "MUTABLE"}
	replacement := normalized_update(
		address,
		platform_recovery_update_resources[address],
		before_values,
		after_values,
	)
	plan := platform_recovery_replacing(address, replacement)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_platform_recovery_rejects_replacement_and_deletion if {
	replacement_body := object.union(
		changes_by_address[opensearch_domain_address].change,
		{"actions": ["delete", "create"], "before": {}},
	)
		with input as approved_platform_recovery_plan
	replacement := object.union(
		changes_by_address[opensearch_domain_address],
		{"change": replacement_body},
	)
		with input as approved_platform_recovery_plan
	replacement_plan := platform_recovery_replacing(opensearch_domain_address, replacement)
	not partial_platform_recovery_plan_valid with input as replacement_plan
	"W5-PLAN-002" in policy_ids_for(replacement_plan)

	deletion := {
		"address": "module.kms.aws_kms_alias.this",
		"type": "aws_kms_alias",
		"change": {
			"actions": ["delete"],
			"before": {"name": "alias/enterprise-ai-platform-sandbox"},
			"after": null,
			"after_unknown": {},
			"after_sensitive": {},
		},
	}
	deletion_plan := object.union(approved_platform_recovery_plan, {"resource_changes": array.concat(
		approved_platform_recovery_plan.resource_changes,
		[deletion],
	)})
	not partial_platform_recovery_plan_valid with input as deletion_plan
	"W5-PLAN-002" in policy_ids_for(deletion_plan)
}

test_partial_platform_recovery_rejects_sensitive_and_critical_unknown_values if {
	address := `module.opensearch.aws_cloudwatch_log_group.this["audit"]`
	original := changes_by_address[address] with input as approved_platform_recovery_plan
	sensitive_body := object.union(original.change, {"after_sensitive": {"kms_key_id": true}})
	sensitive_plan := platform_recovery_replacing(
		address,
		object.union(original, {"change": sensitive_body}),
	)
	not partial_platform_recovery_plan_valid with input as sensitive_plan
	"W5-SEC-001" in policy_ids_for(sensitive_plan)

	unknown_body := object.union(original.change, {"after_unknown": {"tags": true}})
	unknown_plan := platform_recovery_replacing(
		address,
		object.union(original, {"change": unknown_body}),
	)
	not partial_platform_recovery_plan_valid with input as unknown_plan
	"W5-PLAN-001" in policy_ids_for(unknown_plan)
}

test_s3_public_access_block_rule_is_isolated if {
	public_access := change(
		"aws_s3_bucket_public_access_block.invalid",
		"aws_s3_bucket_public_access_block",
		{
			"block_public_acls": false,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	)
	policy_ids_for(plan_with_changes([public_access])) == {"W5-S3-001"}
}

test_s3_encryption_rule_is_isolated if {
	encryption := change(
		"aws_s3_bucket_server_side_encryption_configuration.invalid",
		"aws_s3_bucket_server_side_encryption_configuration",
		{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
	)
	policy_ids_for(plan_with_changes([encryption])) == {"W5-S3-002"}
}

test_s3_lifecycle_rule_is_isolated if {
	lifecycle := change(
		"aws_s3_bucket_lifecycle_configuration.invalid",
		"aws_s3_bucket_lifecycle_configuration",
		{"rule": []},
	)
	policy_ids_for(plan_with_changes([lifecycle])) == {"W5-S3-003"}
}

test_s3_tls_rule_is_isolated if {
	bucket_policy := change(
		"aws_s3_bucket_policy.invalid",
		"aws_s3_bucket_policy",
		{"policy": `{"Statement":[{"Effect":"Allow"}]}`},
	)
	policy_ids_for(plan_with_changes([bucket_policy])) == {"W5-S3-004"}
}

test_structural_s3_kms_and_tls_relationships_are_accepted if {
	count(findings_for(bootstrap_s3_plan)) == 0
}

test_structural_s3_bindings_are_required_for_computed_kms_and_named_tls_policy if {
	context := object.union(bootstrap_s3_context, {
		"s3_bucket_policy_bindings": [],
		"s3_kms_encryption_bindings": [],
	})
	plan := object.union(bootstrap_s3_plan, {"evaluation_context": context})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_unrelated_structural_s3_policy_binding_fails_closed if {
	context := object.union(bootstrap_s3_context, {"s3_bucket_policy_bindings": [{
		"bucket_address": bootstrap_bucket_address,
		"policy_address": "aws_s3_bucket_policy.unrelated",
	}]})
	plan := object.union(bootstrap_s3_plan, {"evaluation_context": context})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_malformed_structural_s3_kms_binding_fails_closed if {
	context := object.union(bootstrap_s3_context, {"s3_kms_encryption_bindings": [{
		"bucket_address": bootstrap_bucket_address,
		"encryption_address": bootstrap_encryption_address,
		"kms_key_address": bootstrap_kms_address,
		"field_path": "kms_master_key_id",
	}]})
	plan := object.union(bootstrap_s3_plan, {"evaluation_context": context})
	policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_sensitive_structural_s3_policy_binding_fails_closed if {
	policy := bootstrap_s3_changes[5]
	body := object.union(policy.change, {"after_sensitive": {"policy": true}})
	sensitive_policy := object.union(policy, {"change": body})
	changes := array.concat(array.slice(bootstrap_s3_changes, 0, 5), [sensitive_policy, bootstrap_s3_changes[6]])
	plan := object.union(bootstrap_s3_plan, {"resource_changes": changes})
	policy_ids_for(plan) == {"W5-PLAN-001", "W5-SEC-001"}
}

test_kms_rule_is_isolated if {
	key := change(
		"aws_kms_key.invalid",
		"aws_kms_key",
		object.union(approved_kms_values, {"enable_key_rotation": false}),
	)
	policy_ids_for(plan_with_changes([key])) == {"W5-KMS-001"}
}

test_iam_action_rule_is_isolated if {
	role_policy := change(
		"aws_iam_role_policy.invalid",
		"aws_iam_role_policy",
		{"policy": `{"Statement":[{"Action":"logs:*","Resource":"arn:aws:logs:ap-southeast-1:526338061652:log-group:approved"}]}`},
	)
	policy_ids_for(plan_with_changes([role_policy])) == {"W5-IAM-001"}
}

test_iam_scope_rule_is_isolated if {
	role := change(
		"aws_iam_role.invalid",
		"aws_iam_role",
		{
			"assume_role_policy": `{"Statement":[{"Principal":"*","Action":"sts:AssumeRole"}]}`,
			"tags_all": approved_tags,
		},
	)
	policy_ids_for(plan_with_changes([role])) == {"W5-IAM-002"}
}

test_exact_log_stream_wildcard_is_allowed_for_bounded_log_delivery if {
	log_policy := change(
		"aws_cloudwatch_log_resource_policy.delivery",
		"aws_cloudwatch_log_resource_policy",
		{"policy_document": `{"Statement":[{"Principal":{"Service":"es.amazonaws.com"},"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs:*","Condition":{"StringEquals":{"aws:SourceAccount":"526338061652"},"ArnLike":{"aws:SourceArn":"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox"}}}]}`},
	)
	count(findings_for(plan_with_changes([log_policy]))) == 0
}

test_unapproved_iam_resource_wildcard_is_denied if {
	role_policy := change(
		"aws_iam_role_policy.unbounded",
		"aws_iam_role_policy",
		{"policy": `{"Statement":[{"Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}]}`},
	)
	policy_ids_for(plan_with_changes([role_policy])) == {"W5-IAM-002"}
}

test_network_traffic_rule_is_isolated if {
	group := change(
		"aws_security_group.invalid",
		"aws_security_group",
		{
			"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
			"egress": [],
			"tags_all": approved_tags,
		},
	)
	policy_ids_for(plan_with_changes([group])) == {"W5-NET-002"}
}

test_opensearch_security_rule_is_isolated if {
	domain := change(
		"aws_opensearch_domain.invalid",
		"aws_opensearch_domain",
		{"tags_all": approved_tags},
	)
	policy_ids_for(plan_with_changes([domain])) == {"W5-OS-001"}
}

test_opensearch_operations_rule_is_isolated if {
	domain := change(
		"aws_opensearch_domain.logs",
		"aws_opensearch_domain",
		approved_opensearch_security,
	)
	policy_ids_for(plan_with_changes([domain])) == {"W5-OS-002"}
}

test_ecr_retention_rule_is_isolated if {
	repository := change(
		"aws_ecr_repository.retention",
		"aws_ecr_repository",
		approved_ecr_values,
	)
	policy_ids_for(plan_with_changes([repository])) == {"W5-ECR-002"}
}

test_secret_material_rule_is_isolated if {
	plan := object.union(approved_plan, {"api_key": concat("", ["runtime", "-", "only"])})
	policy_ids_for(plan) == {"W5-SEC-001"}
}

test_sensitive_plan_marker_is_denied_without_exposing_value if {
	body := object.union(safe_anchor.change, {"after_sensitive": {"subnet_id": true}})
	sensitive_change := object.union(safe_anchor, {"change": body})
	policy_ids_for(plan_with_changes([sensitive_change])) == {"W5-SEC-001"}
}

test_exact_opensearch_provider_sensitive_null_metadata_is_valid if {
	ids := policy_ids_for(opensearch_sensitive_metadata_plan)
	not "W5-PLAN-001" in ids
	not "W5-SEC-001" in ids
}

test_exact_existing_opensearch_role_provider_sensitive_null_metadata_is_valid if {
	ids := policy_ids_for(opensearch_existing_sensitive_metadata_plan)
	not "W5-PLAN-001" in ids
	not "W5-SEC-001" in ids
}

test_exact_existing_noop_opensearch_role_provider_sensitive_null_metadata_is_valid if {
	noop_role := object.union(opensearch_existing_role_change, {"change": object.union(opensearch_existing_role_change.change, {
		"actions": ["no-op"],
		"before": opensearch_existing_role_after,
		"after": opensearch_existing_role_after,
	})})
	plan := object.union(opensearch_existing_sensitive_metadata_plan, {"resource_changes": [noop_role, opensearch_existing_domain_change]})
	ids := policy_ids_for(plan)
	not "W5-PLAN-001" in ids
	not "W5-SEC-001" in ids
}

test_existing_opensearch_role_changed_trust_policy_fails_closed if {
	altered_after := object.union(opensearch_existing_role_after, {"assume_role_policy": `{"Statement":[{}],"Version":"2012-10-17"}`})
	altered_body := object.union(opensearch_existing_role_change.change, {"after": altered_after})
	altered_role := object.union(opensearch_existing_role_change, {"change": altered_body})
	plan := object.union(opensearch_existing_sensitive_metadata_plan, {"resource_changes": [altered_role, opensearch_existing_domain_change]})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_existing_opensearch_role_non_expiry_update_fails_closed if {
	altered_after := object.union(opensearch_existing_role_after, {"name": "altered-role"})
	altered_body := object.union(opensearch_existing_role_change.change, {"after": altered_after})
	altered_role := object.union(opensearch_existing_role_change, {"change": altered_body})
	plan := object.union(opensearch_existing_sensitive_metadata_plan, {"resource_changes": [altered_role, opensearch_existing_domain_change]})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_existing_opensearch_role_arn_mismatch_fails_closed if {
	domain_after := object.union(opensearch_existing_domain_change.change.after, {"advanced_security_options": [{
		"enabled": true,
		"internal_user_database_enabled": false,
		"master_user_options": [{
			"master_user_arn": "arn:aws:iam::526338061652:role/unrelated",
			"master_user_name": null,
		}],
	}]})
	domain_body := object.union(opensearch_existing_domain_change.change, {"after": domain_after})
	domain := object.union(opensearch_existing_domain_change, {"change": domain_body})
	plan := object.union(opensearch_existing_sensitive_metadata_plan, {"resource_changes": [opensearch_existing_role_change, domain]})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_forged_opensearch_sensitive_path_fails_closed if {
	forged := object.union(opensearch_sensitive_metadata, {"field_path": "other"})
	context := object.union(approved_context, {"provider_sensitive_nulls": [forged]})
	plan := object.union(opensearch_sensitive_metadata_plan, {"evaluation_context": context})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_forged_opensearch_sensitive_source_fails_closed if {
	forged := object.union(opensearch_sensitive_metadata, {"source_address": "module.iam.aws_iam_role.unrelated"})
	context := object.union(approved_context, {"provider_sensitive_nulls": [forged]})
	plan := object.union(opensearch_sensitive_metadata_plan, {"evaluation_context": context})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_duplicate_opensearch_sensitive_metadata_fails_closed if {
	context := object.union(approved_context, {"provider_sensitive_nulls": [opensearch_sensitive_metadata, opensearch_sensitive_metadata]})
	plan := object.union(opensearch_sensitive_metadata_plan, {"evaluation_context": context})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_missing_opensearch_sensitive_metadata_fails_closed if {
	context := object.union(approved_context, {"provider_sensitive_nulls": []})
	plan := object.union(opensearch_sensitive_metadata_plan, {"evaluation_context": context})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_missing_opensearch_role_fails_closed if {
	plan := object.union(opensearch_sensitive_metadata_plan, {"resource_changes": [opensearch_domain_change]})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_opensearch_password_value_fails_closed_even_with_metadata if {
	advanced := opensearch_domain_change.change.after.advanced_security_options[0]
	master := object.union(advanced.master_user_options[0], {"master_user_password": "synthetic"})
	altered_advanced := object.union(advanced, {"master_user_options": [master]})
	altered_after := object.union(opensearch_domain_change.change.after, {"advanced_security_options": [altered_advanced]})
	altered_body := object.union(opensearch_domain_change.change, {"after": altered_after})
	altered_domain := object.union(opensearch_domain_change, {"change": altered_body})
	plan := object.union(opensearch_sensitive_metadata_plan, {"resource_changes": [opensearch_role_change, altered_domain]})
	"W5-PLAN-001" in policy_ids_for(plan)
}

test_invalid_exception_registry_fails_closed if {
	result := policy_ids_for(approved_plan) with data.exceptions as [{"invalid": true}]
	result == {"W5-EXC-001"}
}

test_invalid_exception_never_suppresses_an_existing_denial if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	plan := plan_with_changes([destructive])
	result := policy_ids_for(plan) with data.exceptions as [{"invalid": true}]
	result == {"W5-PLAN-002", "W5-EXC-001"}
}

test_active_exact_exception_suppresses_only_matching_finding if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	plan := plan_with_changes([destructive])
	result := findings_for(plan) with data.exceptions as [active_exception("W5-PLAN-002", safe_anchor.address)]
	count(result) == 0
}

test_wrong_resource_exception_does_not_suppress if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	plan := plan_with_changes([destructive])
	result := policy_ids_for(plan) with data.exceptions as [active_exception("W5-PLAN-002", "aws_route_table_association.other[0]")]
	result == {"W5-PLAN-002"}
}

test_wrong_policy_exception_does_not_suppress if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	plan := plan_with_changes([destructive])
	result := policy_ids_for(plan) with data.exceptions as [active_exception("W5-TAG-001", safe_anchor.address)]
	result == {"W5-PLAN-002"}
}

test_expired_future_and_revoked_exceptions_do_not_suppress if {
	destructive := object.union(safe_anchor, {"change": {"actions": ["delete"], "after": null}})
	plan := plan_with_changes([destructive])

	expired := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
		"issued_at": "2026-09-02T00:00:00Z",
		"expires_at": "2026-09-03T00:00:00Z",
	})
	future := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
		"issued_at": "2026-09-04T01:00:00Z",
		"expires_at": "2026-09-05T01:00:00Z",
	})
	revoked := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {"status": "REVOKED"})

	expired_result := findings_for(plan) with data.exceptions as [expired]
	future_result := findings_for(plan) with data.exceptions as [future]
	revoked_result := findings_for(plan) with data.exceptions as [revoked]
	{finding.policy_id | some finding in expired_result} == {"W5-PLAN-002"}
	{finding.exception_status | some finding in expired_result} == {"EXPIRED"}
	{finding.policy_id | some finding in future_result} == {"W5-PLAN-002"}
	{finding.exception_status | some finding in future_result} == {"FUTURE"}
	{finding.policy_id | some finding in revoked_result} == {"W5-PLAN-002"}
	{finding.exception_status | some finding in revoked_result} == {"REVOKED"}
}

test_duplicate_exception_ids_fail_closed if {
	first := active_exception("W5-PLAN-002", safe_anchor.address)
	second := object.union(
		active_exception("W5-TAG-001", "aws_kms_key.other"),
		{"exception_id": first.exception_id},
	)
	result := policy_ids_for(approved_plan) with data.exceptions as [first, second]
	result == {"W5-EXC-001"}
}

test_wildcard_exception_scope_fails_closed if {
	invalid := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {"resource_addresses": ["aws_route_table_association.*"]})
	result := policy_ids_for(approved_plan) with data.exceptions as [invalid]
	result == {"W5-EXC-001"}
}

test_non_exemptible_policy_exception_fails_closed if {
	invalid := active_exception("W5-SEC-001", "policy.input")
	result := policy_ids_for(approved_plan) with data.exceptions as [invalid]
	result == {"W5-EXC-001"}
}

test_findings_are_sorted_by_policy_resource_and_remediation if {
	group := change(
		"aws_security_group.public",
		"aws_security_group",
		{
			"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
			"egress": [],
			"tags_all": approved_tags,
		},
	)
	gateway := change("aws_nat_gateway.unapproved", "aws_nat_gateway", {})
	plan := object.union(plan_with_changes([group, gateway]), {"variables": {"aws_region": {"value": "us-east-1"}}})
	result := findings_for(plan)
	result == sort(result)
	[finding.policy_id | some finding in result] == [
		"W5-NET-001",
		"W5-NET-002",
		"W5-REG-001",
	]
}

test_findings_are_stable_across_object_order if {
	reordered := {
		"resource_changes": [safe_anchor],
		"evaluation_context": approved_context,
		"variables": {"aws_region": {"value": "ap-southeast-1"}},
		"terraform_version": "1.16.1",
		"format_version": "1.2",
	}
	findings_for(reordered) == findings_for(approved_plan)
}

test_safe_findings_do_not_echo_input_material if {
	material := concat("", ["runtime", "-", "only", "-", "material"])
	plan := object.union(approved_plan, {"api_key": material})
	rendered := json.marshal(findings_for(plan))
	not contains(rendered, material)
	contains(rendered, "W5-SEC-001")
}

v2_operation := {
	"schema_version": "w5-004.lifecycle.v2",
	"operation_id": "synthetic-operation",
	"action": "PLATFORM-APPLY",
	"profile": "INITIAL",
	"rules": [{
		"address": safe_anchor.address,
		"resource_type": safe_anchor.type,
		"actions": ["create"],
		"update_paths": [],
		"delta_rule": "NONE",
	}],
	"state_lineage": null,
	"state_serial": null,
	"inventory_sha256": crypto.sha256("synthetic-inventory"),
	"source_sha256": crypto.sha256("synthetic-source"),
	"resource_expires_at": "2026-09-04T23:45:00Z",
	"expires_at": "2026-09-04T00:15:00Z",
}

v2_plan := object.union(approved_plan, {"evaluation_context": object.union(approved_context, {"operation": v2_operation})})

test_production_decision_requires_v2_profile if {
	result := decision with input as approved_plan
	result.schema_version == "w5-004.policy-decision.v2"
	result.allow == false
	count(result.findings) > 0
}

test_production_decision_accepts_exact_initial_profile if {
	result := decision with input as v2_plan
	result.allow == true
	result.findings == []
	object.keys(result) == {"schema_version", "allow", "findings"}
}

test_production_decision_accepts_owner_approved_eight_hour_validity if {
	operation := object.union(v2_operation, {
		"resource_expires_at": "2026-09-04T08:00:00Z",
		"expires_at": "2026-09-04T08:00:00Z",
	})
	context := object.union(approved_context, {"operation": operation})
	plan := object.union(approved_plan, {"evaluation_context": context})
	result := decision with input as plan
	result.allow == true
	result.findings == []
}

test_production_decision_rejects_missing_duplicate_or_altered_rules if {
	every rules in [[], [v2_operation.rules[0], v2_operation.rules[0]], [object.union(v2_operation.rules[0], {"address": "aws_other.unapproved"})]] {
		operation := object.union(v2_operation, {"rules": rules})
		context := object.union(approved_context, {"operation": operation})
		plan := object.union(approved_plan, {"evaluation_context": context})
		result := decision with input as plan
		result.allow == false
	}
}

test_production_decision_rejects_expiry_and_replacement_drift if {
	every patch in [
		{"resource_expires_at": "2026-09-05T00:00:01Z"},
		{"resource_expires_at": "2026-09-04T00:00:00Z"},
		{"expires_at": "2026-09-03T00:00:00Z"},
	] {
		context := object.union(approved_context, {"operation": object.union(v2_operation, patch)})
		result := decision with input as object.union(approved_plan, {"evaluation_context": context})
		result.allow == false
	}
}

v2_destroy_change := {
	"address": "aws_s3_bucket.fixture",
	"type": "aws_s3_bucket",
	"change": {
		"actions": ["delete"], "before": {"tags_all": approved_tags}, "after": null,
		"after_unknown": {}, "after_sensitive": {},
	},
}

v2_destroy_operation := object.union(v2_operation, {
	"action": "PLATFORM-DESTROY", "profile": "DESTROY",
	"state_lineage": "synthetic-state", "state_serial": 1,
	"rules": [{
		"address": v2_destroy_change.address, "resource_type": v2_destroy_change.type,
		"actions": ["delete"], "update_paths": [], "delta_rule": "NONE",
	}],
})

v2_destroy_plan := object.union(approved_plan, {
	"resource_changes": [v2_destroy_change],
	"evaluation_context": object.union(approved_context, {"operation": v2_destroy_operation}),
})

test_production_destroy_uses_deletion_not_create_configuration if {
	result := decision with input as v2_destroy_plan
	result.allow == true
	result.findings == []
}

test_production_destroy_rejects_replacement_sensitive_and_extra_resource if {
	every patch in [{"actions": ["delete", "create"]}, {"after_sensitive": {"field": true}}, {"after": {}}] {
		changed := object.union(v2_destroy_change, {"change": object.union(v2_destroy_change.change, patch)})
		result := decision with input as object.union(v2_destroy_plan, {"resource_changes": [changed]})
		result.allow == false
	}
	result := decision with input as object.union(v2_destroy_plan, {"resource_changes": [v2_destroy_change, object.union(v2_destroy_change, {"address": "aws_s3_bucket.extra"})]})
	result.allow == false
}

test_production_destroy_rejects_wrong_region_and_missing_state if {
	wrong_region := object.union(v2_destroy_plan, {"variables": {"aws_region": {"value": "us-east-1"}}})
	result := decision with input as wrong_region
	result.allow == false
	operation := object.union(v2_destroy_operation, {"state_lineage": null})
	no_state := object.union(v2_destroy_plan, {"evaluation_context": object.union(approved_context, {"operation": operation})})
	other := decision with input as no_state
	other.allow == false
}

exact_log_kms_before_policy := {
	"Version": "2012-10-17",
	"Statement": [approved_opensearch_log_encryption_statement_before],
}

exact_log_kms_after_policy := {
	"Version": "2012-10-17",
	"Statement": [approved_opensearch_log_encryption_statement],
}

platform_kms_log_compatibility_change(before_policy, after_policy) := normalized_update(
	platform_kms_address,
	"aws_kms_key",
	{
		"enable_key_rotation": true,
		"deletion_window_in_days": 7,
		"policy": json.marshal(before_policy),
		"tags": previous_tags,
		"tags_all": previous_tags,
	},
	{
		"enable_key_rotation": true,
		"deletion_window_in_days": 7,
		"policy": json.marshal(after_policy),
		"tags": approved_tags,
		"tags_all": approved_tags,
	},
)

platform_kms_log_compatibility_plan(before_policy, after_policy) := platform_recovery_replacing(
	platform_kms_address,
	platform_kms_log_compatibility_change(before_policy, after_policy),
)

test_partial_recovery_accepts_exact_log_kms_viaservice_removal if {
	plan := platform_kms_log_compatibility_plan(
		exact_log_kms_before_policy,
		exact_log_kms_after_policy,
	)

	partial_platform_recovery_plan_valid with input as plan
	not "W5-PLAN-002" in policy_ids_for(plan)
}

kms_log_delta_rejected(after_policy) if {
	plan := platform_kms_log_compatibility_plan(
		exact_log_kms_before_policy,
		after_policy,
	)

	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_log_kms_delta_rejects_altered_logs_principal if {
	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Principal": {"Service": "logs.us-east-1.amazonaws.com"}},
	)
	kms_log_delta_rejected({
		"Version": "2012-10-17",
		"Statement": [altered],
	})
}

test_log_kms_delta_rejects_altered_kms_action if {
	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Action": ["kms:Decrypt"]},
	)
	kms_log_delta_rejected({
		"Version": "2012-10-17",
		"Statement": [altered],
	})
}

test_log_kms_delta_rejects_altered_context_arns if {
	altered_condition := object.union(
		approved_opensearch_log_encryption_statement.Condition,
		{"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": ["arn:aws:logs:ap-southeast-1:526338061652:log-group:wrong"]}},
	)
	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Condition": altered_condition},
	)
	kms_log_delta_rejected({
		"Version": "2012-10-17",
		"Statement": [altered],
	})
}

test_log_kms_delta_rejects_altered_resource if {
	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Resource": "arn:aws:kms:ap-southeast-1:526338061652:key/*"},
	)
	kms_log_delta_rejected({
		"Version": "2012-10-17",
		"Statement": [altered],
	})
}

test_log_kms_delta_rejects_retained_viaservice if {
	not valid_opensearch_log_viaservice_removal(
		json.marshal(exact_log_kms_before_policy),
		json.marshal(exact_log_kms_before_policy),
	)
}

test_log_kms_delta_rejects_added_condition if {
	altered_condition := object.union(
		approved_opensearch_log_encryption_statement.Condition,
		{"StringEquals": {"kms:ViaService": "logs.ap-southeast-1.amazonaws.com"}},
	)

	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Condition": altered_condition},
	)

	altered_policy := {
		"Version": "2012-10-17",
		"Statement": [altered],
	}

	not valid_opensearch_log_viaservice_removal(
		json.marshal(exact_log_kms_before_policy),
		json.marshal(altered_policy),
	)
}

test_log_kms_delta_rejects_other_kms_statement_change if {
	other_before := {
		"Sid": "KeepOtherKmsStatement",
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::526338061652:root"},
		"Action": ["kms:DescribeKey"],
		"Resource": "*",
	}
	other_after := object.union(
		other_before,
		{"Action": ["kms:DescribeKey", "kms:CreateGrant"]},
	)

	before_policy := {
		"Version": "2012-10-17",
		"Statement": [
			other_before,
			approved_opensearch_log_encryption_statement_before,
		],
	}
	after_policy := {
		"Version": "2012-10-17",
		"Statement": [
			other_after,
			approved_opensearch_log_encryption_statement,
		],
	}

	plan := platform_kms_log_compatibility_plan(before_policy, after_policy)
	not partial_platform_recovery_plan_valid with input as plan
	"W5-PLAN-002" in policy_ids_for(plan)
}

test_partial_recovery_accepts_provider_reordered_kms_actions if {
	provider_action_order := [
		"kms:ReEncryptTo",
		"kms:ReEncryptFrom",
		"kms:GenerateDataKeyWithoutPlaintext",
		"kms:GenerateDataKey",
		"kms:Encrypt",
		"kms:DescribeKey",
		"kms:Decrypt",
	]

	before_statement := object.union(
		approved_opensearch_log_encryption_statement_before,
		{
			"Action": provider_action_order,
			"Resource": ["*"],
		},
	)

	after_statement := object.union(
		approved_opensearch_log_encryption_statement,
		{
			"Action": provider_action_order,
			"Resource": ["*"],
		},
	)

	before_policy := {
		"Version": "2012-10-17",
		"Statement": [before_statement],
	}

	after_policy := {
		"Version": "2012-10-17",
		"Statement": [after_statement],
	}

	plan := platform_kms_log_compatibility_plan(
		before_policy,
		after_policy,
	)

	partial_platform_recovery_plan_valid with input as plan
	not "W5-PLAN-002" in policy_ids_for(plan)
}

test_log_kms_delta_rejects_duplicate_kms_action if {
	duplicate_actions := array.concat(
		approved_opensearch_log_encryption_statement.Action,
		["kms:Decrypt"],
	)

	altered := object.union(
		approved_opensearch_log_encryption_statement,
		{"Action": duplicate_actions},
	)

	kms_log_delta_rejected({
		"Version": "2012-10-17",
		"Statement": [altered],
	})
}

r6_partial_recovery_context := {"evaluation_context": object.union(approved_context, {"operation": {"profile": "PARTIAL_RECOVERY"}})}

r6_gate_noop(gate) := object.union(
	object.remove(gate, {"change"}),
	{"change": {
		"actions": ["no-op"],
		"before": gate.change.after,
		"after": gate.change.after,
		"before_sensitive": object.get(gate.change, "after_sensitive", {}),
		"after_sensitive": object.get(gate.change, "after_sensitive", {}),
		"after_unknown": {},
	}},
)

test_r6_accepts_exact_noop_governance_gates if {
	valid_change(r6_gate_noop(owner_expiry_gate)) with input as r6_partial_recovery_context
	valid_change(r6_gate_noop(w6_004_runtime_gate)) with input as r6_partial_recovery_context
}

test_r6_rejects_unapproved_noop_terraform_data if {
	invalid := object.union(
		r6_gate_noop(owner_expiry_gate),
		{"address": "terraform_data.unapproved"},
	)
	not valid_change(invalid) with input as r6_partial_recovery_context
}

test_r6_rejects_modified_governance_gate_as_noop if {
	noop := r6_gate_noop(owner_expiry_gate)
	invalid := object.union(noop, {"change": object.union(noop.change, {"after": object.union(noop.change.after, {"input": "2026-09-04T02:00:00Z"})})})
	not valid_change(invalid) with input as r6_partial_recovery_context
}

r6_runtime_policy_values := {
	"name": "enterprise-ai-sandbox-runtime",
	"policy": json.marshal(runtime_policy_document(approved_tags.ExpiresAt)),
	"role": "enterprise-ai-sandbox-runtime",
}

r6_runtime_policy_noop := {
	"address": platform_runtime_policy_address,
	"type": "aws_iam_role_policy",
	"change": {
		"actions": ["no-op"],
		"before": r6_runtime_policy_values,
		"after": r6_runtime_policy_values,
		"before_sensitive": {},
		"after_sensitive": {},
		"after_unknown": {},
	},
}

test_r6_accepts_exact_noop_runtime_policy_scope if {
	approved_existing_w6_004_iam_policy(r6_runtime_policy_noop) with input as r6_partial_recovery_context
}

test_r6_rejects_modified_runtime_policy_disguised_as_noop if {
	invalid := object.union(r6_runtime_policy_noop, {"change": object.union(r6_runtime_policy_noop.change, {"after": object.union(r6_runtime_policy_values, {"role": "unapproved-runtime-role"})})})
	not approved_existing_w6_004_iam_policy(invalid) with input as r6_partial_recovery_context
}

r5_policy_test_input := {"evaluation_context": object.union(approved_context, {"operation": {"resource_expires_at": approved_tags.ExpiresAt}})}

r5_expiry_rule(address, resource_type) := {
	"address": address,
	"resource_type": resource_type,
	"actions": ["update"],
	"update_paths": ["tags.ExpiresAt", "tags_all.ExpiresAt"],
	"delta_rule": "EXPIRES_AT",
}

r5_access_entry_change := normalized_update(
	"module.eks[0].aws_eks_access_entry.resilience",
	"aws_eks_access_entry",
	{"user_name": "fis-experiment", "tags": {"ExpiresAt": previous_tags.ExpiresAt}, "tags_all": previous_tags},
	{"user_name": "fis-experiment", "tags": {}, "tags_all": approved_tags},
)

r5_pod_identity_change := {
	"address": "module.eks[0].aws_eks_pod_identity_association.runtime",
	"type": "aws_eks_pod_identity_association",
	"change": {
		"actions": ["update"],
		"before": {
			"external_id": null,
			"role_arn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime",
			"tags": {"ExpiresAt": previous_tags.ExpiresAt},
			"tags_all": previous_tags,
		},
		"after": {
			"role_arn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime",
			"tags": null,
			"tags_all": approved_tags,
		},
		"after_unknown": {"external_id": true, "tags_all": {}},
		"before_sensitive": {"tags": {}, "tags_all": {}},
		"after_sensitive": {"tags_all": {}},
	},
}

test_r5_accepts_provider_normalized_expiry_changes if {
	access_rule := r5_expiry_rule(r5_access_entry_change.address, r5_access_entry_change.type)
	operational_expiry_delta(r5_access_entry_change, access_rule) with input as r5_policy_test_input

	pod_rule := r5_expiry_rule(r5_pod_identity_change.address, r5_pod_identity_change.type)
	operational_expiry_delta(r5_pod_identity_change, pod_rule) with input as r5_policy_test_input
}

test_r5_rejects_pod_identity_role_change if {
	after := object.union(r5_pod_identity_change.change.after, {"role_arn": "arn:aws:iam::526338061652:role/unapproved"})
	changed := object.union(r5_pod_identity_change, {"change": object.union(r5_pod_identity_change.change, {"after": after})})
	rule := r5_expiry_rule(changed.address, changed.type)
	not operational_expiry_delta(changed, rule) with input as r5_policy_test_input
}

r5_recovery_rule(address, resource_type, actions, update_paths) := {
	"address": address,
	"resource_type": resource_type,
	"actions": actions,
	"update_paths": update_paths,
	"delta_rule": "W6_004_STAGE3_RECOVERY",
}

r9_runtime_gate_test_input := {"evaluation_context": object.union(approved_context, {"operation": {
	"expires_at": "2026-09-04T08:00:00Z",
	"resource_expires_at": "2026-09-04T23:45:00Z",
}})}

r9_runtime_gate_change(approval_expires_at) := normalized_update(
	"terraform_data.w6_004_runtime_gate[0]",
	"terraform_data",
	{
		"input": {
			"approval_issued_at": "2026-09-03T16:00:00Z",
			"deployment_start": "2026-09-03T16:00:00Z",
			"approval_expires_at": "2026-09-04T00:30:00Z",
		},
		"output": null,
	},
	{
		"input": {
			"approval_issued_at": "2026-09-04T00:00:00Z",
			"deployment_start": "2026-09-04T00:00:00Z",
			"approval_expires_at": approval_expires_at,
		},
		"output": null,
	},
)

r9_runtime_gate_rule := r5_recovery_rule(
	"terraform_data.w6_004_runtime_gate[0]",
	"terraform_data",
	["update"],
	[
		"input.approval_expires_at",
		"input.approval_issued_at",
		"input.deployment_start",
		"output",
	],
)

test_r9_runtime_gate_binds_approval_to_mutation_deadline if {
	r9_runtime_gate_test_input.evaluation_context.operation.expires_at != r9_runtime_gate_test_input.evaluation_context.operation.resource_expires_at
	change := r9_runtime_gate_change(r9_runtime_gate_test_input.evaluation_context.operation.expires_at)
	w6_004_stage3_recovery_delta(change, r9_runtime_gate_rule) with input as r9_runtime_gate_test_input
}

test_r9_runtime_gate_rejects_resource_expiry_as_approval_deadline if {
	change := r9_runtime_gate_change(r9_runtime_gate_test_input.evaluation_context.operation.resource_expires_at)
	not w6_004_stage3_recovery_delta(change, r9_runtime_gate_rule) with input as r9_runtime_gate_test_input
}

r9_admin_trust_policy(expires_at) := {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "TimeBoundExactSandboxAdministrator",
		"Effect": "Allow",
		"Action": "sts:AssumeRole",
		"Principal": {"AWS": "arn:aws:iam::526338061652:role/approved-owner"},
		"Condition": {
			"DateLessThan": {"aws:CurrentTime": expires_at},
			"StringEquals": {"aws:PrincipalAccount": "526338061652"},
		},
	}],
}

r9_admin_role_change(trust_expires_at) := normalized_update(
	opensearch_admin_role_address,
	"aws_iam_role",
	{
		"arn": opensearch_existing_role_arn,
		"assume_role_policy": json.marshal(r9_admin_trust_policy("2026-09-04T00:30:00Z")),
		"name": "enterprise-ai-sandbox-opensearch-admin",
		"tags": object.union(approved_tags, {"ExpiresAt": "2026-09-04T00:30:00Z"}),
		"tags_all": object.union(approved_tags, {"ExpiresAt": "2026-09-04T00:30:00Z"}),
	},
	{
		"arn": opensearch_existing_role_arn,
		"assume_role_policy": json.marshal(r9_admin_trust_policy(trust_expires_at)),
		"name": "enterprise-ai-sandbox-opensearch-admin",
		"tags": object.union(approved_tags, {"ExpiresAt": r9_runtime_gate_test_input.evaluation_context.operation.resource_expires_at}),
		"tags_all": object.union(approved_tags, {"ExpiresAt": r9_runtime_gate_test_input.evaluation_context.operation.resource_expires_at}),
	},
)

test_r9_admin_trust_binds_authorization_to_mutation_deadline if {
	change := r9_admin_role_change(r9_runtime_gate_test_input.evaluation_context.operation.expires_at)
	valid_admin_trust_expiry_update(change) with input as r9_runtime_gate_test_input
}

test_r9_admin_trust_rejects_resource_expiry_as_authorization_deadline if {
	change := r9_admin_role_change(r9_runtime_gate_test_input.evaluation_context.operation.resource_expires_at)
	not valid_admin_trust_expiry_update(change) with input as r9_runtime_gate_test_input
}

r5_vpc_cni_change(configuration_values) := normalized_update(
	`module.eks[0].aws_eks_addon.this["vpc-cni"]`,
	"aws_eks_addon",
	{"configuration_values": "", "tags": previous_tags, "tags_all": previous_tags},
	{"configuration_values": configuration_values, "tags": approved_tags, "tags_all": approved_tags},
)

test_r5_accepts_exact_vpc_cni_network_policy_enablement if {
	change := r5_vpc_cni_change(`{"enableNetworkPolicy":"true"}`)
	rule := r5_recovery_rule(change.address, change.type, ["update"], ["configuration_values", "tags.ExpiresAt", "tags_all.ExpiresAt"])
	w6_004_stage3_recovery_delta(change, rule) with input as r5_policy_test_input
}

test_r5_rejects_disabled_vpc_cni_network_policy if {
	change := r5_vpc_cni_change(`{"enableNetworkPolicy":"false"}`)
	rule := r5_recovery_rule(change.address, change.type, ["update"], ["configuration_values", "tags.ExpiresAt", "tags_all.ExpiresAt"])
	not w6_004_stage3_recovery_delta(change, rule) with input as r5_policy_test_input
}

r5_fis_before := {
	"action": [{
		"action_id": "aws:eks:pod-delete",
		"parameter": [{"key": "kubernetesServiceAccount", "value": "fis-experiment"}],
	}],
	"experiment_options": [{"account_targeting": "single-account", "empty_target_resolution_mode": "fail"}],
	"id": "approved-template-id",
	"tags": previous_tags,
	"tags_all": previous_tags,
	"target": [{
		"parameters": {
			"namespace": "enterprise-ai-sandbox",
			"selectorType": "labelSelector",
			"selectorValue": "app.kubernetes.io/name=enterprise-ai-api",
		},
		"resource_type": "aws:eks:pod",
		"selection_mode": "COUNT(1)",
	}],
}

r5_fis_after(service_account) := {
	"action": [{
		"action_id": "aws:eks:pod-delete",
		"parameter": [{"key": "kubernetesServiceAccount", "value": service_account}],
	}],
	"tags": approved_tags,
	"tags_all": approved_tags,
	"target": [{
		"parameters": {
			"namespace": "enterprise-ai-sandbox",
			"selectorType": "labelSelector",
			"selectorValue": "app.kubernetes.io/name=enterprise-ai-api",
		},
		"resource_type": "aws:eks:pod",
		"selection_mode": "COUNT(1)",
	}],
}

r5_fis_change(service_account) := {
	"address": "module.observability[0].aws_fis_experiment_template.pod_delete",
	"type": "aws_fis_experiment_template",
	"change": {
		"actions": ["delete", "create"],
		"before": r5_fis_before,
		"after": r5_fis_after(service_account),
		"after_unknown": {"experiment_options": true, "id": true},
		"before_sensitive": {},
		"after_sensitive": {},
	},
}

r5_fis_rule := r5_recovery_rule(
	"module.observability[0].aws_fis_experiment_template.pod_delete",
	"aws_fis_experiment_template",
	["delete", "create"],
	["experiment_options", "id", "tags.ExpiresAt", "tags_all.ExpiresAt"],
)

test_r5_accepts_exact_bounded_fis_replacement if {
	w6_004_stage3_recovery_delta(r5_fis_change("fis-experiment"), r5_fis_rule) with input as r5_policy_test_input
}

test_r5_rejects_wrong_fis_service_account if {
	not w6_004_stage3_recovery_delta(r5_fis_change("default"), r5_fis_rule) with input as r5_policy_test_input
}

r5_opensearch_existing_statement := {
	"Sid": "ExactSandboxRoleDataPlaneAccess",
	"Effect": "Allow",
	"Principal": {"AWS": ["arn:aws:iam::526338061652:role/enterprise-ai-sandbox-ingestion"]},
	"Action": ["es:ESHttpGet"],
	"Resource": ["arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/*"],
}

r5_opensearch_runtime_statement(actions) := {
	"Sid": "RuntimeExactReadAccess",
	"Effect": "Allow",
	"Principal": {"AWS": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"},
	"Action": actions,
	"Resource": [
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/_cluster/health",
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
	],
}

r5_opensearch_policy(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

test_r5_accepts_exact_runtime_opensearch_policy_addition if {
	before := r5_opensearch_policy([r5_opensearch_existing_statement])
	after := r5_opensearch_policy([
		r5_opensearch_existing_statement,
		r5_opensearch_runtime_statement(["es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost"]),
	])
	valid_runtime_opensearch_policy_addition(before, after)
}

test_r5_rejects_runtime_opensearch_write_access if {
	before := r5_opensearch_policy([r5_opensearch_existing_statement])
	after := r5_opensearch_policy([
		r5_opensearch_existing_statement,
		r5_opensearch_runtime_statement(["es:ESHttpGet", "es:ESHttpPut", "es:ESHttpPost"]),
	])
	not valid_runtime_opensearch_policy_addition(before, after)
}

r7_sts_policy(actions) := json.marshal({
	"Statement": [{
		"Action": actions,
		"Condition": {"StringEquals": {"aws:PrincipalAccount": "526338061652"}},
		"Effect": "Allow",
		"Principal": {"AWS": "*"},
		"Resource": "*",
		"Sid": "ExactSandboxAccountSTS",
	}],
	"Version": "2012-10-17",
})

r7_sts_policy_change(after_actions) := normalized_update(
	`module.network.aws_vpc_endpoint.interface["STS"]`,
	"aws_vpc_endpoint",
	{"policy": r7_sts_policy("sts:AssumeRole")},
	{"policy": r7_sts_policy(after_actions)},
)

r7_sts_policy_rule := r5_recovery_rule(
	`module.network.aws_vpc_endpoint.interface["STS"]`,
	"aws_vpc_endpoint",
	["update"],
	["policy"],
)

test_r7_accepts_exact_sts_get_caller_identity_addition if {
	change := r7_sts_policy_change([
		"sts:GetCallerIdentity",
		"sts:AssumeRole",
	])
	w6_004_stage3_recovery_delta(change, r7_sts_policy_rule)
}

test_r7_rejects_unapproved_sts_action if {
	change := r7_sts_policy_change([
		"sts:GetCallerIdentity",
		"sts:AssumeRole",
		"sts:*",
	])
	not w6_004_stage3_recovery_delta(change, r7_sts_policy_rule)
}

test_r7_rejects_sts_policy_non_action_change if {
	change := r7_sts_policy_change([
		"sts:GetCallerIdentity",
		"sts:AssumeRole",
	])
	modified_after := object.union(change.change.after, {"policy": json.marshal({
		"Statement": [{
			"Action": [
				"sts:GetCallerIdentity",
				"sts:AssumeRole",
			],
			"Condition": {"StringEquals": {"aws:PrincipalAccount": "000000000000"}},
			"Effect": "Allow",
			"Principal": {"AWS": "*"},
			"Resource": "*",
			"Sid": "ExactSandboxAccountSTS",
		}],
		"Version": "2012-10-17",
	})})
	modified := object.union(change, {"change": object.union(change.change, {"after": modified_after})})
	not w6_004_stage3_recovery_delta(modified, r7_sts_policy_rule)
}

r8_index_root_arn := "arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox"
r8_index_child_arn := sprintf("%s/*", [r8_index_root_arn])
r8_health_arn := "arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/_cluster/health"

r8_iam_policy(sid, resources) := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": sid,
		"Effect": "Allow",
		"Action": ["es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost"],
		"Resource": resources,
	}],
})

r8_iam_change(address, sid, after_resources) := normalized_update(
	address,
	"aws_iam_role_policy",
	{
		"name": "enterprise-ai-sandbox",
		"role": "enterprise-ai-sandbox",
		"policy": r8_iam_policy(sid, r8_index_child_arn),
	},
	{
		"name": "enterprise-ai-sandbox",
		"role": "enterprise-ai-sandbox",
		"policy": r8_iam_policy(sid, after_resources),
	},
)

r8_runtime_iam_rule := r5_recovery_rule(
	"module.iam.aws_iam_role_policy.runtime",
	"aws_iam_role_policy",
	["update"],
	["policy"],
)

r8_ingestion_iam_rule := r5_recovery_rule(
	"module.iam.aws_iam_role_policy.ingestion",
	"aws_iam_role_policy",
	["update"],
	["policy"],
)

r11_fis_iam_rule := r5_recovery_rule(
	platform_fis_policy_address,
	"aws_iam_role_policy",
	["update"],
	["policy"],
)

r11_fis_policy(discovery_actions, cluster_actions) := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Action": discovery_actions,
			"Effect": "Allow",
			"Resource": ["*"],
		},
		{
			"Action": cluster_actions,
			"Effect": "Allow",
			"Resource": [platform_fis_cluster_arn],
		},
	],
})

r11_fis_change(after_discovery_actions, after_cluster_actions) := normalized_update(
	platform_fis_policy_address,
	"aws_iam_role_policy",
	{
		"id": "enterprise-ai-sandbox-fis:bounded-eks-pod-delete-discovery",
		"name": "bounded-eks-pod-delete-discovery",
		"name_prefix": "",
		"policy": r11_fis_policy(
			["tag:GetResources", "ec2:DescribeInstances"],
			["eks:DescribeCluster", "eks:AccessKubernetesApi"],
		),
		"role": "enterprise-ai-sandbox-fis",
	},
	{
		"id": "enterprise-ai-sandbox-fis:bounded-eks-pod-delete-discovery",
		"name": "bounded-eks-pod-delete-discovery",
		"name_prefix": "",
		"policy": r11_fis_policy(after_discovery_actions, after_cluster_actions),
		"role": "enterprise-ai-sandbox-fis",
	},
)

r11_fis_update_context := {"evaluation_context": object.union(approved_context, {"operation": {
	"profile": "PARTIAL_RECOVERY",
	"rules": [r11_fis_iam_rule],
}})}

test_r11_accepts_exact_fis_subnet_discovery_repair if {
	change := r11_fis_change(
		["tag:GetResources", "ec2:DescribeSubnets", "ec2:DescribeInstances"],
		["eks:DescribeCluster", "eks:AccessKubernetesApi"],
	)
	w6_004_stage3_recovery_delta(change, r11_fis_iam_rule)
	approved_existing_w6_004_iam_policy(change) with input as r11_fis_update_context
}

test_r11_rejects_broader_fis_discovery_repair if {
	change := r11_fis_change(
		["tag:GetResources", "ec2:DescribeSubnets", "ec2:DescribeInstances", "ec2:Describe*"],
		["eks:DescribeCluster", "eks:AccessKubernetesApi"],
	)
	not w6_004_stage3_recovery_delta(change, r11_fis_iam_rule)
}

test_r11_rejects_fis_cluster_permission_change if {
	change := r11_fis_change(
		["tag:GetResources", "ec2:DescribeSubnets", "ec2:DescribeInstances"],
		["eks:DescribeCluster", "eks:AccessKubernetesApi", "eks:DeleteCluster"],
	)
	not w6_004_stage3_recovery_delta(change, r11_fis_iam_rule)
}

r8_runtime_update_context := {"evaluation_context": object.union(approved_context, {"operation": {
	"profile": "PARTIAL_RECOVERY",
	"rules": [r8_runtime_iam_rule],
}})}

r10_runtime_legacy_bedrock_statement(expires_at) := {
	"Sid": "InvokeExactApprovedInferenceProfile",
	"Effect": "Allow",
	"Action": "bedrock:InvokeModel",
	"Resource": platform_global_inference_profile_arn,
	"Condition": {
		"ArnEquals": {"aws:PrincipalArn": platform_runtime_role_arn},
		"DateLessThan": {"aws:CurrentTime": expires_at},
		"StringEquals": {
			"aws:PrincipalAccount": "526338061652",
			"aws:RequestedRegion": "ap-southeast-1",
			"bedrock:InferenceProfileArn": platform_global_inference_profile_arn,
		},
	},
}

r10_runtime_bedrock_policy(statements) := json.marshal({
	"Version": "2012-10-17",
	"Statement": array.concat(statements, [{
		"Sid": "RuntimeReadPlatformObjects",
		"Effect": "Allow",
		"Action": "s3:GetObject",
		"Resource": "arn:aws:s3:::enterprise-ai-platform-sandbox/*",
	}]),
})

r10_runtime_bedrock_statement_array(sid, resource, conditions) := {
	"Sid": sid,
	"Effect": "Allow",
	"Action": ["bedrock:InvokeModel"],
	"Resource": [resource],
	"Condition": conditions,
}

r10_runtime_bedrock_change(after_statements) := normalized_update(
	"module.iam.aws_iam_role_policy.runtime",
	"aws_iam_role_policy",
	{
		"name": "enterprise-ai-sandbox-runtime",
		"role": "enterprise-ai-sandbox-runtime",
		"policy": r10_runtime_bedrock_policy([r10_runtime_legacy_bedrock_statement(approved_tags.ExpiresAt)]),
	},
	{
		"name": "enterprise-ai-sandbox-runtime",
		"role": "enterprise-ai-sandbox-runtime",
		"policy": r10_runtime_bedrock_policy(after_statements),
	},
)

test_r10_accepts_exact_global_bedrock_inference_profile_repair if {
	change := r10_runtime_bedrock_change([
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfile", platform_global_inference_profile_arn, runtime_bedrock_base_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfileRegionalModel", platform_regional_foundation_model_arn, runtime_bedrock_profile_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfileGlobalModel", platform_global_foundation_model_arn, runtime_bedrock_profile_conditions("unspecified", approved_tags.ExpiresAt)),
	])
	w6_004_stage3_recovery_delta(change, r8_runtime_iam_rule)
}

test_r10_accepts_terraform_singleton_array_bedrock_policy_representation if {
	before_policy := r10_runtime_bedrock_policy([r10_runtime_bedrock_statement_array("InvokeExactApprovedInferenceProfile", platform_global_inference_profile_arn, runtime_bedrock_profile_conditions("ap-southeast-1", approved_tags.ExpiresAt))])
	after_policy := r10_runtime_bedrock_policy([
		r10_runtime_bedrock_statement_array("InvokeExactGlobalInferenceProfile", platform_global_inference_profile_arn, runtime_bedrock_base_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		r10_runtime_bedrock_statement_array("InvokeExactGlobalInferenceProfileRegionalModel", platform_regional_foundation_model_arn, runtime_bedrock_profile_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		r10_runtime_bedrock_statement_array("InvokeExactGlobalInferenceProfileGlobalModel", platform_global_foundation_model_arn, runtime_bedrock_profile_conditions("unspecified", approved_tags.ExpiresAt)),
	])
	valid_runtime_global_bedrock_profile_repair(before_policy, after_policy)
}

test_r10_rejects_global_bedrock_profile_repair_with_broad_model_access if {
	change := r10_runtime_bedrock_change([
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfile", platform_global_inference_profile_arn, runtime_bedrock_base_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfileRegionalModel", "arn:aws:bedrock:ap-southeast-1::foundation-model/*", runtime_bedrock_profile_conditions("ap-southeast-1", approved_tags.ExpiresAt)),
		runtime_bedrock_statement("InvokeExactGlobalInferenceProfileGlobalModel", platform_global_foundation_model_arn, runtime_bedrock_profile_conditions("unspecified", approved_tags.ExpiresAt)),
	])
	not w6_004_stage3_recovery_delta(change, r8_runtime_iam_rule)
}

test_r8_runtime_scope_exemption_accepts_exact_index_root_repair if {
	change := r8_iam_change(
		"module.iam.aws_iam_role_policy.runtime",
		"RuntimeOpenSearchExactIndexQuery",
		[r8_index_root_arn, r8_index_child_arn],
	)
	approved_existing_w6_004_iam_policy(change) with input as r8_runtime_update_context
}

test_r8_runtime_scope_exemption_rejects_broader_resource if {
	change := r8_iam_change(
		"module.iam.aws_iam_role_policy.runtime",
		"RuntimeOpenSearchExactIndexQuery",
		[
			r8_index_root_arn,
			r8_index_child_arn,
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/*",
		],
	)
	not approved_existing_w6_004_iam_policy(change) with input as r8_runtime_update_context
}

test_r8_accepts_runtime_iam_index_root_addition if {
	change := r8_iam_change(
		"module.iam.aws_iam_role_policy.runtime",
		"RuntimeOpenSearchExactIndexQuery",
		[r8_index_root_arn, r8_index_child_arn],
	)
	w6_004_stage3_recovery_delta(change, r8_runtime_iam_rule)
}

test_r8_accepts_ingestion_iam_index_root_addition if {
	change := r8_iam_change(
		"module.iam.aws_iam_role_policy.ingestion",
		"IngestionOpenSearchDataPlane",
		[r8_index_root_arn, r8_index_child_arn],
	)
	w6_004_stage3_recovery_delta(change, r8_ingestion_iam_rule)
}

test_r8_rejects_additional_iam_resource if {
	change := r8_iam_change(
		"module.iam.aws_iam_role_policy.runtime",
		"RuntimeOpenSearchExactIndexQuery",
		[
			r8_index_root_arn,
			r8_index_child_arn,
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/*",
		],
	)
	not w6_004_stage3_recovery_delta(change, r8_runtime_iam_rule)
}

r8_domain_runtime_statement(resources) := {
	"Sid": "RuntimeExactReadAccess",
	"Effect": "Allow",
	"Principal": {"AWS": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"},
	"Action": ["es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost"],
	"Resource": resources,
}

r8_domain_change(after_resources) := normalized_update(
	"module.opensearch.aws_opensearch_domain.this",
	"aws_opensearch_domain",
	{"access_policies": r5_opensearch_policy([
		r5_opensearch_existing_statement,
		r8_domain_runtime_statement([r8_health_arn, r8_index_child_arn]),
	])},
	{"access_policies": r5_opensearch_policy([
		r5_opensearch_existing_statement,
		r8_domain_runtime_statement(after_resources),
	])},
)

r8_domain_rule := r5_recovery_rule(
	"module.opensearch.aws_opensearch_domain.this",
	"aws_opensearch_domain",
	["update"],
	["access_policies"],
)

test_r8_accepts_domain_index_root_addition if {
	change := r8_domain_change([
		r8_health_arn,
		r8_index_root_arn,
		r8_index_child_arn,
	])
	w6_004_stage3_recovery_delta(change, r8_domain_rule)
}

test_r8_rejects_additional_domain_resource if {
	change := r8_domain_change([
		r8_health_arn,
		r8_index_root_arn,
		r8_index_child_arn,
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/*",
	])
	not w6_004_stage3_recovery_delta(change, r8_domain_rule)
}

test_r8_exact_index_child_wildcard_is_approved if {
	approved_wildcard_arn(r8_index_child_arn)
}

test_r8_unrelated_index_wildcard_remains_rejected if {
	not approved_wildcard_arn("arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/unapproved_index/*")
}
