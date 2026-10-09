package enterprise_ai.terraform.plan

import rego.v1

day_ns := 86400000000000
week_ns := 604800000000000

policy_inventory := [
	{"policy_id": "W5-PLAN-001", "severity": "CRITICAL", "category": "PLAN_INPUT", "remediation_code": "REJECT_UNEVALUATED_INPUT"},
	{"policy_id": "W5-REG-001", "severity": "CRITICAL", "category": "REGION", "remediation_code": "USE_APPROVED_REGION"},
	{"policy_id": "W5-TAG-001", "severity": "HIGH", "category": "TAGS", "remediation_code": "APPLY_MANDATORY_TAGS"},
	{"policy_id": "W5-TAG-002", "severity": "HIGH", "category": "TAG_EXPIRY", "remediation_code": "SET_BOUNDED_EXPIRY"},
	{"policy_id": "W5-PLAN-002", "severity": "HIGH", "category": "CHANGE_LIFECYCLE", "remediation_code": "REQUIRE_OWNER_REVIEW"},
	{"policy_id": "W5-S3-001", "severity": "CRITICAL", "category": "S3_PUBLIC_ACCESS", "remediation_code": "ENABLE_S3_PUBLIC_BLOCK"},
	{"policy_id": "W5-S3-002", "severity": "CRITICAL", "category": "S3_ENCRYPTION", "remediation_code": "USE_APPROVED_S3_KMS"},
	{"policy_id": "W5-S3-003", "severity": "HIGH", "category": "S3_LIFECYCLE", "remediation_code": "ENABLE_S3_LIFECYCLE"},
	{"policy_id": "W5-S3-004", "severity": "CRITICAL", "category": "S3_TRANSPORT", "remediation_code": "ENFORCE_S3_TLS"},
	{"policy_id": "W5-KMS-001", "severity": "CRITICAL", "category": "KMS_LIFECYCLE", "remediation_code": "ENABLE_KMS_ROTATION"},
	{"policy_id": "W5-IAM-001", "severity": "CRITICAL", "category": "IAM_ACTION", "remediation_code": "NARROW_IAM_ACTIONS"},
	{"policy_id": "W5-IAM-002", "severity": "CRITICAL", "category": "IAM_SCOPE", "remediation_code": "NARROW_IAM_SCOPE"},
	{"policy_id": "W5-NET-001", "severity": "CRITICAL", "category": "NETWORK_TOPOLOGY", "remediation_code": "USE_PRIVATE_NETWORK"},
	{"policy_id": "W5-NET-002", "severity": "CRITICAL", "category": "NETWORK_TRAFFIC", "remediation_code": "RESTRICT_SECURITY_GROUP"},
	{"policy_id": "W5-OS-001", "severity": "CRITICAL", "category": "OPENSEARCH_SECURITY", "remediation_code": "HARDEN_OPENSEARCH"},
	{"policy_id": "W5-OS-002", "severity": "HIGH", "category": "OPENSEARCH_OPERATIONS", "remediation_code": "CONFIGURE_OPENSEARCH_LOGS"},
	{"policy_id": "W5-ECR-001", "severity": "CRITICAL", "category": "ECR_SECURITY", "remediation_code": "HARDEN_ECR"},
	{"policy_id": "W5-ECR-002", "severity": "HIGH", "category": "ECR_RETENTION", "remediation_code": "RETAIN_TEN_IMAGES"},
	{"policy_id": "W5-SEC-001", "severity": "CRITICAL", "category": "SECRET_BOUNDARY", "remediation_code": "REMOVE_SECRET_MATERIAL"},
	{"policy_id": "W5-EXC-001", "severity": "CRITICAL", "category": "EXCEPTION_REGISTRY", "remediation_code": "REPAIR_EXCEPTION_REGISTRY"},
]

policy_order := [entry.policy_id | some entry in policy_inventory]
policy_ids := {entry.policy_id | some entry in policy_inventory}
policy_by_id := {entry.policy_id: entry | some entry in policy_inventory}

non_exemptible_policy_ids := {
	"W5-PLAN-001",
	"W5-SEC-001",
	"W5-EXC-001",
}

required_tags := {
	"Project": "enterprise-ai-platform",
	"Environment": "sandbox",
	"Owner": "Gyan-Prakash-Rai",
	"ManagedBy": "terraform",
	"CostCenter": "Personal-Learning",
	"Feature": "MVP-001",
	"Repository": "enterprise-ai-platform",
}

required_tag_keys := {
	"Project",
	"Environment",
	"Owner",
	"ManagedBy",
	"CostCenter",
	"Feature",
	"Repository",
	"ExpiresAt",
}

policy_critical_unknown_keys := {
	"account_id",
	"access_policies",
	"assume_role_policy",
	"aws_region",
	"cidr_block",
	"cloudwatch_log_group_arn",
	"egress",
	"ingress",
	"kms_key_id",
	"kms_key",
	"kms_master_key_id",
	"policy",
	"policy_document",
	"publicly_accessible",
	"security_group_ids",
	"subnet_id",
	"subnet_ids",
	"tags",
	"tags_all",
	"vpc_id",
}

taggable_resource_types := {
	"aws_cloudwatch_log_group",
	"aws_cloudwatch_metric_alarm",
	"aws_eks_addon",
	"aws_eks_cluster",
	"aws_eks_node_group",
	"aws_fis_experiment_template",
	"aws_dynamodb_table",
	"aws_ecr_repository",
	"aws_iam_policy",
	"aws_iam_role",
	"aws_kms_key",
	"aws_opensearch_domain",
	"aws_route_table",
	"aws_s3_bucket",
	"aws_secretsmanager_secret",
	"aws_sns_topic",
	"aws_security_group",
	"aws_subnet",
	"aws_vpc",
	"aws_vpc_endpoint",
}

supported_aws_resource_types := {
	"aws_bedrock_model_invocation_logging_configuration",
	"aws_cloudwatch_log_group",
	"aws_cloudwatch_log_resource_policy",
	"aws_cloudwatch_dashboard",
	"aws_cloudwatch_metric_alarm",
	"aws_default_security_group",
	"aws_dynamodb_table",
	"aws_ecr_lifecycle_policy",
	"aws_ecr_repository",
	"aws_eks_access_entry",
	"aws_eks_access_policy_association",
	"aws_eks_addon",
	"aws_eks_cluster",
	"aws_eks_node_group",
	"aws_eks_pod_identity_association",
	"aws_fis_experiment_template",
	"aws_iam_policy",
	"aws_iam_role",
	"aws_iam_role_policy_attachment",
	"aws_iam_role_policy",
	"aws_internet_gateway",
	"aws_kms_alias",
	"aws_kms_key",
	"aws_nat_gateway",
	"aws_opensearch_domain",
	"aws_route_table",
	"aws_route_table_association",
	"aws_s3_bucket",
	"aws_s3_bucket_lifecycle_configuration",
	"aws_s3_bucket_ownership_controls",
	"aws_s3_bucket_policy",
	"aws_s3_bucket_public_access_block",
	"aws_s3_bucket_server_side_encryption_configuration",
	"aws_s3_bucket_versioning",
	"aws_secretsmanager_secret",
	"aws_sns_topic",
	"aws_sns_topic_subscription",
	"aws_security_group",
	"aws_subnet",
	"aws_vpc",
	"aws_vpc_endpoint",
}

supported_action_sequences := {
	json.marshal(["create"]),
	json.marshal(["update"]),
	json.marshal(["delete"]),
	json.marshal(["delete", "create"]),
	json.marshal(["create", "delete"]),
	json.marshal(["no-op"]),
	json.marshal(["read"]),
}

bootstrap_recovery_dynamodb_address := "aws_dynamodb_table.terraform_lock"
bootstrap_recovery_kms_address := "aws_kms_key.terraform_state"
bootstrap_recovery_bucket_address := "aws_s3_bucket.terraform_state"
bootstrap_recovery_expiry_address := "terraform_data.owner_expiry_gate"

bootstrap_recovery_update_addresses := {
	bootstrap_recovery_kms_address,
	bootstrap_recovery_bucket_address,
	bootstrap_recovery_expiry_address,
}

approved_dynamodb_grant_statement := {
	"Sid": "AllowExactAccountDynamoDBStateGrant",
	"Effect": "Allow",
	"Principal": {"AWS": "arn:aws:iam::526338061652:root"},
	"Action": "kms:CreateGrant",
	"Resource": "*",
	"Condition": {
		"StringEquals": {"kms:CallerAccount": "526338061652"},
		"StringLike": {"kms:ViaService": "dynamodb.*.amazonaws.com"},
	},
}

approved_endpoint_services := {
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

platform_vpc_address := "module.network.aws_vpc.this"
platform_kms_address := "module.kms.aws_kms_key.this"
platform_subnet_addresses := [
	"module.network.aws_subnet.private[0]",
	"module.network.aws_subnet.private[1]",
]

platform_endpoint_security_group_address := "module.network.aws_security_group.endpoints"
opensearch_domain_address := "module.opensearch.aws_opensearch_domain.this"
opensearch_admin_role_address := "module.iam.aws_iam_role.opensearch_administrator"
opensearch_password_field_path := "advanced_security_options[].master_user_options[].master_user_password"
opensearch_sensitive_relationship := "omitted-null-password-with-structurally-resolved-admin-role"
opensearch_existing_sensitive_relationship := "omitted-null-password-with-existing-admin-role"
platform_runtime_policy_address := "module.iam.aws_iam_role_policy.runtime"
platform_fis_policy_address := "module.iam.aws_iam_role_policy.fis"
platform_fis_cluster_arn := "arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox"
platform_runtime_policy_legacy_bedrock_sid := "InvokeExactApprovedInferenceProfile"
platform_runtime_policy_expiry_statement_sids := {
	"InvokeExactGlobalInferenceProfile",
	"InvokeExactGlobalInferenceProfileRegionalModel",
	"InvokeExactGlobalInferenceProfileGlobalModel",
}

platform_runtime_policy_expiry_paths := {
	"policy.Statement[Sid=InvokeExactGlobalInferenceProfile].Condition.DateLessThan.aws:CurrentTime",
	"policy.Statement[Sid=InvokeExactGlobalInferenceProfileRegionalModel].Condition.DateLessThan.aws:CurrentTime",
	"policy.Statement[Sid=InvokeExactGlobalInferenceProfileGlobalModel].Condition.DateLessThan.aws:CurrentTime",
}

platform_runtime_role_arn := "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"
platform_global_inference_profile_arn := "arn:aws:bedrock:ap-southeast-1:526338061652:inference-profile/global.amazon.nova-2-lite-v1:0"
platform_regional_foundation_model_arn := "arn:aws:bedrock:ap-southeast-1::foundation-model/amazon.nova-2-lite-v1:0"
platform_global_foundation_model_arn := "arn:aws:bedrock:::foundation-model/amazon.nova-2-lite-v1:0"

platform_gateway_endpoint_addresses := {
	`module.network.aws_vpc_endpoint.gateway["DynamoDB"]`,
	`module.network.aws_vpc_endpoint.gateway["S3"]`,
}

platform_interface_endpoint_addresses := {
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

w6_004_node_policy_attachment_addresses := {
	`module.eks[0].aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"]`: "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
	`module.eks[0].aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]`: "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
	`module.eks[0].aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]`: "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
}

w6_004_alert_subscription_addresses := {
	`module.observability[0].aws_sns_topic_subscription.email["vayunetrix.aws.dev@zohomail.com"]`: "vayunetrix.aws.dev@zohomail.com",
	`module.observability[0].aws_sns_topic_subscription.email["vayunetrix.aws.stage@zohomail.com"]`: "vayunetrix.aws.stage@zohomail.com",
}

w6_004_special_aws_addresses := object.keys(w6_004_node_policy_attachment_addresses) | object.keys(w6_004_alert_subscription_addresses)

w6_004_interface_endpoint_names := {
	"Bedrock Runtime",
	"CloudWatch Logs",
	"CloudWatch Monitoring",
	"EC2",
	"ECR API",
	"ECR DKR",
	"EKS",
	"EKS Auth",
	"KMS",
	"STS",
	"Secrets Manager",
	"X-Ray",
}

w6_004_endpoint_policy_document_relationships := {
{
	"resource_address": sprintf(`module.network.aws_vpc_endpoint.interface["%s"]`, [name]),
	"resource_type": "aws_vpc_endpoint",
	"field_path": "policy",
	"policy_document_address": sprintf(`module.network.data.aws_iam_policy_document.interface_endpoint["%s"]`, [name]),
	"relationship": "exact-policy-document",
} |
	some name in w6_004_interface_endpoint_names
} | {
{
	"resource_address": sprintf(`module.network.aws_vpc_endpoint.gateway["%s"]`, [name]),
	"resource_type": "aws_vpc_endpoint",
	"field_path": "policy",
	"policy_document_address": sprintf(`module.network.data.aws_iam_policy_document.gateway_endpoint["%s"]`, [name]),
	"relationship": "exact-policy-document",
} |
	some name in {"DynamoDB", "S3"}
}

w6_004_eks_policy_document_relationships := {
	{
		"resource_address": "module.eks[0].aws_iam_role.cluster",
		"resource_type": "aws_iam_role",
		"field_path": "assume_role_policy",
		"policy_document_address": "module.eks[0].data.aws_iam_policy_document.cluster_assume",
		"relationship": "exact-policy-document",
	},
	{
		"resource_address": "module.eks[0].aws_iam_role.node",
		"resource_type": "aws_iam_role",
		"field_path": "assume_role_policy",
		"policy_document_address": "module.eks[0].data.aws_iam_policy_document.node_assume",
		"relationship": "exact-policy-document",
	},
}

w6_004_policy_document_relationships := w6_004_endpoint_policy_document_relationships | w6_004_eks_policy_document_relationships

platform_vpc_reference_consumers := (platform_gateway_endpoint_addresses | platform_interface_endpoint_addresses) | {
	"module.network.aws_default_security_group.restricted",
	"module.network.aws_route_table.private",
	"module.network.aws_security_group.endpoints",
	"module.network.aws_subnet.private[0]",
	"module.network.aws_subnet.private[1]",
}

platform_log_group_addresses := {
	`module.opensearch.aws_cloudwatch_log_group.this["application"]`,
	`module.opensearch.aws_cloudwatch_log_group.this["audit"]`,
	`module.opensearch.aws_cloudwatch_log_group.this["index_slow"]`,
	`module.opensearch.aws_cloudwatch_log_group.this["search_slow"]`,
}

platform_recovery_create_resources := {
	`module.opensearch.aws_cloudwatch_log_group.this["application"]`: "aws_cloudwatch_log_group",
	`module.opensearch.aws_cloudwatch_log_group.this["audit"]`: "aws_cloudwatch_log_group",
	`module.opensearch.aws_cloudwatch_log_group.this["index_slow"]`: "aws_cloudwatch_log_group",
	`module.opensearch.aws_cloudwatch_log_group.this["search_slow"]`: "aws_cloudwatch_log_group",
	"module.opensearch.aws_opensearch_domain.this": "aws_opensearch_domain",
}

platform_recovery_update_resources := {
	"module.ecr.aws_ecr_repository.this": "aws_ecr_repository",
	"module.iam.aws_iam_role.github_oidc": "aws_iam_role",
	"module.iam.aws_iam_role.ingestion": "aws_iam_role",
	"module.iam.aws_iam_role.opensearch_administrator": "aws_iam_role",
	"module.iam.aws_iam_role.runtime": "aws_iam_role",
	"module.iam.aws_iam_role_policy.fis": "aws_iam_role_policy",
	"module.iam.aws_iam_role_policy.runtime": "aws_iam_role_policy",
	"module.kms.aws_kms_key.this": "aws_kms_key",
	"module.network.aws_default_security_group.restricted": "aws_default_security_group",
	"module.network.aws_route_table.private": "aws_route_table",
	"module.network.aws_security_group.endpoints": "aws_security_group",
	"module.network.aws_subnet.private[0]": "aws_subnet",
	"module.network.aws_subnet.private[1]": "aws_subnet",
	"module.network.aws_vpc.this": "aws_vpc",
	`module.network.aws_vpc_endpoint.gateway["DynamoDB"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.gateway["S3"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["Bedrock Runtime"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["CloudWatch Logs"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["ECR API"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["ECR DKR"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["EKS"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["KMS"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["STS"]`: "aws_vpc_endpoint",
	`module.network.aws_vpc_endpoint.interface["Secrets Manager"]`: "aws_vpc_endpoint",
	"module.storage.aws_s3_bucket.this": "aws_s3_bucket",
	"terraform_data.owner_expiry_gate": "terraform_data",
}

platform_recovery_passive_resources := {
	"module.ecr.aws_ecr_lifecycle_policy.retain_exact_count": "aws_ecr_lifecycle_policy",
	"module.iam.aws_iam_role_policy.ingestion": "aws_iam_role_policy",
	"module.iam.data.aws_iam_policy_document.administrator_trust": "aws_iam_policy_document",
	"module.iam.data.aws_iam_policy_document.github_trust": "aws_iam_policy_document",
	"module.iam.data.aws_iam_policy_document.ingestion": "aws_iam_policy_document",
	"module.iam.data.aws_iam_policy_document.ingestion_trust": "aws_iam_policy_document",
	"module.iam.data.aws_iam_policy_document.runtime": "aws_iam_policy_document",
	"module.iam.data.aws_iam_policy_document.runtime_trust": "aws_iam_policy_document",
	"module.kms.aws_kms_alias.this": "aws_kms_alias",
	"module.kms.data.aws_iam_policy_document.this": "aws_iam_policy_document",
	"module.network.aws_route_table_association.private[0]": "aws_route_table_association",
	"module.network.aws_route_table_association.private[1]": "aws_route_table_association",
	"module.opensearch.aws_cloudwatch_log_resource_policy.opensearch": "aws_cloudwatch_log_resource_policy",
	"module.opensearch.data.aws_iam_policy_document.domain_access": "aws_iam_policy_document",
	"module.opensearch.data.aws_iam_policy_document.log_delivery": "aws_iam_policy_document",
	"module.storage.aws_s3_bucket_lifecycle_configuration.this": "aws_s3_bucket_lifecycle_configuration",
	"module.storage.aws_s3_bucket_ownership_controls.this": "aws_s3_bucket_ownership_controls",
	"module.storage.aws_s3_bucket_policy.tls_only": "aws_s3_bucket_policy",
	"module.storage.aws_s3_bucket_public_access_block.this": "aws_s3_bucket_public_access_block",
	"module.storage.aws_s3_bucket_server_side_encryption_configuration.this": "aws_s3_bucket_server_side_encryption_configuration",
	"module.storage.aws_s3_bucket_versioning.this": "aws_s3_bucket_versioning",
	"module.storage.data.aws_iam_policy_document.tls_only": "aws_iam_policy_document",
}

platform_recovery_resources := object.union(
	object.union(platform_recovery_create_resources, platform_recovery_update_resources),
	platform_recovery_passive_resources,
)

platform_policy_document_relationships := {
	{
		"resource_address": "module.iam.aws_iam_role_policy.ingestion",
		"resource_type": "aws_iam_role_policy",
		"field_path": "policy",
		"policy_document_address": "module.iam.data.aws_iam_policy_document.ingestion",
		"relationship": "exact-policy-document",
	},
	{
		"resource_address": "module.iam.aws_iam_role_policy.runtime",
		"resource_type": "aws_iam_role_policy",
		"field_path": "policy",
		"policy_document_address": "module.iam.data.aws_iam_policy_document.runtime",
		"relationship": "exact-policy-document",
	},
	{
		"resource_address": "module.kms.aws_kms_key.this",
		"resource_type": "aws_kms_key",
		"field_path": "policy",
		"policy_document_address": "module.kms.data.aws_iam_policy_document.this",
		"relationship": "exact-policy-document",
	},
	{
		"resource_address": "module.storage.aws_s3_bucket_policy.tls_only",
		"resource_type": "aws_s3_bucket_policy",
		"field_path": "policy",
		"policy_document_address": "module.storage.data.aws_iam_policy_document.tls_only",
		"relationship": "exact-policy-document",
	},
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
} | w6_004_policy_document_relationships

approved_log_types := {
	"ES_APPLICATION_LOGS",
	"AUDIT_LOGS",
	"INDEX_SLOW_LOGS",
	"SEARCH_SLOW_LOGS",
}

approved_wildcard_arns := {
	"arn:aws:s3:::enterprise-ai-platform-sandbox-tfstate-526338061652-ap-southeast-1/*",
	"arn:aws:s3:::enterprise-ai-platform-526338061652-ap-southeast-1-sandbox/*",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs:*",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/audit-logs:*",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/index-slow-logs:*",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/search-slow-logs:*",
	"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/*",
	"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
	"arn:aws:bedrock:*:526338061652:inference-profile/global.amazon.nova-2-lite-v1:0",
}

exception_keys := {
	"exception_id",
	"policy_id",
	"resource_addresses",
	"owner",
	"approver",
	"rationale",
	"evidence_reference",
	"issued_at",
	"expires_at",
	"status",
}

resource_changes := object.get(input, "resource_changes", []) if is_object(input)
evaluation_context := object.get(input, "evaluation_context", {}) if is_object(input)
provider_computed_unknowns := object.get(evaluation_context, "provider_computed_unknowns", [])
resource_reference_unknowns := object.get(evaluation_context, "resource_reference_unknowns", [])
policy_document_bindings := object.get(evaluation_context, "policy_document_bindings", [])
s3_bucket_policy_bindings := object.get(evaluation_context, "s3_bucket_policy_bindings", [])
s3_kms_encryption_bindings := object.get(evaluation_context, "s3_kms_encryption_bindings", [])
provider_sensitive_nulls := object.get(evaluation_context, "provider_sensitive_nulls", [])

after(change) := object.get(object.get(change, "change", {}), "after", null)

valid_utc_timestamp(value) if {
	is_string(value)
	endswith(value, "Z")
	count(value) <= 40
	time.parse_rfc3339_ns(value)
}

evaluation_time_ns := value if {
	timestamp := object.get(evaluation_context, "evaluation_time", "")
	valid_utc_timestamp(timestamp)
	value := time.parse_rfc3339_ns(timestamp)
}

valid_resource_address(address) if {
	is_string(address)
	count(address) > 0
	count(address) <= 240
	regex.match(`^[A-Za-z0-9_.\[\]"-]+$`, address)
	regex.match(`(^|\.)aws_[a-z0-9_]+\.[A-Za-z0-9_"\[\]-]+$`, address)
}

valid_resource_address(address) if {
	address in platform_interface_endpoint_addresses
}

valid_resource_address(address) if {
	address in w6_004_special_aws_addresses
}

supported_change_type(resource_type) if {
	resource_type in supported_aws_resource_types
}

valid_change_after(actions, value) if {
	json.marshal(actions) == json.marshal(["delete"])
	value == null
}

valid_change_after(actions, value) if {
	json.marshal(actions) == json.marshal(["delete"])
	is_object(value)
}

valid_change_after(actions, value) if {
	json.marshal(actions) != json.marshal(["delete"])
	is_object(value)
}

policy_critical_unknown_present(unknowns) if {
	some key in policy_critical_unknown_keys
	contains(json.marshal(unknowns), sprintf(`"%s":true`, [key]))
}

change_has_no_policy_critical_unknown_values(change_body) if {
	unknowns := object.get(change_body, "after_unknown", {})
	not policy_critical_unknown_present(unknowns)
}

valid_aws_change(change) if {
	is_object(change)
	address := object.get(change, "address", "")
	valid_resource_address(address)
	not address in w6_004_special_aws_addresses
	resource_type := object.get(change, "type", "")
	is_string(resource_type)
	supported_change_type(resource_type)
	change_body := object.get(change, "change", null)
	is_object(change_body)
	actions := object.get(change_body, "actions", [])
	is_array(actions)
	json.marshal(actions) in supported_action_sequences
	valid_change_after(actions, object.get(change_body, "after", null))
	change_has_no_policy_critical_unknown_values(change_body)
}

valid_w6_004_runtime_gate_change(change) if {
	is_object(change)
	object.keys(change) == {"address", "change", "type"}
	change.address == "terraform_data.w6_004_runtime_gate[0]"
	change.type == "terraform_data"
	change_body := change.change
	object.keys(change_body) == {"actions", "after", "after_sensitive", "after_unknown", "before", "before_sensitive"}
	change_body.actions == ["create"]
	change_body.before == null
	change_body.before_sensitive == {}
	change_body.after_sensitive == {"input": {}, "output": {}}
	change_body.after_unknown == {"id": true, "input": {}, "output": true}
	after_values := change_body.after
	object.keys(after_values) == {"input", "store", "triggers_replace"}
	after_values.store == null
	after_values.triggers_replace == null
	input_values := after_values.input
	object.keys(input_values) == {"approval_expires_at", "approval_issued_at", "deployment_start"}
	valid_utc_timestamp(input_values.approval_issued_at)
	valid_utc_timestamp(input_values.deployment_start)
	valid_utc_timestamp(input_values.approval_expires_at)
	input_values.approval_issued_at == input_values.deployment_start
	expires_ns := time.parse_rfc3339_ns(input_values.approval_expires_at)
	start_ns := time.parse_rfc3339_ns(input_values.deployment_start)
	expires_ns > start_ns
	expires_ns - start_ns <= day_ns
}

valid_w6_004_node_policy_attachment(change) if {
	is_object(change)
	address := change.address
	expected_policy_arn := w6_004_node_policy_attachment_addresses[address]
	change.type == "aws_iam_role_policy_attachment"
	change_body := change.change
	change_body.actions == ["create"]
	change_body.before == null
	change_body.before_sensitive == {}
	change_body.after_sensitive == {}
	change_body.after_unknown == {"id": true}
	after_values := change_body.after
	object.keys(after_values) == {"policy_arn", "role"}
	after_values.policy_arn == expected_policy_arn
	after_values.role == "enterprise-ai-sandbox-node"
}

valid_w6_004_alert_subscription(change) if {
	is_object(change)
	address := change.address
	expected_endpoint := w6_004_alert_subscription_addresses[address]
	change.type == "aws_sns_topic_subscription"
	change_body := change.change
	change_body.actions == ["create"]
	change_body.before == null
	change_body.before_sensitive == {}
	change_body.after_sensitive == {}
	change_body.after_unknown == {"arn": true, "confirmation_was_authenticated": true, "filter_policy_scope": true, "id": true, "owner_id": true, "pending_confirmation": true, "topic_arn": true}
	after_values := change_body.after
	object.keys(after_values) == {"confirmation_timeout_in_minutes", "delivery_policy", "endpoint", "endpoint_auto_confirms", "filter_policy", "protocol", "raw_message_delivery", "redrive_policy", "region", "replay_policy", "subscription_role_arn"}
	after_values.confirmation_timeout_in_minutes == 1
	after_values.delivery_policy == null
	after_values.endpoint == expected_endpoint
	after_values.endpoint_auto_confirms == false
	after_values.filter_policy == null
	after_values.protocol == "email"
	after_values.raw_message_delivery == false
	after_values.redrive_policy == null
	after_values.region == "ap-southeast-1"
	after_values.replay_policy == null
	after_values.subscription_role_arn == null
}

valid_owner_expiry_gate_change(change) if {
	is_object(change)
	object.keys(change) == {"address", "change", "type"}
	object.get(change, "address", "") == "terraform_data.owner_expiry_gate"
	object.get(change, "type", "") == "terraform_data"

	change_body := object.get(change, "change", null)
	is_object(change_body)
	valid_false_only_sensitive_shape(object.get(change_body, "before_sensitive", {}))
	object.keys(object.remove(change_body, {"before_sensitive"})) == {
		"actions",
		"after",
		"after_sensitive",
		"after_unknown",
		"before",
	}
	object.get(change_body, "actions", []) == ["create"]
	object.get(change_body, "before", false) == null

	after_values := object.get(change_body, "after", null)
	is_object(after_values)
	object.keys(after_values) == {"input", "store", "triggers_replace"}
	object.get(after_values, "store", false) == null
	object.get(after_values, "triggers_replace", false) == null
	expires_at := object.get(after_values, "input", "")
	valid_utc_timestamp(expires_at)
	expires_at_ns := time.parse_rfc3339_ns(expires_at)
	expires_at_ns > evaluation_time_ns
	expires_at_ns - evaluation_time_ns <= day_ns

	object.get(change_body, "after_unknown", null) == {"id": true, "output": true}
	object.get(change_body, "after_sensitive", null) == {}
}

valid_owner_expiry_gate_change(change) if {
	valid_owner_expiry_gate_recovery_update(change)
}

valid_owner_expiry_gate_recovery_update(change) if {
	is_object(change)
	object.keys(change) == {"address", "change", "type"}
	object.get(change, "address", "") == bootstrap_recovery_expiry_address
	object.get(change, "type", "") == "terraform_data"

	change_body := object.get(change, "change", null)
	is_object(change_body)
	valid_false_only_sensitive_shape(object.get(change_body, "before_sensitive", {}))
	object.keys(object.remove(change_body, {"before_sensitive"})) == {
		"actions",
		"after",
		"after_sensitive",
		"after_unknown",
		"before",
	}
	object.get(change_body, "actions", []) == ["update"]

	before_values := object.get(change_body, "before", null)
	after_values := object.get(change_body, "after", null)
	is_object(before_values)
	is_object(after_values)
	object.keys(before_values) == {"id", "input", "output", "store", "triggers_replace"}
	object.keys(after_values) == {"id", "input", "store", "triggers_replace"}
	is_string(object.get(before_values, "id", null))
	object.get(before_values, "id", "") != ""
	object.get(after_values, "id", null) == object.get(before_values, "id", null)
	object.get(before_values, "store", false) == null
	object.get(after_values, "store", false) == null
	object.get(before_values, "triggers_replace", false) == null
	object.get(after_values, "triggers_replace", false) == null

	previous_expiry := object.get(before_values, "input", "")
	next_expiry := object.get(after_values, "input", "")
	valid_utc_timestamp(previous_expiry)
	object.get(before_values, "output", null) == previous_expiry
	valid_utc_timestamp(next_expiry)
	next_expiry != previous_expiry
	next_expiry_ns := time.parse_rfc3339_ns(next_expiry)
	next_expiry_ns > evaluation_time_ns
	next_expiry_ns - evaluation_time_ns <= day_ns

	object.get(change_body, "after_unknown", null) == {"output": true}
	object.get(change_body, "after_sensitive", null) == {}
}

valid_expiry_reconciliation(before_tags, after_tags, expected_expiry) if {
	is_object(before_tags)
	is_object(after_tags)
	object.keys(before_tags) == object.keys(after_tags)
	object.remove(before_tags, {"ExpiresAt"}) == object.remove(after_tags, {"ExpiresAt"})
	previous_expiry := object.get(before_tags, "ExpiresAt", "")
	next_expiry := object.get(after_tags, "ExpiresAt", "")
	valid_utc_timestamp(previous_expiry)
	valid_utc_timestamp(next_expiry)
	next_expiry != previous_expiry
	next_expiry == expected_expiry
	next_expiry_ns := time.parse_rfc3339_ns(next_expiry)
	next_expiry_ns > evaluation_time_ns
	next_expiry_ns - evaluation_time_ns <= day_ns
}

valid_normalized_recovery_update(change, address, resource_type) if {
	is_object(change)
	object.keys(change) == {"address", "change", "type"}
	object.get(change, "address", "") == address
	object.get(change, "type", "") == resource_type
	change_body := object.get(change, "change", null)
	is_object(change_body)
	valid_false_only_sensitive_shape(object.get(change_body, "before_sensitive", {}))
	object.keys(object.remove(change_body, {"before_sensitive"})) == {
		"actions",
		"after",
		"after_sensitive",
		"after_unknown",
		"before",
	}
	object.get(change_body, "actions", []) == ["update"]
	is_object(object.get(change_body, "before", null))
	is_object(object.get(change_body, "after", null))
	change_has_no_sensitive_markers(change)
	change_has_no_policy_critical_unknown_values(change_body)
}

valid_bootstrap_bucket_recovery_update(change) if {
	valid_normalized_recovery_update(
		change,
		bootstrap_recovery_bucket_address,
		"aws_s3_bucket",
	)
	change_body := change.change
	before_values := change_body.before
	after_values := change_body.after
	object.remove(before_values, {"tags", "tags_all"}) == object.remove(after_values, {"tags", "tags_all"})
	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
	next_expiry := expiry_change.change.after.input
	valid_expiry_reconciliation(before_values.tags, after_values.tags, next_expiry)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, next_expiry)
}

valid_dynamodb_grant_policy_delta(before_policy, after_policy) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	is_object(before_document)
	is_object(after_document)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})
	before_statements := object.get(before_document, "Statement", [])
	after_statements := object.get(after_document, "Statement", [])
	is_array(before_statements)
	is_array(after_statements)
	count(after_statements) == count(before_statements) + 1
	before_statement_set := {json.marshal(statement) | some statement in before_statements}
	after_statement_set := {json.marshal(statement) | some statement in after_statements}
	count(before_statement_set) == count(before_statements)
	count(after_statement_set) == count(after_statements)
	every statement in before_statements {
		json.marshal(statement) in after_statement_set
	}
	json.marshal(approved_dynamodb_grant_statement) in after_statement_set
	not json.marshal(approved_dynamodb_grant_statement) in before_statement_set
}

valid_bootstrap_kms_recovery_update(change) if {
	valid_normalized_recovery_update(
		change,
		bootstrap_recovery_kms_address,
		"aws_kms_key",
	)
	change_body := change.change
	before_values := change_body.before
	after_values := change_body.after
	object.remove(before_values, {"policy", "tags", "tags_all"}) == object.remove(after_values, {"policy", "tags", "tags_all"})
	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
	next_expiry := expiry_change.change.after.input
	valid_expiry_reconciliation(before_values.tags, after_values.tags, next_expiry)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, next_expiry)
	valid_dynamodb_grant_policy_delta(before_values.policy, after_values.policy)
}

valid_bootstrap_dynamodb_recovery_create(change) if {
	is_object(change)
	object.keys(change) == {"address", "change", "type"}
	object.get(change, "address", "") == bootstrap_recovery_dynamodb_address
	object.get(change, "type", "") == "aws_dynamodb_table"
	change_body := object.get(change, "change", null)
	is_object(change_body)
	object.get(change_body, "actions", []) == ["create"]
	object.get(change_body, "before", false) == null
	object.get(change_body, "after_sensitive", {}) == {}
	change_has_no_policy_critical_unknown_values(change_body)
	after_values := object.get(change_body, "after", null)
	is_object(after_values)
	object.get(after_values, "billing_mode", "") == "PAY_PER_REQUEST"
	object.get(after_values, "hash_key", "") == "LockID"
	object.get(after_values, "attribute", []) == [{"name": "LockID", "type": "S"}]
	some recovery in object.get(after_values, "point_in_time_recovery", [])
	object.get(recovery, "enabled", false)
	some encryption in object.get(after_values, "server_side_encryption", [])
	object.get(encryption, "enabled", false)
	kms_key_arn := object.get(encryption, "kms_key_arn", "")
	regex.match(`^arn:aws:kms:ap-southeast-1:526338061652:key/[A-Za-z0-9-]+$`, kms_key_arn)
	fixed_tags_valid(tags_for(change))
	expires_at_valid(tags_for(change))
}

partial_bootstrap_recovery_has_destructive_change if {
	some change in resource_changes
	"delete" in object.get(change.change, "actions", [])
}

partial_bootstrap_recovery_plan_valid if {
	create_addresses := {
	change.address |
		some change in resource_changes
		object.get(change.change, "actions", []) == ["create"]
	}
	create_addresses == {bootstrap_recovery_dynamodb_address}

	update_addresses := {
	change.address |
		some change in resource_changes
		object.get(change.change, "actions", []) == ["update"]
	}
	update_addresses == bootstrap_recovery_update_addresses

	not partial_bootstrap_recovery_has_destructive_change

	dynamodb_change := changes_by_address[bootstrap_recovery_dynamodb_address]
	valid_bootstrap_dynamodb_recovery_create(dynamodb_change)
	kms_change := changes_by_address[bootstrap_recovery_kms_address]
	valid_bootstrap_kms_recovery_update(kms_change)
	bucket_change := changes_by_address[bootstrap_recovery_bucket_address]
	valid_bootstrap_bucket_recovery_update(bucket_change)
	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
}

valid_platform_recovery_create(change) if {
	expected_type := platform_recovery_create_resources[change.address]
	change.type == expected_type
	change.change.actions == ["create"]
	object.get(change.change, "before", false) == null
	valid_aws_change(change)
	change_has_no_sensitive_markers(change)
}

runtime_policy_expiry_statements(document) := {sid: statement |
	some statement in object.get(document, "Statement", [])
	is_object(statement)
	sid := object.get(statement, "Sid", "")
	platform_runtime_policy_expiry_statement_sids[sid]
}

runtime_policy_nonexpiry_statement_set(document) := {
json.marshal(statement) |
	some statement in object.get(document, "Statement", [])
	is_object(statement)
	sid := object.get(statement, "Sid", "")
	not platform_runtime_policy_expiry_statement_sids[sid]
}

valid_runtime_policy_expiry_statement_delta(before_statement, after_statement, next_expiry) if {
	object.remove(before_statement, {"Condition"}) == object.remove(after_statement, {"Condition"})

	before_condition := object.get(before_statement, "Condition", null)
	after_condition := object.get(after_statement, "Condition", null)
	is_object(before_condition)
	is_object(after_condition)
	object.remove(before_condition, {"DateLessThan"}) == object.remove(after_condition, {"DateLessThan"})

	before_date_less_than := object.get(before_condition, "DateLessThan", null)
	after_date_less_than := object.get(after_condition, "DateLessThan", null)
	is_object(before_date_less_than)
	is_object(after_date_less_than)
	object.keys(before_date_less_than) == {"aws:CurrentTime"}
	object.keys(after_date_less_than) == {"aws:CurrentTime"}
	previous_expiry := object.get(before_date_less_than, "aws:CurrentTime", "")
	policy_expiry := object.get(after_date_less_than, "aws:CurrentTime", "")
	valid_utc_timestamp(previous_expiry)
	valid_utc_timestamp(policy_expiry)
	previous_expiry != policy_expiry
	policy_expiry == next_expiry
}

valid_runtime_policy_expiry_delta(before_policy, after_policy, next_expiry) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	is_object(before_document)
	is_object(after_document)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})

	before_statements := object.get(before_document, "Statement", null)
	after_statements := object.get(after_document, "Statement", null)
	is_array(before_statements)
	is_array(after_statements)
	count(before_statements) == count(after_statements)

	before_expiry_statements := runtime_policy_expiry_statements(before_document)
	after_expiry_statements := runtime_policy_expiry_statements(after_document)
	object.keys(before_expiry_statements) == platform_runtime_policy_expiry_statement_sids
	object.keys(after_expiry_statements) == platform_runtime_policy_expiry_statement_sids
	every sid in platform_runtime_policy_expiry_statement_sids {
		valid_runtime_policy_expiry_statement_delta(
			before_expiry_statements[sid],
			after_expiry_statements[sid],
			next_expiry,
		)
	}

	before_other_statements := runtime_policy_nonexpiry_statement_set(before_document)
	after_other_statements := runtime_policy_nonexpiry_statement_set(after_document)
	count(before_other_statements) == count(before_statements) - count(platform_runtime_policy_expiry_statement_sids)
	count(after_other_statements) == count(after_statements) - count(platform_runtime_policy_expiry_statement_sids)
	before_other_statements == after_other_statements
	next_expiry_ns := time.parse_rfc3339_ns(next_expiry)
	next_expiry_ns > evaluation_time_ns
	next_expiry_ns - evaluation_time_ns <= day_ns
}

valid_runtime_policy_expiry_recovery_update(change) if {
	valid_normalized_recovery_update(
		change,
		platform_runtime_policy_address,
		"aws_iam_role_policy",
	)
	object.get(change.change, "after_unknown", null) == {}
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})

	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
	next_expiry := expiry_change.change.after.input
	valid_runtime_policy_expiry_delta(
		object.get(before_values, "policy", null),
		object.get(after_values, "policy", null),
		next_expiry,
	)
}

valid_platform_expiry_recovery_update(change) if {
	change.address != bootstrap_recovery_expiry_address
	change.address != platform_runtime_policy_address
	expected_type := platform_recovery_update_resources[change.address]
	change.type == expected_type
	valid_normalized_recovery_update(change, change.address, change.type)
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"tags", "tags_all"}) == object.remove(after_values, {"tags", "tags_all"})
	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
	next_expiry := expiry_change.change.after.input
	valid_expiry_reconciliation(before_values.tags, after_values.tags, next_expiry)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, next_expiry)
}

valid_platform_expiry_recovery_update(change) if {
	change.address == bootstrap_recovery_expiry_address
	change.type == platform_recovery_update_resources[change.address]
	valid_owner_expiry_gate_recovery_update(change)
}

valid_platform_expiry_recovery_update(change) if {
	change.address == platform_runtime_policy_address
	change.type == platform_recovery_update_resources[change.address]
	valid_runtime_policy_expiry_recovery_update(change)
}

valid_platform_expiry_recovery_update(change) if {
	change.address == platform_kms_address
	change.type == "aws_kms_key"

	expiry_change := changes_by_address[bootstrap_recovery_expiry_address]
	valid_owner_expiry_gate_recovery_update(expiry_change)
	next_expiry := expiry_change.change.after.input

	valid_platform_kms_log_compatibility_update(change, next_expiry)
}

valid_platform_recovery_passive_change(change) if {
	expected_type := platform_recovery_passive_resources[change.address]
	change.type == expected_type
	change.change.actions in [["no-op"], ["read"]]
	valid_change(change)
	change_has_no_sensitive_markers(change)
}

valid_platform_recovery_change(change) if {
	valid_platform_recovery_create(change)
}

valid_platform_recovery_change(change) if {
	valid_platform_expiry_recovery_update(change)
}

valid_platform_recovery_change(change) if {
	valid_platform_recovery_passive_change(change)
}

partial_platform_recovery_plan_valid if {
	create_addresses := {
	change.address |
		some change in resource_changes
		object.get(change.change, "actions", []) == ["create"]
	}
	create_addresses == object.keys(platform_recovery_create_resources)

	update_addresses := {
	change.address |
		some change in resource_changes
		object.get(change.change, "actions", []) == ["update"]
	}
	update_addresses == object.keys(platform_recovery_update_resources)

	every change in resource_changes {
		expected_type := platform_recovery_resources[change.address]
		change.type == expected_type
		valid_platform_recovery_change(change)
	}
}

invalid_sensitive_leaf(value) if {
	walk(value, [_, leaf])
	not is_object(leaf)
	not is_array(leaf)
	leaf != false
}

valid_false_only_sensitive_shape(value) if {
	is_object(value)
	not invalid_sensitive_leaf(value)
}

change_has_no_sensitive_markers(change) if {
	change_body := object.get(change, "change", {})
	sensitive := object.get(change_body, "after_sensitive", {})
	valid_false_only_sensitive_shape(sensitive)
	valid_false_only_sensitive_shape(object.get(change_body, "before_sensitive", {}))
}

resource_change_matches(address, resource_type) if {
	some change in resource_changes
	change.address == address
	change.type == resource_type
	change_has_no_sensitive_markers(change)
}

resource_address_has_type(address, resource_type) if {
	valid_resource_address(address)
	regex.match(sprintf(`(^|\.)%s\.[A-Za-z0-9_"\[\]-]+$`, [resource_type]), address)
}

valid_binding_paths(paths) if {
	is_array(paths)
	count(paths) > 0
	sort(paths) == paths
	count(paths) == count({path | some path in paths})
	every path in paths {
		is_string(path)
		count(path) > 0
		count(path) <= 180
	}
}

resource_reference_record_exists(address, field_path, relationship) if {
	some binding in resource_reference_unknowns
	binding.address == address
	binding.unknown_paths == [field_path]
	binding.relationship == relationship
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.type == "aws_s3_bucket"
	binding.unknown_paths == ["policy"]
	resource_change_matches(binding.address, binding.type)
	some relationship in s3_bucket_policy_bindings
	relationship.bucket_address == binding.address
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address == "module.eks[0].aws_eks_cluster.this"
	binding.type == "aws_eks_cluster"
	binding.unknown_paths == ["vpc_config[].vpc_id"]
	resource_change_matches(binding.address, binding.type)
	resource_reference_record_exists(
		binding.address,
		"vpc_config[].vpc_id",
		"eks-vpc-derived-from-private-subnets",
	)
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address == "module.observability[0].aws_sns_topic.alerts"
	binding.type == "aws_sns_topic"
	binding.unknown_paths == ["policy"]
	resource_change_matches(binding.address, binding.type)
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.type == "aws_s3_bucket_server_side_encryption_configuration"
	binding.unknown_paths == ["rule[].apply_server_side_encryption_by_default[].kms_master_key_id"]
	resource_change_matches(binding.address, binding.type)
	some relationship in s3_kms_encryption_bindings
	relationship.encryption_address == binding.address
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address in platform_gateway_endpoint_addresses
	binding.type == "aws_vpc_endpoint"
	binding.unknown_paths == ["policy", "security_group_ids", "subnet_ids"]
	resource_change_matches(binding.address, binding.type)
	object.get(after(changes_by_address[binding.address]), "vpc_endpoint_type", "") == "Gateway"
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address in platform_gateway_endpoint_addresses
	binding.type == "aws_vpc_endpoint"
	binding.unknown_paths == ["security_group_ids", "subnet_ids"]
	resource_change_matches(binding.address, binding.type)
	object.get(after(changes_by_address[binding.address]), "vpc_endpoint_type", "") == "Gateway"
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address in platform_interface_endpoint_addresses
	binding.type == "aws_vpc_endpoint"
	binding.unknown_paths == ["policy"]
	resource_change_matches(binding.address, binding.type)
	object.get(after(changes_by_address[binding.address]), "vpc_endpoint_type", "") == "Interface"
}

valid_provider_computed_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {"address", "type", "unknown_paths"}
	binding.address == "module.opensearch.aws_opensearch_domain.this"
	binding.type == "aws_opensearch_domain"
	binding.unknown_paths == ["vpc_options[].vpc_id"]
	resource_change_matches(binding.address, binding.type)
	resource_reference_record_exists(
		binding.address,
		"vpc_options[].vpc_id",
		"opensearch-vpc-derived-from-network",
	)
}

valid_network_vpc_reference(binding) if {
	binding.address in platform_vpc_reference_consumers
	binding.unknown_paths == ["vpc_id"]
	binding.source_addresses == [platform_vpc_address]
	binding.relationship == "network-vpc-reference"
}

valid_eks_vpc_reference(binding) if {
	binding.address == "module.eks[0].aws_eks_cluster.this"
	binding.unknown_paths == ["vpc_config[].vpc_id"]
	binding.source_addresses == [
		platform_subnet_addresses[0],
		platform_subnet_addresses[1],
		platform_vpc_address,
	]
	binding.relationship == "eks-vpc-derived-from-private-subnets"
}

valid_eks_private_subnets_reference(binding) if {
	binding.address == "module.eks[0].aws_eks_cluster.this"
	binding.unknown_paths == ["vpc_config[].subnet_ids"]
	binding.source_addresses == platform_subnet_addresses
	binding.relationship == "network-private-subnets-reference"
}

valid_eks_private_subnets_reference(binding) if {
	binding.address == "module.eks[0].aws_eks_node_group.application"
	binding.unknown_paths == ["subnet_ids"]
	binding.source_addresses == platform_subnet_addresses
	binding.relationship == "network-private-subnets-reference"
}

valid_network_subnet_reference(binding) if {
	binding.address == "module.network.aws_route_table_association.private[0]"
	binding.unknown_paths == ["subnet_id"]
	binding.source_addresses == [platform_subnet_addresses[0]]
	binding.relationship == "network-subnet-reference"
}

valid_network_subnet_reference(binding) if {
	binding.address == "module.network.aws_route_table_association.private[1]"
	binding.unknown_paths == ["subnet_id"]
	binding.source_addresses == [platform_subnet_addresses[1]]
	binding.relationship == "network-subnet-reference"
}

valid_network_subnet_reference(binding) if {
	binding.address == "module.opensearch.aws_opensearch_domain.this"
	binding.unknown_paths == ["vpc_options[].subnet_ids"]
	binding.source_addresses == [platform_subnet_addresses[0]]
	binding.relationship == "network-subnet-reference"
}

valid_private_subnets_reference(binding) if {
	binding.address in platform_interface_endpoint_addresses
	binding.unknown_paths == ["subnet_ids"]
	binding.source_addresses == platform_subnet_addresses
	binding.relationship == "network-private-subnets-reference"
}

valid_endpoint_security_group_reference(binding) if {
	binding.address in platform_interface_endpoint_addresses
	binding.unknown_paths == ["security_group_ids"]
	binding.source_addresses == [platform_endpoint_security_group_address]
	binding.relationship == "network-endpoint-security-group-reference"
}

valid_endpoint_security_group_reference(binding) if {
	binding.address == "module.opensearch.aws_opensearch_domain.this"
	binding.unknown_paths == ["vpc_options[].security_group_ids"]
	binding.source_addresses == [platform_endpoint_security_group_address]
	binding.relationship == "network-endpoint-security-group-reference"
}

valid_kms_reference(binding) if {
	binding.address in platform_log_group_addresses
	binding.unknown_paths == ["kms_key_id"]
	binding.source_addresses == [platform_kms_address]
	binding.relationship == "platform-kms-key-reference"
}

valid_kms_reference(binding) if {
	binding.address == "module.opensearch.aws_opensearch_domain.this"
	binding.unknown_paths == ["encrypt_at_rest[].kms_key_id"]
	binding.source_addresses == [platform_kms_address]
	binding.relationship == "platform-kms-key-reference"
}

valid_kms_reference(binding) if {
	binding.address == "module.storage.aws_s3_bucket_server_side_encryption_configuration.this"
	binding.unknown_paths == ["rule[].apply_server_side_encryption_by_default[].kms_master_key_id"]
	binding.source_addresses == [platform_kms_address]
	binding.relationship == "platform-kms-key-reference"
}

valid_opensearch_vpc_reference(binding) if {
	binding.address == "module.opensearch.aws_opensearch_domain.this"
	binding.unknown_paths == ["vpc_options[].vpc_id"]
	binding.source_addresses == [
		platform_endpoint_security_group_address,
		platform_subnet_addresses[0],
		platform_vpc_address,
	]
	binding.relationship == "opensearch-vpc-derived-from-network"
}

valid_ecr_kms_reference(binding) if {
	binding.address == "module.ecr.aws_ecr_repository.this"
	binding.type == "aws_ecr_repository"
	binding.unknown_paths == ["encryption_configuration[].kms_key"]
	binding.source_addresses == [platform_kms_address]
	binding.relationship == "platform-ecr-kms-key-reference"
	provider_computed_arn_source(platform_kms_address, "aws_kms_key")
}

valid_opensearch_log_groups_reference(binding) if {
	binding.address == opensearch_domain_address
	binding.type == "aws_opensearch_domain"
	binding.unknown_paths == ["log_publishing_options[].cloudwatch_log_group_arn"]
	binding.source_addresses == sort([address | some address in platform_log_group_addresses])
	binding.relationship == "opensearch-log-groups-reference"
	every address in platform_log_group_addresses {
		provider_computed_arn_source(address, "aws_cloudwatch_log_group")
	}
}

provider_computed_arn_source(address, resource_type) if {
	some source in resource_changes
	source.address == address
	source.type == resource_type
	object.get(source.change, "actions", []) == ["create"]
	object.get(after(source), "arn", null) == null
	object.get(object.get(source.change, "after_unknown", {}), "arn", false) == true
	change_has_no_sensitive_markers(source)
}

valid_resource_reference_unknown(binding) if {
	is_object(binding)
	object.keys(binding) == {
		"address",
		"relationship",
		"source_addresses",
		"type",
		"unknown_paths",
	}
	valid_resource_address(binding.address)
	valid_binding_paths(binding.unknown_paths)
	is_array(binding.source_addresses)
	sort(binding.source_addresses) == binding.source_addresses
	count(binding.source_addresses) == count({source | some source in binding.source_addresses})
	resource_change_matches(binding.address, binding.type)
	every source in binding.source_addresses {
		valid_resource_address(source)
		some source_change in resource_changes
		source_change.address == source
		change_has_no_sensitive_markers(source_change)
	}
	valid_approved_resource_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_network_vpc_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_eks_vpc_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_eks_private_subnets_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_network_subnet_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_private_subnets_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_endpoint_security_group_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_kms_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_opensearch_vpc_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_ecr_kms_reference(binding)
}

valid_approved_resource_reference(binding) if {
	valid_opensearch_log_groups_reference(binding)
}

valid_policy_document_binding(binding) if {
	is_object(binding)
	object.keys(binding) == {
		"field_path",
		"policy_document_address",
		"relationship",
		"resource_address",
		"resource_type",
	}
	binding in platform_policy_document_relationships
	resource_change_matches(binding.resource_address, binding.resource_type)
	resource_change_matches(binding.policy_document_address, "aws_iam_policy_document")
}

policy_document_bound(resource_address, policy_document_address) if {
	policy_document_field_bound(resource_address, "policy", policy_document_address)
}

policy_document_field_bound(resource_address, field_path, policy_document_address) if {
	some binding in policy_document_bindings
	binding.resource_address == resource_address
	binding.field_path == field_path
	binding.policy_document_address == policy_document_address
	valid_policy_document_binding(binding)
}

valid_bound_policy_document_change(change) if {
	is_object(change)
	change.type == "aws_iam_policy_document"
	some binding in policy_document_bindings
	binding.policy_document_address == change.address
	change_body := object.get(change, "change", null)
	is_object(change_body)
	object.get(change_body, "actions", []) == ["read"]
	valid_change_after(["read"], object.get(change_body, "after", null))
	change_has_no_policy_critical_unknown_values(change_body)
	change_has_no_sensitive_markers(change)
}

s3_tls_policy_evidence_valid(change) if {
	s3_tls_policy_valid(change)
}

s3_tls_policy_evidence_valid(change) if {
	change.address == "module.storage.aws_s3_bucket_policy.tls_only"
	policy_document_bound(
		change.address,
		"module.storage.data.aws_iam_policy_document.tls_only",
	)
}

valid_s3_bucket_policy_binding(binding) if {
	is_object(binding)
	object.keys(binding) == {"bucket_address", "policy_address"}
	bucket_address := object.get(binding, "bucket_address", "")
	policy_address := object.get(binding, "policy_address", "")
	valid_resource_address(bucket_address)
	valid_resource_address(policy_address)
	resource_address_has_type(bucket_address, "aws_s3_bucket")
	resource_address_has_type(policy_address, "aws_s3_bucket_policy")
	some bucket in resource_changes
	bucket.address == bucket_address
	bucket.type == "aws_s3_bucket"
	change_has_no_sensitive_markers(bucket)
	some policy in resource_changes
	policy.address == policy_address
	policy.type == "aws_s3_bucket_policy"
	change_has_no_sensitive_markers(policy)
	s3_tls_policy_evidence_valid(policy)
}

valid_s3_kms_encryption_binding(binding) if {
	is_object(binding)
	object.keys(binding) == {
		"bucket_address",
		"encryption_address",
		"field_path",
		"kms_key_address",
	}
	bucket_address := object.get(binding, "bucket_address", "")
	encryption_address := object.get(binding, "encryption_address", "")
	kms_key_address := object.get(binding, "kms_key_address", "")
	object.get(binding, "field_path", "") == "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
	valid_resource_address(bucket_address)
	valid_resource_address(encryption_address)
	valid_resource_address(kms_key_address)
	resource_address_has_type(bucket_address, "aws_s3_bucket")
	resource_address_has_type(encryption_address, "aws_s3_bucket_server_side_encryption_configuration")
	resource_address_has_type(kms_key_address, "aws_kms_key")
	some bucket in resource_changes
	bucket.address == bucket_address
	bucket.type == "aws_s3_bucket"
	change_has_no_sensitive_markers(bucket)
	some encryption in resource_changes
	encryption.address == encryption_address
	encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
	change_has_no_sensitive_markers(encryption)
	s3_kms_algorithm_valid(encryption)
	some key in resource_changes
	key.address == kms_key_address
	key.type == "aws_kms_key"
	change_has_no_sensitive_markers(key)
}

valid_opensearch_provider_sensitive_null(binding) if {
	is_object(binding)
	object.keys(binding) == {
		"address",
		"field_path",
		"relationship",
		"source_address",
		"type",
	}
	binding.address == opensearch_domain_address
	binding.type == "aws_opensearch_domain"
	binding.field_path == opensearch_password_field_path
	binding.relationship == opensearch_sensitive_relationship
	binding.source_address == opensearch_admin_role_address

	domain := changes_by_address[opensearch_domain_address]
	domain.type == "aws_opensearch_domain"
	domain.change.actions == ["create"]
	change_has_no_sensitive_markers(domain)
	advanced_options := object.get(after(domain), "advanced_security_options", [])
	count(advanced_options) == 1
	advanced := advanced_options[0]
	object.get(advanced, "enabled", false) == true
	object.get(advanced, "internal_user_database_enabled", true) == false
	master_options := object.get(advanced, "master_user_options", [])
	count(master_options) == 1
	master := master_options[0]
	object.get(master, "master_user_arn", null) == null
	object.get(master, "master_user_name", null) in {null, ""}
	object.get(master, "master_user_password", null) == null

	domain_unknowns := object.get(domain.change, "after_unknown", {})
	unknown_advanced_options := object.get(domain_unknowns, "advanced_security_options", [])
	count(unknown_advanced_options) == 1
	unknown_master_options := object.get(unknown_advanced_options[0], "master_user_options", [])
	count(unknown_master_options) == 1
	object.get(unknown_master_options[0], "master_user_arn", false) == true
	object.get(unknown_master_options[0], "master_user_password", false) == false

	role := changes_by_address[opensearch_admin_role_address]
	role.type == "aws_iam_role"
	role.change.actions == ["create"]
	change_has_no_sensitive_markers(role)
	object.get(object.get(role.change, "after_unknown", {}), "arn", false) == true
}

valid_existing_opensearch_admin_role_action(role) if {
	role.change.actions == ["no-op"]
	role.change.before == role.change.after
	valid_aws_change(role)
}

valid_existing_opensearch_admin_role_action(role) if {
	valid_platform_expiry_recovery_update(role)
}

valid_admin_trust_expiry_update(role) if {
	role.change.actions == ["update"]
	before := role.change.before
	after := role.change.after
	valid_expiry_reconciliation(before.tags, after.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before.tags_all, after.tags_all, operational.resource_expires_at)
	object.remove(before, {"assume_role_policy", "tags", "tags_all"}) == object.remove(after, {"assume_role_policy", "tags", "tags_all"})

	before_document := json.unmarshal(before.assume_role_policy)
	after_document := json.unmarshal(after.assume_role_policy)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})
	count(before_document.Statement) == 1
	count(after_document.Statement) == 1
	before_statement := before_document.Statement[0]
	after_statement := after_document.Statement[0]
	before_statement.Sid == "TimeBoundExactSandboxAdministrator"
	after_statement.Sid == "TimeBoundExactSandboxAdministrator"
	object.remove(before_statement, {"Condition"}) == object.remove(after_statement, {"Condition"})
	object.remove(before_statement.Condition, {"DateLessThan"}) == object.remove(after_statement.Condition, {"DateLessThan"})
	object.keys(before_statement.Condition.DateLessThan) == {"aws:CurrentTime"}
	object.keys(after_statement.Condition.DateLessThan) == {"aws:CurrentTime"}
	valid_utc_timestamp(before_statement.Condition.DateLessThan["aws:CurrentTime"])
	valid_utc_timestamp(before.tags.ExpiresAt)
	time.parse_rfc3339_ns(before_statement.Condition.DateLessThan["aws:CurrentTime"]) <= time.parse_rfc3339_ns(before.tags.ExpiresAt)
	time.parse_rfc3339_ns(before.tags.ExpiresAt) < time.parse_rfc3339_ns(operational.resource_expires_at)
	after_statement.Condition.DateLessThan["aws:CurrentTime"] == operational.expires_at
}

valid_existing_opensearch_admin_role_action(role) if {
	valid_admin_trust_expiry_update(role)
}

valid_existing_admin_policy_relation(role, before_policy, after_policy) if {
	is_object(role)
	before_policy == after_policy
}

valid_existing_admin_policy_relation(role, before_policy, after_policy) if {
	before_policy != after_policy
	valid_admin_trust_expiry_update(role)
}

valid_opensearch_provider_sensitive_null(binding) if {
	is_object(binding)
	object.keys(binding) == {
		"address",
		"field_path",
		"relationship",
		"source_address",
		"type",
	}
	binding.address == opensearch_domain_address
	binding.type == "aws_opensearch_domain"
	binding.field_path == opensearch_password_field_path
	binding.relationship == opensearch_existing_sensitive_relationship
	binding.source_address == opensearch_admin_role_address

	domain := changes_by_address[opensearch_domain_address]
	domain.type == "aws_opensearch_domain"
	domain.change.actions in [["create"], ["no-op"], ["update"]]
	change_has_no_sensitive_markers(domain)
	advanced_options := object.get(after(domain), "advanced_security_options", [])
	count(advanced_options) == 1
	advanced := advanced_options[0]
	object.get(advanced, "enabled", false) == true
	object.get(advanced, "internal_user_database_enabled", true) == false
	master_options := object.get(advanced, "master_user_options", [])
	count(master_options) == 1
	master := master_options[0]
	master_user_arn := object.get(master, "master_user_arn", null)
	is_string(master_user_arn)
	master_user_arn != ""
	object.get(master, "master_user_name", null) in {null, ""}
	object.get(master, "master_user_password", null) == null

	domain_unknowns := object.get(domain.change, "after_unknown", {})
	unknown_advanced_options := object.get(domain_unknowns, "advanced_security_options", [{"master_user_options": [{}]}])
	count(unknown_advanced_options) == 1
	unknown_master_options := object.get(unknown_advanced_options[0], "master_user_options", [])
	count(unknown_master_options) == 1
	object.get(unknown_master_options[0], "master_user_arn", false) == false
	object.get(unknown_master_options[0], "master_user_password", false) == false

	role := changes_by_address[opensearch_admin_role_address]
	role.type == "aws_iam_role"
	valid_existing_opensearch_admin_role_action(role)
	change_has_no_sensitive_markers(role)
	role_unknowns := object.get(role.change, "after_unknown", {})
	not policy_critical_unknown_present(role_unknowns)
	object.get(role_unknowns, "arn", false) == false
	role_before := object.get(role.change, "before", null)
	role_after := object.get(role.change, "after", null)
	is_object(role_before)
	is_object(role_after)
	object.get(role_before, "arn", "") == master_user_arn
	object.get(role_after, "arn", "") == master_user_arn
	before_policy := object.get(role_before, "assume_role_policy", null)
	after_policy := object.get(role_after, "assume_role_policy", null)
	is_string(before_policy)
	valid_existing_admin_policy_relation(role, before_policy, after_policy)
}

opensearch_sensitive_metadata_required(change) if {
	change.address == opensearch_domain_address
	change.type == "aws_opensearch_domain"
	change.change.actions in [["create"], ["no-op"], ["update"]]
	advanced_options := object.get(after(change), "advanced_security_options", [])
	count(advanced_options) == 1
	advanced := advanced_options[0]
	object.get(advanced, "internal_user_database_enabled", true) == false
	master_options := object.get(advanced, "master_user_options", [])
	count(master_options) == 1
	object.get(master_options[0], "master_user_arn", null) == null
	domain_unknowns := object.get(change.change, "after_unknown", {})
	unknown_advanced_options := object.get(domain_unknowns, "advanced_security_options", [])
	count(unknown_advanced_options) == 1
	unknown_master_options := object.get(unknown_advanced_options[0], "master_user_options", [])
	count(unknown_master_options) == 1
	object.get(unknown_master_options[0], "master_user_arn", false) == true
}

opensearch_sensitive_metadata_required(change) if {
	change.address == opensearch_domain_address
	change.type == "aws_opensearch_domain"
	change.change.actions in [["create"], ["no-op"], ["update"]]
	advanced_options := object.get(after(change), "advanced_security_options", [])
	count(advanced_options) == 1
	advanced := advanced_options[0]
	object.get(advanced, "internal_user_database_enabled", true) == false
	master_options := object.get(advanced, "master_user_options", [])
	count(master_options) == 1
	master_user_arn := object.get(master_options[0], "master_user_arn", null)
	is_string(master_user_arn)
	master_user_arn != ""
}

required_opensearch_sensitive_changes := [
change |
	some change in resource_changes
	opensearch_sensitive_metadata_required(change)
]

valid_binding_context if {
	valid_before_sensitive_context
	is_array(provider_computed_unknowns)
	is_array(resource_reference_unknowns)
	is_array(policy_document_bindings)
	is_array(s3_bucket_policy_bindings)
	is_array(s3_kms_encryption_bindings)
	is_array(provider_sensitive_nulls)
	count(provider_computed_unknowns) == count({json.marshal(binding) | some binding in provider_computed_unknowns})
	count(resource_reference_unknowns) == count({json.marshal(binding) | some binding in resource_reference_unknowns})
	count(policy_document_bindings) == count({json.marshal(binding) | some binding in policy_document_bindings})
	count(s3_bucket_policy_bindings) == count({json.marshal(binding) | some binding in s3_bucket_policy_bindings})
	count(s3_kms_encryption_bindings) == count({json.marshal(binding) | some binding in s3_kms_encryption_bindings})
	count(provider_sensitive_nulls) == count({json.marshal(binding) | some binding in provider_sensitive_nulls})
	count(required_opensearch_sensitive_changes) == count(provider_sensitive_nulls)
	every binding in provider_computed_unknowns {
		valid_provider_computed_unknown(binding)
	}
	every binding in resource_reference_unknowns {
		valid_resource_reference_unknown(binding)
	}
	every binding in policy_document_bindings {
		valid_policy_document_binding(binding)
	}
	every binding in s3_bucket_policy_bindings {
		valid_s3_bucket_policy_binding(binding)
	}
	every binding in s3_kms_encryption_bindings {
		valid_s3_kms_encryption_binding(binding)
	}
	every binding in provider_sensitive_nulls {
		valid_opensearch_provider_sensitive_null(binding)
	}
}

valid_change(change) if {
	valid_aws_change(change)
}

valid_change(change) if {
	valid_owner_expiry_gate_change(change)
}

valid_change(change) if {
	valid_w6_004_runtime_gate_change(change)
}

valid_change(change) if {
	valid_w6_004_node_policy_attachment(change)
}

valid_change(change) if {
	valid_w6_004_alert_subscription(change)
}

valid_change(change) if {
	valid_bound_policy_document_change(change)
}

valid_change(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule := operational_rule(change)
	rule.delta_rule == "W6_004_STAGE3_RECOVERY"
	w6_004_stage3_recovery_delta(change, rule)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

valid_change(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address in w6_004_special_aws_addresses
	change.change.actions == ["no-op"]
	change.change.before == change.change.after
	change.change.before_sensitive == change.change.after_sensitive
	change.change.after_unknown == {}
}

valid_change(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address in {
		"terraform_data.owner_expiry_gate",
		"terraform_data.w6_004_runtime_gate[0]",
	}
	change.type == "terraform_data"
	change.change.actions == ["no-op"]
	change.change.before == change.change.after
	change.change.before_sensitive == change.change.after_sensitive
	change.change.after_unknown == {}
}

valid_policy_context if {
	is_object(evaluation_context)
	timestamp := object.get(evaluation_context, "evaluation_time", "")
	valid_utc_timestamp(timestamp)
	configured_policy_ids := object.get(evaluation_context, "policy_ids", null)
	is_array(configured_policy_ids)
	count(configured_policy_ids) == count(policy_inventory)
	{policy_id | some policy_id in configured_policy_ids} == policy_ids
	valid_binding_context
}

input_contract_valid if {
	is_object(input)
	object.get(input, "format_version", "") != ""
	object.get(input, "terraform_version", "") != ""
	variables := object.get(input, "variables", null)
	is_object(variables)
	changes := object.get(input, "resource_changes", null)
	is_array(changes)
	count(changes) == count({change.address | some change in changes; is_object(change); is_string(change.address)})
	valid_policy_context
	every change in changes {
		valid_change(change)
	}
}

evaluated_changes := resource_changes if input_contract_valid
changes_by_address := {change.address: change | some change in resource_changes}

violation(policy_id, resource_address) := {
	"policy_id": policy_id,
	"resource_address": resource_address,
}

tags_for(change) := tags if {
	values := after(change)
	is_object(values)
	tags := object.get(values, "tags_all", object.get(values, "tags", {}))
	is_object(tags)
}

tags_for(change) := {} if {
	values := after(change)
	is_object(values)
	tags := object.get(values, "tags_all", object.get(values, "tags", {}))
	not is_object(tags)
}

fixed_tags_valid(tags) if {
	count(required_tag_keys - object.keys(tags)) == 0
	object.get(tags, "Project", "") == required_tags.Project
	object.get(tags, "Environment", "") == required_tags.Environment
	object.get(tags, "Owner", "") == required_tags.Owner
	object.get(tags, "ManagedBy", "") == required_tags.ManagedBy
	object.get(tags, "CostCenter", "") == required_tags.CostCenter
	object.get(tags, "Feature", "") == required_tags.Feature
	object.get(tags, "Repository", "") == required_tags.Repository
}

expires_at_valid(tags) if {
	expires_at := object.get(tags, "ExpiresAt", "")
	valid_utc_timestamp(expires_at)
	expires_ns := time.parse_rfc3339_ns(expires_at)
	expires_ns > evaluation_time_ns
	expires_ns - evaluation_time_ns <= day_ns
}

destructive_change(change) if {
	actions := object.get(object.get(change, "change", {}), "actions", [])
	"delete" in actions
}

unapproved_initial_change(change) if {
	actions := object.get(object.get(change, "change", {}), "actions", [])
	"update" in actions
	not partial_bootstrap_recovery_plan_valid
	not partial_platform_recovery_plan_valid
}

unapproved_initial_change(change) if {
	destructive_change(change)
	not approved_partial_recovery_replacement(change)
}

approved_partial_recovery_replacement(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule := operational_rule(change)
	rule.delta_rule == "W6_004_STAGE3_RECOVERY"
	w6_004_stage3_recovery_delta(change, rule)
	change.change.actions == ["delete", "create"]
}

approved_partial_recovery_replacement(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule := operational_rule(change)
	w6_004_bedrock_logging_disable(change, rule)
}

related_address(address, resource_type) := replace(
	address,
	"aws_s3_bucket.",
	sprintf("%s.", [resource_type]),
)

related_change(bucket, resource_type) := change if {
	address := related_address(bucket.address, resource_type)
	change := changes_by_address[address]
}

related_change_exists(bucket, resource_type) if {
	resource_type != "aws_s3_bucket_policy"
	related_change(bucket, resource_type)
}

related_change_exists(bucket, "aws_s3_bucket_policy") if {
	some binding in s3_bucket_policy_bindings
	binding.bucket_address == bucket.address
	policy := changes_by_address[binding.policy_address]
	policy.type == "aws_s3_bucket_policy"
	s3_tls_policy_evidence_valid(policy)
}

s3_public_access_valid(change) if {
	values := after(change)
	object.get(values, "block_public_acls", false)
	object.get(values, "block_public_policy", false)
	object.get(values, "ignore_public_acls", false)
	object.get(values, "restrict_public_buckets", false)
}

s3_kms_algorithm_valid(change) if {
	values := after(change)
	some rule in object.get(values, "rule", [])
	some defaults in object.get(rule, "apply_server_side_encryption_by_default", [])
	object.get(defaults, "sse_algorithm", "") == "aws:kms"
}

s3_encryption_valid(change) if {
	s3_kms_algorithm_valid(change)
	values := after(change)
	some rule in object.get(values, "rule", [])
	some defaults in object.get(rule, "apply_server_side_encryption_by_default", [])
	object.get(defaults, "kms_master_key_id", "") != ""
}

s3_encryption_valid(change) if {
	s3_kms_algorithm_valid(change)
	some binding in s3_kms_encryption_bindings
	binding.encryption_address == change.address
}

s3_versioning_valid(change) if {
	some configuration in object.get(after(change), "versioning_configuration", [])
	object.get(configuration, "status", "") == "Enabled"
}

state_bucket_address(address) if contains(address, "terraform_state")

s3_lifecycle_valid(change, address) if {
	state_bucket_address(address)
	rules := object.get(after(change), "rule", [])
	some rule in rules
	some abort in object.get(rule, "abort_incomplete_multipart_upload", [])
	object.get(abort, "days_after_initiation", 0) == 7
	every candidate in rules {
		count(object.get(candidate, "expiration", [])) == 0
		count(object.get(candidate, "noncurrent_version_expiration", [])) == 0
	}
}

lifecycle_prefix_expires(rules, prefix) if {
	some rule in rules
	some filter in object.get(rule, "filter", [])
	object.get(filter, "prefix", "") == prefix
	some expiration in object.get(rule, "expiration", [])
	object.get(expiration, "days", 0) == 30
}

s3_lifecycle_valid(change, address) if {
	not state_bucket_address(address)
	rules := object.get(after(change), "rule", [])
	some rule in rules
	some abort in object.get(rule, "abort_incomplete_multipart_upload", [])
	object.get(abort, "days_after_initiation", 0) == 7
	some noncurrent in object.get(rule, "noncurrent_version_expiration", [])
	object.get(noncurrent, "noncurrent_days", 0) == 30
	lifecycle_prefix_expires(rules, "tmp/")
	lifecycle_prefix_expires(rules, "test/")
}

s3_tls_policy_valid(change) if {
	policy := lower(object.get(after(change), "policy", ""))
	contains(policy, `"effect":"deny"`)
	contains(policy, "aws:securetransport")
	contains(policy, `"false"`)
}

policy_text(change) := policy if {
	values := after(change)
	is_object(values)
	policy := object.get(
		values,
		"policy",
		object.get(
			values,
			"assume_role_policy",
			object.get(values, "policy_document", ""),
		),
	)
	is_string(policy)
}

policy_has_action_wildcard(policy) if {
	regex.match(`(?i)"Action"\s*:\s*("[^"]*\*"|\[[^\]]*"[^"]*\*)`, policy)
}

policy_has_prohibited_action(policy) if {
	action_fields := regex.find_n(`(?i)"Action"\s*:\s*("[^"]*"|\[[^\]]*\])`, policy, -1)
	some action_field in action_fields
	regex.match(
		`(?i)(kms:\*|es:ESHttp\*|logs:\*|ecr:GetAuthorizationToken|iam:(List|Describe)[A-Za-z0-9]*)`,
		action_field,
	)
}

approved_wildcard_arn(arn) if arn in approved_wildcard_arns

iam_scope_invalid(policy) if {
	regex.match(`(?i)"Resource"\s*:\s*"\*"`, policy)
}

iam_scope_invalid(policy) if {
	regex.match(`(?i)"Principal"\s*:\s*("\*"|\{[^}]*"\*"\s*:\s*"\*")`, policy)
}

iam_scope_invalid(policy) if contains(policy, "repo:gprai/enterprise-ai-platform:")

iam_scope_invalid(policy) if {
	contains(policy, "token.actions.githubusercontent.com:sub")
	not contains(policy, "repo:gprai/enterprize_ai_platform:environment:sandbox")
}

iam_scope_invalid(policy) if {
	wildcard_arns := regex.find_n(`arn:aws:[^",[:space:]]*\*`, policy, -1)
	some wildcard_arn in wildcard_arns
	not approved_wildcard_arn(wildcard_arn)
}

endpoint_services := {
object.get(after(change), "service_name", "") |
	some change in evaluated_changes
	change.type == "aws_vpc_endpoint"
}

vpc_present if {
	some change in evaluated_changes
	change.type == "aws_vpc"
}

network_topology_invalid(change) if {
	change.type in {"aws_internet_gateway", "aws_nat_gateway"}
	after(change) != null
}

network_topology_invalid(change) if {
	change.type == "aws_subnet"
	object.get(after(change), "map_public_ip_on_launch", true)
}

network_topology_invalid(change) if {
	change.type == "aws_vpc"
	not object.get(after(change), "enable_dns_support", false)
}

network_topology_invalid(change) if {
	change.type == "aws_vpc"
	not object.get(after(change), "enable_dns_hostnames", false)
}

network_topology_invalid(change) if {
	change.type == "aws_vpc"
	endpoint_services != approved_endpoint_services
}

network_topology_invalid(change) if {
	change.type == "aws_vpc_endpoint"
	service_name := object.get(after(change), "service_name", "")
	not service_name in approved_endpoint_services
}

network_topology_invalid(change) if {
	change.type == "aws_vpc_endpoint"
	object.get(after(change), "vpc_endpoint_type", "") == "Interface"
	not object.get(after(change), "private_dns_enabled", false)
}

network_topology_invalid(change) if {
	change.type == "aws_route_table"
	serialized := json.marshal(after(change))
	regex.match(`(?i)(0\.0\.0\.0/0|::/0)`, serialized)
}

public_cidr(rule) if {
	some cidr in object.get(rule, "cidr_blocks", [])
	cidr in {"0.0.0.0/0", "::/0"}
}

public_cidr(rule) if {
	some cidr in object.get(rule, "ipv6_cidr_blocks", [])
	cidr == "::/0"
}

network_traffic_invalid(change) if {
	change.type in {"aws_security_group", "aws_default_security_group"}
	some rule in object.get(after(change), "ingress", [])
	public_cidr(rule)
}

network_traffic_invalid(change) if {
	change.type in {"aws_security_group", "aws_default_security_group"}
	count(object.get(after(change), "egress", [])) > 0
}

opensearch_kms_valid(change) if {
	some at_rest in object.get(after(change), "encrypt_at_rest", [])
	object.get(at_rest, "kms_key_id", "") != ""
}

opensearch_kms_valid(change) if {
	resource_reference_record_exists(
		change.address,
		"encrypt_at_rest[].kms_key_id",
		"platform-kms-key-reference",
	)
}

opensearch_security_valid(change) if {
	values := after(change)
	count(object.get(values, "vpc_options", [])) > 0
	some at_rest in object.get(values, "encrypt_at_rest", [])
	object.get(at_rest, "enabled", false)
	opensearch_kms_valid(change)
	some node in object.get(values, "node_to_node_encryption", [])
	object.get(node, "enabled", false)
	some endpoint in object.get(values, "domain_endpoint_options", [])
	object.get(endpoint, "enforce_https", false)
	object.get(endpoint, "tls_security_policy", "") == "Policy-Min-TLS-1-2-2019-07"
}

opensearch_access_policy_valid(change) if {
	values := after(change)
	access_policy := object.get(values, "access_policies", "")
	is_string(access_policy)
	contains(access_policy, "526338061652")
	not regex.match(`(?i)"Principal"\s*:\s*("\*"|\{[^}]*"AWS"\s*:\s*"\*")`, access_policy)
}

opensearch_access_policy_valid(change) if {
	change.address == opensearch_domain_address
	policy_document_field_bound(
		change.address,
		"access_policies",
		"module.opensearch.data.aws_iam_policy_document.domain_access",
	)
}

opensearch_logs_valid(change) if {
	values := after(change)
	options := object.get(values, "log_publishing_options", [])
	count(options) == 4
	{object.get(option, "log_type", "") | some option in options} == approved_log_types
	every option in options {
		object.get(option, "enabled", false)
		opensearch_log_destination_valid(change, option)
	}
	opensearch_access_policy_valid(change)
}

opensearch_log_destination_valid(_, option) if {
	arn := object.get(option, "cloudwatch_log_group_arn", "")
	is_string(arn)
	arn != ""
}

opensearch_log_destination_valid(change, _) if {
	resource_reference_record_exists(
		change.address,
		"log_publishing_options[].cloudwatch_log_group_arn",
		"opensearch-log-groups-reference",
	)
}

log_group_kms_valid(group) if {
	object.get(after(group), "kms_key_id", "") != ""
}

log_group_kms_valid(group) if {
	resource_reference_record_exists(
		group.address,
		"kms_key_id",
		"platform-kms-key-reference",
	)
}

opensearch_log_groups_valid if {
	groups := [change |
		some change in evaluated_changes
		change.address in platform_log_group_addresses
		change.type == "aws_cloudwatch_log_group"
	]
	count(groups) == 4
	every group in groups {
		object.get(after(group), "retention_in_days", 0) == 30
		log_group_kms_valid(group)
	}
}

opensearch_log_resource_policy_valid if {
	some change in evaluated_changes
	change.type == "aws_cloudwatch_log_resource_policy"
	policy := policy_text(change)
	contains(policy, "es.amazonaws.com")
	contains(policy, "logs:CreateLogStream")
	contains(policy, "logs:PutLogEvents")
	contains(policy, "aws:SourceAccount")
	contains(policy, "526338061652")
	contains(policy, "aws:SourceArn")
	contains(
		policy,
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox",
	)
	not policy_has_action_wildcard(policy)
	not iam_scope_invalid(policy)
}

opensearch_log_resource_policy_valid if {
	some change in evaluated_changes
	change.address == "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch"
	change.type == "aws_cloudwatch_log_resource_policy"
	policy_document_field_bound(
		change.address,
		"policy_document",
		"module.opensearch.data.aws_iam_policy_document.log_delivery",
	)
}

ecr_security_valid(change) if {
	values := after(change)
	object.get(values, "image_tag_mutability", "") == "IMMUTABLE"
	some scanning in object.get(values, "image_scanning_configuration", [])
	object.get(scanning, "scan_on_push", false)
	some encryption in object.get(values, "encryption_configuration", [])
	object.get(encryption, "encryption_type", "") == "KMS"
	ecr_kms_key_valid(change, encryption)
}

ecr_kms_key_valid(_, encryption) if {
	kms_key := object.get(encryption, "kms_key", "")
	is_string(kms_key)
	kms_key != ""
}

ecr_kms_key_valid(change, _) if {
	resource_reference_record_exists(
		change.address,
		"encryption_configuration[].kms_key",
		"platform-ecr-kms-key-reference",
	)
}

ecr_lifecycle_valid if {
	some change in evaluated_changes
	change.type == "aws_ecr_lifecycle_policy"
	policy := object.get(after(change), "policy", "")
	contains(policy, `"countType":"imageCountMoreThan"`)
	contains(policy, `"countNumber":10`)
}

secret_material_present if {
	serialized := json.marshal(input)
	regex.match(
		`(?i)"(secret_string|secret_binary|password|master_user_password|passwd|access_key|secret_key|private_key|credential|client_secret|auth_token|api_key)"\s*:`,
		serialized,
	)
}

secret_material_present if {
	some change in resource_changes
	change_body := object.get(change, "change", {})
	sensitive := object.get(change_body, "after_sensitive", {})
	regex.match(`(^|[:,\[])true([,}\]]|$)`, json.marshal(sensitive))
}

secret_material_present if {
	some change in resource_changes
	object.get(change, "type", "") in {
		"aws_iam_access_key",
		"aws_secretsmanager_secret_version",
	}
}

registry_schema_version := data.schema_version
registry_exceptions := data.exceptions

valid_exception_address(address) if {
	valid_resource_address(address)
	not contains(address, "*")
	not contains(address, "?")
	not endswith(address, ".tf")
	not endswith(address, ".py")
	not endswith(address, "/")
}

valid_exception_shape(exception) if {
	is_object(exception)
	object.keys(exception) == exception_keys
	exception_id := exception.exception_id
	is_string(exception_id)
	regex.match(`^W5-EXC-[A-Z0-9][A-Z0-9-]{0,71}$`, exception_id)
	exception.policy_id in policy_ids
	not exception.policy_id in non_exemptible_policy_ids
	addresses := exception.resource_addresses
	is_array(addresses)
	count(addresses) >= 1
	count(addresses) <= 10
	count({address | some address in addresses}) == count(addresses)
	every address in addresses {
		valid_exception_address(address)
	}
	exception.owner == "Gyan Prakash Rai"
	exception.approver == "Gyan Prakash Rai"
	is_string(exception.rationale)
	count(exception.rationale) >= 1
	count(exception.rationale) <= 500
	is_string(exception.evidence_reference)
	count(exception.evidence_reference) >= 1
	count(exception.evidence_reference) <= 256
	valid_utc_timestamp(exception.issued_at)
	valid_utc_timestamp(exception.expires_at)
	issued_ns := time.parse_rfc3339_ns(exception.issued_at)
	expires_ns := time.parse_rfc3339_ns(exception.expires_at)
	expires_ns > issued_ns
	expires_ns - issued_ns <= week_ns
	exception.status in {"ACTIVE", "REVOKED"}
}

unique_exception_ids if {
	ids := {exception.exception_id | some exception in registry_exceptions}
	count(ids) == count(registry_exceptions)
}

unique_exception_bindings if {
	bindings := [
	sprintf("%s|%s", [exception.policy_id, address]) |
		some exception in registry_exceptions
		some address in exception.resource_addresses
	]
	count({binding | some binding in bindings}) == count(bindings)
}

registry_valid if {
	registry_schema_version == "w5-003.policy-exceptions.v1"
	is_array(registry_exceptions)
	unique_exception_ids
	unique_exception_bindings
	every exception in registry_exceptions {
		valid_exception_shape(exception)
	}
}

exception_state(exception) := "REVOKED" if exception.status == "REVOKED"

exception_state(exception) := "FUTURE" if {
	exception.status == "ACTIVE"
	time.parse_rfc3339_ns(exception.issued_at) > evaluation_time_ns
}

exception_state(exception) := "EXPIRED" if {
	exception.status == "ACTIVE"
	time.parse_rfc3339_ns(exception.expires_at) <= evaluation_time_ns
}

exception_state(exception) := "ACTIVE" if {
	exception.status == "ACTIVE"
	time.parse_rfc3339_ns(exception.issued_at) <= evaluation_time_ns
	time.parse_rfc3339_ns(exception.expires_at) > evaluation_time_ns
}

matching_exception(policy_id, resource_address) := exception if {
	registry_valid
	some exception in registry_exceptions
	exception.policy_id == policy_id
	resource_address in exception.resource_addresses
}

matching_exception_exists(policy_id, resource_address) if {
	matching_exception(policy_id, resource_address)
}

exception_status_for(policy_id, resource_address) := "INVALID" if {
	policy_id in policy_ids
	is_string(resource_address)
	not registry_valid
}

exception_status_for(policy_id, resource_address) := state if {
	registry_valid
	exception := matching_exception(policy_id, resource_address)
	state := exception_state(exception)
}

exception_status_for(policy_id, resource_address) := "NONE" if {
	registry_valid
	not matching_exception_exists(policy_id, resource_address)
}

finding_suppressed(policy_id, resource_address) if {
	not policy_id in non_exemptible_policy_ids
	exception := matching_exception(policy_id, resource_address)
	exception_state(exception) == "ACTIVE"
}

raw_violations contains violation("W5-PLAN-001", "policy.input") if {
	not input_contract_valid
}

raw_violations contains violation("W5-REG-001", "policy.region") if {
	variables := object.get(input, "variables", {})
	region := object.get(object.get(variables, "aws_region", {}), "value", "")
	region != "ap-southeast-1"
	input_contract_valid
}

raw_violations contains violation("W5-TAG-001", change.address) if {
	some change in evaluated_changes
	change.type in taggable_resource_types
	after(change) != null
	tags := tags_for(change)
	not fixed_tags_valid(tags)
}

raw_violations contains violation("W5-TAG-002", change.address) if {
	some change in evaluated_changes
	change.type in taggable_resource_types
	after(change) != null
	tags := tags_for(change)
	not expires_at_valid(tags)
	not approved_bedrock_logging_fis_noop(change)
}

raw_violations contains violation("W5-PLAN-002", change.address) if {
	some change in evaluated_changes
	unapproved_initial_change(change)
}

raw_violations contains violation("W5-S3-001", change.address) if {
	some change in evaluated_changes
	change.type == "aws_s3_bucket_public_access_block"
	not s3_public_access_valid(change)
}

raw_violations contains violation("W5-S3-001", bucket.address) if {
	some bucket in evaluated_changes
	bucket.type == "aws_s3_bucket"
	after(bucket) != null
	not related_change_exists(bucket, "aws_s3_bucket_public_access_block")
}

raw_violations contains violation("W5-S3-002", change.address) if {
	some change in evaluated_changes
	change.type == "aws_s3_bucket_server_side_encryption_configuration"
	not s3_encryption_valid(change)
}

raw_violations contains violation("W5-S3-002", bucket.address) if {
	some bucket in evaluated_changes
	bucket.type == "aws_s3_bucket"
	after(bucket) != null
	not related_change_exists(bucket, "aws_s3_bucket_server_side_encryption_configuration")
}

raw_violations contains violation("W5-S3-003", change.address) if {
	some change in evaluated_changes
	change.type == "aws_s3_bucket_versioning"
	not s3_versioning_valid(change)
}

raw_violations contains violation("W5-S3-003", change.address) if {
	some change in evaluated_changes
	change.type == "aws_s3_bucket_lifecycle_configuration"
	not s3_lifecycle_valid(change, change.address)
}

raw_violations contains violation("W5-S3-003", bucket.address) if {
	some bucket in evaluated_changes
	bucket.type == "aws_s3_bucket"
	after(bucket) != null
	not related_change_exists(bucket, "aws_s3_bucket_versioning")
}

raw_violations contains violation("W5-S3-003", bucket.address) if {
	some bucket in evaluated_changes
	bucket.type == "aws_s3_bucket"
	after(bucket) != null
	not related_change_exists(bucket, "aws_s3_bucket_lifecycle_configuration")
}

raw_violations contains violation("W5-S3-004", change.address) if {
	some change in evaluated_changes
	change.type == "aws_s3_bucket_policy"
	not s3_tls_policy_evidence_valid(change)
}

raw_violations contains violation("W5-S3-004", bucket.address) if {
	some bucket in evaluated_changes
	bucket.type == "aws_s3_bucket"
	after(bucket) != null
	not related_change_exists(bucket, "aws_s3_bucket_policy")
}

raw_violations contains violation("W5-KMS-001", change.address) if {
	some change in evaluated_changes
	change.type == "aws_kms_key"
	values := after(change)
	not object.get(values, "enable_key_rotation", false)
}

raw_violations contains violation("W5-KMS-001", change.address) if {
	some change in evaluated_changes
	change.type == "aws_kms_key"
	object.get(after(change), "deletion_window_in_days", 0) != 7
}

raw_violations contains violation("W5-IAM-001", change.address) if {
	some change in evaluated_changes
	change.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_cloudwatch_log_resource_policy"}
	policy := policy_text(change)
	policy_has_action_wildcard(policy)
}

raw_violations contains violation("W5-IAM-001", change.address) if {
	some change in evaluated_changes
	change.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_cloudwatch_log_resource_policy"}
	policy := policy_text(change)
	policy_has_prohibited_action(policy)
}

raw_violations contains violation("W5-IAM-002", change.address) if {
	some change in evaluated_changes
	change.type in {"aws_iam_policy", "aws_iam_role", "aws_iam_role_policy", "aws_cloudwatch_log_resource_policy"}
	policy := policy_text(change)
	iam_scope_invalid(policy)
	not approved_existing_w6_004_iam_policy(change)
}

approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.iam.aws_iam_role_policy.ingestion"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["no-op"]
	change.change.before == change.change.after
}

# Permit only an unchanged existing runtime policy during partial recovery.
approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.iam.aws_iam_role_policy.runtime"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["no-op"]
	change.change.before == change.change.after
	object.get(change.change, "before_sensitive", {}) == object.get(change.change, "after_sensitive", {})
	object.get(change.change, "after_unknown", {}) == {}
}

approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.iam.aws_iam_role_policy.runtime"
	change.type == "aws_iam_role_policy"
	valid_runtime_policy_expiry_delta(
		change.change.before.policy,
		change.change.after.policy,
		operational.resource_expires_at,
	)
}

# Grandfather the runtime policy's unchanged bounded wildcard statements only
# when the operation-bound rule proves the exact r8 OpenSearch index-root repair.
approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.iam.aws_iam_role_policy.runtime"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]

	rule := operational_rule(change)
	rule.delta_rule == "W6_004_STAGE3_RECOVERY"
	rule.update_paths == ["policy"]
	w6_004_stage3_recovery_delta(change, rule)
}

approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.observability[0].aws_iam_role.bedrock_log_delivery"
	change.type == "aws_iam_role"
	change.change.actions == ["create"]
	values := change.change.after
	values.name == "enterprise-ai-sandbox-bedrock-log-delivery"
	json.unmarshal(values.assume_role_policy) == {
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "ExactBedrockLogDeliveryTrust",
			"Effect": "Allow",
			"Principal": {"Service": "bedrock.amazonaws.com"},
			"Action": ["sts:AssumeRole"],
			"Condition": {
				"ArnLike": {"aws:SourceArn": "arn:aws:bedrock:ap-southeast-1:526338061652:*"},
				"StringEquals": {"aws:SourceAccount": "526338061652"},
			},
		}],
	}
}

approved_bedrock_logging_fis_noop(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == "module.observability[0].aws_fis_experiment_template.pod_delete"
	change.type == "aws_fis_experiment_template"
	change.change.actions == ["no-op"]
	change.change.before == change.change.after
	change.change.before_sensitive == change.change.after_sensitive
	change.change.after_unknown == {}
	fixed_tags_valid(change.change.after.tags_all)
	valid_utc_timestamp(change.change.after.tags_all.ExpiresAt)
	time.parse_rfc3339_ns(change.change.after.tags_all.ExpiresAt) <= evaluation_time_ns
	logging := changes_by_address["module.observability[0].aws_bedrock_model_invocation_logging_configuration.this[0]"]
	logging.type == "aws_bedrock_model_invocation_logging_configuration"
	logging.change.actions == ["create"]
	rule := operational_rule(change)
	rule.update_paths == []
	rule.delta_rule == "NONE"
}

# Permit only the exact FIS discovery repair required by the Amazon EKS pod-delete
# action. The bounded wildcard resource and the existing EKS statement remain
# structurally fixed; only ec2:DescribeSubnets is added.
approved_existing_w6_004_iam_policy(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	change.address == platform_fis_policy_address
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]

	rule := operational_rule(change)
	rule.delta_rule == "W6_004_STAGE3_RECOVERY"
	rule.update_paths == ["policy"]
	w6_004_stage3_recovery_delta(change, rule)
}

raw_violations contains violation("W5-NET-001", change.address) if {
	some change in evaluated_changes
	network_topology_invalid(change)
}

raw_violations contains violation("W5-NET-002", change.address) if {
	some change in evaluated_changes
	network_traffic_invalid(change)
}

raw_violations contains violation("W5-OS-001", change.address) if {
	some change in evaluated_changes
	change.type == "aws_opensearch_domain"
	not opensearch_security_valid(change)
}

raw_violations contains violation("W5-OS-002", change.address) if {
	some change in evaluated_changes
	change.type == "aws_opensearch_domain"
	opensearch_security_valid(change)
	not opensearch_logs_valid(change)
}

raw_violations contains violation("W5-OS-002", change.address) if {
	some change in evaluated_changes
	change.type == "aws_opensearch_domain"
	opensearch_security_valid(change)
	opensearch_logs_valid(change)
	not opensearch_log_groups_valid
}

raw_violations contains violation("W5-OS-002", change.address) if {
	some change in evaluated_changes
	change.type == "aws_opensearch_domain"
	opensearch_security_valid(change)
	opensearch_logs_valid(change)
	opensearch_log_groups_valid
	not opensearch_log_resource_policy_valid
}

raw_violations contains violation("W5-ECR-001", change.address) if {
	some change in evaluated_changes
	change.type == "aws_ecr_repository"
	not ecr_security_valid(change)
}

raw_violations contains violation("W5-ECR-002", change.address) if {
	some change in evaluated_changes
	change.type == "aws_ecr_repository"
	ecr_security_valid(change)
	not ecr_lifecycle_valid
}

raw_violations contains violation("W5-SEC-001", "policy.input") if {
	secret_material_present
}

raw_violations contains violation("W5-EXC-001", "policy.exceptions") if {
	not registry_valid
}

safe_finding(item) := {
	"schema_version": "w5-003.policy-finding.v1",
	"policy_id": item.policy_id,
	"severity": metadata.severity,
	"resource_address": item.resource_address,
	"category": metadata.category,
	"remediation_code": metadata.remediation_code,
	"exception_status": exception_status_for(item.policy_id, item.resource_address),
} if {
	metadata := policy_by_id[item.policy_id]
}

effective_findings contains finding if {
	some item in raw_violations
	not finding_suppressed(item.policy_id, item.resource_address)
	finding := safe_finding(item)
}

finding_map := {sprintf("%s|%s|%s", [finding.policy_id, finding.resource_address, finding.remediation_code]): finding |
	some finding in effective_findings
}

finding_keys := sort(object.keys(finding_map))

findings := [
finding_map[key] |
	some index
	key := finding_keys[index]
]

deny := findings

allow if count(findings) == 0

policy_evaluated := true

# The legacy package remains readable for historical offline evidence. Production
# queries only decision and must supply the bound, operation-specific v2 profile.
operational := object.get(evaluation_context, "operation", {})

operational_rule(change) := rule if {
	some rule in object.get(operational, "rules", [])
	rule.address == change.address
	rule.resource_type == change.type
	rule.actions == change.change.actions
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "EXPIRES_AT"
	rule.update_paths == ["tags.ExpiresAt", "tags_all.ExpiresAt"]
	change.address != "terraform_data.owner_expiry_gate"
	change.change.actions == ["update"]
	before_values := change.change.before
	after_values := change.change.after
	is_object(before_values)
	is_object(after_values)
	object.remove(before_values, {"tags", "tags_all"}) == object.remove(after_values, {"tags", "tags_all"})
	valid_expiry_reconciliation(before_values.tags, after_values.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "EXPIRES_AT"
	rule.update_paths == ["tags.ExpiresAt", "tags_all.ExpiresAt"]
	change.address in {
		"module.eks[0].aws_eks_access_entry.administrator",
		"module.eks[0].aws_eks_access_entry.deployment",
		"module.eks[0].aws_eks_access_entry.resilience",
	}
	change.change.actions == ["update"]
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"tags", "tags_all"}) == object.remove(after_values, {"tags", "tags_all"})
	object.keys(before_values.tags) == {"ExpiresAt"}
	after_values.tags == {}
	valid_utc_timestamp(before_values.tags.ExpiresAt)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "EXPIRES_AT"
	rule.update_paths == ["tags.ExpiresAt", "tags_all.ExpiresAt"]
	change.address in {
		"module.eks[0].aws_eks_pod_identity_association.ingestion",
		"module.eks[0].aws_eks_pod_identity_association.runtime",
	}
	change.change.actions == ["update"]
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"external_id", "tags", "tags_all"}) == object.remove(after_values, {"external_id", "tags", "tags_all"})
	object.get(before_values, "external_id", null) == null
	object.get(after_values, "external_id", null) == null
	object.keys(before_values.tags) == {"ExpiresAt"}
	after_values.tags == null
	valid_utc_timestamp(before_values.tags.ExpiresAt)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
	object.get(change.change.after_unknown, "external_id", false) == true
	object.get(change.change.after_unknown, "tags_all", {}) == {}
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "EXPIRES_AT"
	rule.update_paths == ["input"]
	change.address == "terraform_data.owner_expiry_gate"
	valid_owner_expiry_gate_recovery_update(change)
	change.change.after.input == operational.resource_expires_at
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "RUNTIME_IAM_EXPIRY"
	count(rule.update_paths) == count(platform_runtime_policy_expiry_paths)
	{path | some path in rule.update_paths} == platform_runtime_policy_expiry_paths
	change.address == "module.iam.aws_iam_role_policy.runtime"
	valid_runtime_policy_expiry_recovery_update(change)
	changes_by_address["terraform_data.owner_expiry_gate"].change.after.input == operational.resource_expires_at
}

approved_opensearch_log_context_arns := [
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/audit-logs",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/index-slow-logs",
	"arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/search-slow-logs",
]

approved_opensearch_log_encryption_statement := {
	"Sid": "AllowExactOpenSearchLogEncryption",
	"Effect": "Allow",
	"Principal": {"Service": "logs.ap-southeast-1.amazonaws.com"},
	"Action": [
		"kms:Decrypt",
		"kms:DescribeKey",
		"kms:Encrypt",
		"kms:GenerateDataKey",
		"kms:GenerateDataKeyWithoutPlaintext",
		"kms:ReEncryptFrom",
		"kms:ReEncryptTo",
	],
	"Resource": "*",
	"Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": approved_opensearch_log_context_arns}},
}

approved_opensearch_log_encryption_statement_before := object.union(
	approved_opensearch_log_encryption_statement,
	{"Condition": {
		"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": approved_opensearch_log_context_arns},
		"StringEquals": {"kms:ViaService": "logs.ap-southeast-1.amazonaws.com"},
	}},
)

approved_opensearch_log_encryption_actions := {
	"kms:Decrypt",
	"kms:DescribeKey",
	"kms:Encrypt",
	"kms:GenerateDataKey",
	"kms:GenerateDataKeyWithoutPlaintext",
	"kms:ReEncryptFrom",
	"kms:ReEncryptTo",
}

approved_opensearch_log_context_arn_set := {
arn |
	arn := approved_opensearch_log_context_arns[_]
}

exact_string_members(values, expected) if {
	is_array(values)
	count(values) == count(expected)
	{value | value := values[_]} == expected
}

exact_string_value_or_members(value, expected) if {
	is_string(value)
	expected == {value}
}

exact_string_value_or_members(value, expected) if {
	exact_string_members(value, expected)
}

valid_opensearch_log_encryption_statement_core(statement) if {
	object.keys(statement) == {
		"Action",
		"Condition",
		"Effect",
		"Principal",
		"Resource",
		"Sid",
	}
	statement.Sid == "AllowExactOpenSearchLogEncryption"
	statement.Effect == "Allow"
	exact_string_value_or_members(statement.Resource, {"*"})
	statement.Principal == {"Service": "logs.ap-southeast-1.amazonaws.com"}
	exact_string_members(
		statement.Action,
		approved_opensearch_log_encryption_actions,
	)
}

valid_opensearch_log_encryption_statement_after(statement) if {
	valid_opensearch_log_encryption_statement_core(statement)

	condition := statement.Condition
	object.keys(condition) == {"ArnEquals"}

	arn_equals := condition.ArnEquals
	object.keys(arn_equals) == {"kms:EncryptionContext:aws:logs:arn"}

	exact_string_members(
		arn_equals["kms:EncryptionContext:aws:logs:arn"],
		approved_opensearch_log_context_arn_set,
	)
}

valid_opensearch_log_encryption_statement_before(statement) if {
	valid_opensearch_log_encryption_statement_core(statement)

	condition := statement.Condition
	object.keys(condition) == {"ArnEquals", "StringEquals"}

	arn_equals := condition.ArnEquals
	object.keys(arn_equals) == {"kms:EncryptionContext:aws:logs:arn"}
	exact_string_members(
		arn_equals["kms:EncryptionContext:aws:logs:arn"],
		approved_opensearch_log_context_arn_set,
	)

	string_equals := condition.StringEquals
	object.keys(string_equals) == {"kms:ViaService"}
	string_equals["kms:ViaService"] == "logs.ap-southeast-1.amazonaws.com"
}

valid_opensearch_log_viaservice_removal(before_policy, after_policy) if {
	is_string(before_policy)
	is_string(after_policy)

	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)

	is_object(before_document)
	is_object(after_document)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})

	before_statements := object.get(before_document, "Statement", [])
	after_statements := object.get(after_document, "Statement", [])
	is_array(before_statements)
	is_array(after_statements)
	count(before_statements) == count(after_statements)

	before_target := [
	statement |
		statement := before_statements[_]
		object.get(statement, "Sid", "") == "AllowExactOpenSearchLogEncryption"
	]
	after_target := [
	statement |
		statement := after_statements[_]
		object.get(statement, "Sid", "") == "AllowExactOpenSearchLogEncryption"
	]

	count(before_target) == 1
	count(after_target) == 1
	valid_opensearch_log_encryption_statement_before(before_target[0])
	valid_opensearch_log_encryption_statement_after(after_target[0])

	before_other := {
	json.marshal(statement) |
		statement := before_statements[_]
		object.get(statement, "Sid", "") != "AllowExactOpenSearchLogEncryption"
	}
	after_other := {
	json.marshal(statement) |
		statement := after_statements[_]
		object.get(statement, "Sid", "") != "AllowExactOpenSearchLogEncryption"
	}

	count(before_other) == count(before_statements) - 1
	count(after_other) == count(after_statements) - 1
	before_other == after_other
}

valid_platform_kms_log_compatibility_update(change, expected_expiry) if {
	valid_normalized_recovery_update(
		change,
		platform_kms_address,
		"aws_kms_key",
	)

	before_values := change.change.before
	after_values := change.change.after

	object.remove(before_values, {"policy", "tags", "tags_all"}) == object.remove(after_values, {"policy", "tags", "tags_all"})
	valid_expiry_reconciliation(before_values.tags, after_values.tags, expected_expiry)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, expected_expiry)
	valid_opensearch_log_viaservice_removal(before_values.policy, after_values.policy)
}

operational_expiry_delta(change, rule) if {
	rule.delta_rule == "EXPIRES_AT"
	rule.update_paths == ["tags.ExpiresAt", "tags_all.ExpiresAt"]
	change.address == platform_kms_address
	valid_platform_kms_log_compatibility_update(change, operational.resource_expires_at)
}

exact_policy_statement_addition(before_policy, after_policy, target_sid, expected) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})
	before_statements := before_document.Statement
	after_statements := after_document.Statement
	is_array(before_statements)
	is_array(after_statements)
	count(after_statements) == count(before_statements) + 1
	count([statement | some statement in before_statements; object.get(statement, "Sid", "") == target_sid]) == 0
	after_target := [statement | some statement in after_statements; object.get(statement, "Sid", "") == target_sid]
	after_target == [expected]
	{json.marshal(statement) | some statement in before_statements} == {
	json.marshal(statement) |
		some statement in after_statements
		object.get(statement, "Sid", "") != target_sid
	}
}

bedrock_log_kms_statement := {
	"Sid": "AllowExactBedrockInvocationLogEncryption",
	"Effect": "Allow",
	"Principal": {"Service": "bedrock.amazonaws.com"},
	"Action": ["kms:GenerateDataKey"],
	"Resource": ["*"],
	"Condition": {
		"ArnLike": {"aws:SourceArn": "arn:aws:bedrock:ap-southeast-1:526338061652:*"},
		"StringEquals": {"aws:SourceAccount": "526338061652"},
	},
}

bedrock_log_s3_statement := {
	"Sid": "AllowExactBedrockInvocationLogDelivery",
	"Effect": "Allow",
	"Principal": {"Service": "bedrock.amazonaws.com"},
	"Action": ["s3:PutObject"],
	"Resource": ["arn:aws:s3:::enterprise-ai-platform-526338061652-ap-southeast-1-sandbox/bedrock-model-invocations/AWSLogs/526338061652/BedrockModelInvocationLogs/*"],
	"Condition": {
		"ArnLike": {"aws:SourceArn": "arn:aws:bedrock:ap-southeast-1:526338061652:*"},
		"StringEquals": {"aws:SourceAccount": "526338061652"},
	},
}

bedrock_log_lifecycle_rule := {
	"abort_incomplete_multipart_upload": [],
	"expiration": [{
		"date": null,
		"days": 7,
		"expired_object_delete_marker": false,
	}],
	"filter": [{
		"and": [],
		"object_size_greater_than": null,
		"object_size_less_than": null,
		"prefix": "bedrock-model-invocations/",
		"tag": [],
	}],
	"id": "expire-bedrock-model-invocation-logs",
	"noncurrent_version_expiration": [{
		"newer_noncurrent_versions": null,
		"noncurrent_days": 7,
	}],
	"noncurrent_version_transition": [],
	"prefix": "",
	"status": "Enabled",
	"transition": [],
}

bedrock_logging_configuration_snapshot := {
	"id": "ap-southeast-1",
	"logging_config": [{
		"cloudwatch_config": [{
			"large_data_delivery_s3_config": [{
				"bucket_name": "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
				"key_prefix": "bedrock-model-invocations",
			}],
			"log_group_name": "/aws/bedrock/enterprise-ai-sandbox/model-invocations",
			"role_arn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-bedrock-log-delivery",
		}],
		"embedding_data_delivery_enabled": false,
		"image_data_delivery_enabled": false,
		"s3_config": [{
			"bucket_name": "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
			"key_prefix": "bedrock-model-invocations",
		}],
		"text_data_delivery_enabled": true,
		"video_data_delivery_enabled": false,
	}],
	"region": "ap-southeast-1",
}

bedrock_logging_configuration_before_sensitive := {
	"logging_config": [{
		"cloudwatch_config": [{
			"large_data_delivery_s3_config": [{}],
		}],
		"s3_config": [{}],
	}],
}

w6_004_bedrock_logging_disable(change, rule) if {
	change.address == "module.observability[0].aws_bedrock_model_invocation_logging_configuration.this[0]"
	change.type == "aws_bedrock_model_invocation_logging_configuration"
	change.change.actions == ["delete"]
	change.change.before == bedrock_logging_configuration_snapshot
	change.change.before_sensitive == bedrock_logging_configuration_before_sensitive
	change.change.after == null
	change.change.after_sensitive == {}
	change.change.after_unknown == {}
	rule.update_paths == []
	rule.delta_rule == "W6_004_BEDROCK_LOGGING_DISABLE"
}

w6_004_bedrock_logging_delta(change, rule) if {
	change.address == platform_kms_address
	change.type == "aws_kms_key"
	change.change.actions == ["update"]
	rule.update_paths == ["policy", "tags.ExpiresAt", "tags_all.ExpiresAt"]
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy", "tags", "tags_all"}) == object.remove(after_values, {"policy", "tags", "tags_all"})
	valid_expiry_reconciliation(before_values.tags, after_values.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
	exact_policy_statement_addition(before_values.policy, after_values.policy, bedrock_log_kms_statement.Sid, bedrock_log_kms_statement)
}

w6_004_bedrock_logging_delta(change, rule) if {
	change.address == "module.storage.aws_s3_bucket_policy.tls_only"
	change.type == "aws_s3_bucket_policy"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})
	exact_policy_statement_addition(before_values.policy, after_values.policy, bedrock_log_s3_statement.Sid, bedrock_log_s3_statement)
}

w6_004_bedrock_logging_delta(change, rule) if {
	change.address == "module.storage.aws_s3_bucket_lifecycle_configuration.this"
	change.type == "aws_s3_bucket_lifecycle_configuration"
	change.change.actions == ["update"]
	rule.update_paths == ["rule"]
	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"rule"}) == object.remove(after_values, {"rule"})
	count(after_values.rule) == count(before_values.rule) + 1
	[entry | some entry in after_values.rule; entry.id == bedrock_log_lifecycle_rule.id] == [bedrock_log_lifecycle_rule]
	{json.marshal(entry) | some entry in before_values.rule} == {
	json.marshal(entry) |
		some entry in after_values.rule
		entry.id != bedrock_log_lifecycle_rule.id
	}
}

operational_change_valid(change, rule) if {
	change.change.actions in [["create"], ["read"], ["no-op"]]
	rule.update_paths == []
	rule.delta_rule == "NONE"
	valid_change(change)
	change_has_no_sensitive_markers(change)
}

operational_change_valid(change, rule) if {
	operational.profile == "PARTIAL_RECOVERY"
	operational_expiry_delta(change, rule)
}

valid_change(change) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule := operational_rule(change)
	rule.delta_rule == "W6_004_BEDROCK_LOGGING"
	w6_004_bedrock_logging_delta(change, rule)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_change_valid(change, rule) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule.delta_rule == "W6_004_BEDROCK_LOGGING"
	w6_004_bedrock_logging_delta(change, rule)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_change_valid(change, rule) if {
	operational.profile == "PARTIAL_RECOVERY"
	w6_004_bedrock_logging_disable(change, rule)
	change_has_no_sensitive_markers(change)
}

w6_004_stage3_endpoint_address(address) if address in platform_interface_endpoint_addresses

w6_004_stage3_endpoint_address(address) if {
	address in {
		`module.network.aws_vpc_endpoint.gateway["DynamoDB"]`,
		`module.network.aws_vpc_endpoint.gateway["S3"]`,
	}
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "terraform_data.w6_004_runtime_gate[0]"
	change.type == "terraform_data"
	change.change.actions == ["update"]
	rule.update_paths == [
		"input.approval_expires_at",
		"input.approval_issued_at",
		"input.deployment_start",
		"output",
	]
	change.change.after.input.approval_expires_at == operational.expires_at
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.eks[0].aws_eks_access_entry.resilience"
	change.type == "aws_eks_access_entry"
	change.change.actions == ["update"]
	rule.update_paths == ["tags.ExpiresAt", "tags_all.ExpiresAt", "user_name"]
	change.change.after.user_name == "fis-experiment"
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == `module.eks[0].aws_eks_addon.this["coredns"]`
	change.type == "aws_eks_addon"
	change.change.actions == ["delete", "create"]
	rule.update_paths == [
		"arn", "configuration_values", "created_at", "id", "modified_at",
		"namespace_config", "service_account_role_arn", "tags.ExpiresAt",
		"tags_all.ExpiresAt",
	]
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.eks[0].aws_eks_node_group.application"
	change.type == "aws_eks_node_group"
	change.change.actions == ["delete", "create"]
	rule.update_paths == [
		"ami_type", "arn", "disk_size", "id", "labels", "node_group_name_prefix",
		"node_repair_config", "release_version", "resources", "status",
		"tags.ExpiresAt", "tags_all.ExpiresAt",
		"update_config[0].max_unavailable_percentage",
		"update_config[0].update_strategy", "version",
	]
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address in {
		"module.eks[0].aws_eks_pod_identity_association.ingestion",
		"module.eks[0].aws_eks_pod_identity_association.runtime",
	}
	change.type == "aws_eks_pod_identity_association"
	change.change.actions == ["update"]
	rule.update_paths == ["external_id", "tags", "tags_all.ExpiresAt"]
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address in {
		"module.eks[0].aws_iam_role.cluster",
		"module.eks[0].aws_iam_role.node",
		"module.iam.aws_iam_role.opensearch_administrator",
	}
	change.type == "aws_iam_role"
	change.change.actions == ["update"]
	rule.update_paths == ["assume_role_policy", "tags.ExpiresAt", "tags_all.ExpiresAt"]
}

valid_sts_endpoint_policy_only_repair(change) if {
	before_document := json.unmarshal(change.change.before.policy)
	after_document := json.unmarshal(change.change.after.policy)

	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})
	count(before_document.Statement) == 1
	count(after_document.Statement) == 1

	before_statement := before_document.Statement[0]
	after_statement := after_document.Statement[0]

	object.remove(before_statement, {"Action"}) == object.remove(after_statement, {"Action"})
	exact_string_value_or_members(before_statement.Action, {"sts:AssumeRole"})
	exact_string_members(after_statement.Action, {"sts:AssumeRole", "sts:GetCallerIdentity"})
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == `module.network.aws_vpc_endpoint.interface["STS"]`
	change.type == "aws_vpc_endpoint"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]
	valid_sts_endpoint_policy_only_repair(change)
}

w6_004_stage3_recovery_delta(change, rule) if {
	w6_004_stage3_endpoint_address(change.address)
	change.type == "aws_vpc_endpoint"
	change.change.actions == ["update"]
	rule.update_paths == ["policy", "tags.ExpiresAt", "tags_all.ExpiresAt"]
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == `module.eks[0].aws_eks_addon.this["vpc-cni"]`
	change.type == "aws_eks_addon"
	change.change.actions == ["update"]
	rule.update_paths == ["configuration_values", "tags.ExpiresAt", "tags_all.ExpiresAt"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"configuration_values", "tags", "tags_all"}) == object.remove(after_values, {"configuration_values", "tags", "tags_all"})
	before_values.configuration_values == ""
	json.unmarshal(after_values.configuration_values) == {"enableNetworkPolicy": "true"}
	valid_expiry_reconciliation(before_values.tags, after_values.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.observability[0].aws_fis_experiment_template.pod_delete"
	change.type == "aws_fis_experiment_template"
	change.change.actions == ["delete", "create"]
	rule.update_paths == ["experiment_options", "id", "tags.ExpiresAt", "tags_all.ExpiresAt"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"experiment_options", "id", "tags", "tags_all"}) == object.remove(after_values, {"experiment_options", "id", "tags", "tags_all"})
	before_values.experiment_options == [{
		"account_targeting": "single-account",
		"empty_target_resolution_mode": "fail",
	}]
	is_string(before_values.id)
	before_values.id != ""
	not "experiment_options" in object.keys(after_values)
	not "id" in object.keys(after_values)
	object.get(change.change.after_unknown, "experiment_options", false) == true
	object.get(change.change.after_unknown, "id", false) == true
	valid_expiry_reconciliation(before_values.tags, after_values.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)

	some action in after_values.action
	action.action_id == "aws:eks:pod-delete"
	some parameter in action.parameter
	parameter == {"key": "kubernetesServiceAccount", "value": "fis-experiment"}
	some target in after_values.target
	target.resource_type == "aws:eks:pod"
	target.selection_mode == "COUNT(1)"
	target.parameters.namespace == "enterprise-ai-sandbox"
	target.parameters.selectorType == "labelSelector"
	target.parameters.selectorValue == "app.kubernetes.io/name=enterprise-ai-api"
}

valid_exact_statement_resource_repair(
	before_policy,
	after_policy,
	target_sid,
	before_resources,
	after_resources,
) if {
	is_string(before_policy)
	is_string(after_policy)

	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)

	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})

	before_statements := before_document.Statement
	after_statements := after_document.Statement
	count(before_statements) == count(after_statements)

	before_target := [
	statement |
		some statement in before_statements
		object.get(statement, "Sid", "") == target_sid
	]
	after_target := [
	statement |
		some statement in after_statements
		object.get(statement, "Sid", "") == target_sid
	]
	count(before_target) == 1
	count(after_target) == 1

	object.remove(before_target[0], {"Resource"}) == object.remove(after_target[0], {"Resource"})
	exact_string_value_or_members(before_target[0].Resource, before_resources)
	exact_string_members(after_target[0].Resource, after_resources)

	before_other := {
	json.marshal(statement) |
		some statement in before_statements
		object.get(statement, "Sid", "") != target_sid
	}
	after_other := {
	json.marshal(statement) |
		some statement in after_statements
		object.get(statement, "Sid", "") != target_sid
	}
	before_other == after_other
}

valid_iam_index_root_resource_repair(before_policy, after_policy, target_sid) if {
	valid_exact_statement_resource_repair(
		before_policy,
		after_policy,
		target_sid,
		{"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*"},
		{
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox",
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
		},
	)
}

valid_runtime_opensearch_root_resource_repair(before_policy, after_policy) if {
	valid_exact_statement_resource_repair(
		before_policy,
		after_policy,
		"RuntimeExactReadAccess",
		{
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/_cluster/health",
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
		},
		{
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/_cluster/health",
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox",
			"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
		},
	)
}

runtime_bedrock_base_conditions(requested_region, expires_at) := {
	"ArnEquals": {"aws:PrincipalArn": platform_runtime_role_arn},
	"DateLessThan": {"aws:CurrentTime": expires_at},
	"StringEquals": {
		"aws:PrincipalAccount": "526338061652",
		"aws:RequestedRegion": requested_region,
	},
}

runtime_bedrock_profile_conditions(requested_region, expires_at) := conditions if {
	base := runtime_bedrock_base_conditions(requested_region, expires_at)
	conditions := object.union(base, {"StringEquals": object.union(base.StringEquals, {"bedrock:InferenceProfileArn": platform_global_inference_profile_arn})})
}

runtime_bedrock_statement(sid, resource, conditions) := statement if {
	statement := {
		"Sid": sid,
		"Effect": "Allow",
		"Action": "bedrock:InvokeModel",
		"Resource": resource,
		"Condition": conditions,
	}
}

# aws_iam_policy_document serializes single action and resource values as
# singleton arrays. Accept that Terraform representation as well as the scalar
# representation used by the narrow unit fixtures; both forms remain exact.
valid_runtime_bedrock_statement(statement, sid, resource, conditions) if {
	is_object(statement)
	object.keys(statement) == {"Action", "Condition", "Effect", "Resource", "Sid"}
	statement.Sid == sid
	statement.Effect == "Allow"
	exact_string_value_or_members(statement.Action, {"bedrock:InvokeModel"})
	exact_string_value_or_members(statement.Resource, {resource})
	statement.Condition == conditions
}

policy_statement_by_sid(document, sid) := statement if {
	matching := [
	candidate |
		some candidate in document.Statement
		object.get(candidate, "Sid", "") == sid
	]
	count(matching) == 1
	statement := matching[0]
}

policy_statement_set_without_sids(document, sids) := {
json.marshal(statement) |
	some statement in document.Statement
	not sids[object.get(statement, "Sid", "")]
}

valid_runtime_global_bedrock_profile_repair(before_policy, after_policy) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	is_object(before_document)
	is_object(after_document)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})
	legacy := policy_statement_by_sid(before_document, platform_runtime_policy_legacy_bedrock_sid)
	expires_at := legacy.Condition.DateLessThan["aws:CurrentTime"]
	valid_utc_timestamp(expires_at)
	valid_runtime_bedrock_statement(legacy, platform_runtime_policy_legacy_bedrock_sid, platform_global_inference_profile_arn, runtime_bedrock_profile_conditions("ap-southeast-1", expires_at))
	valid_runtime_bedrock_statement(policy_statement_by_sid(after_document, "InvokeExactGlobalInferenceProfile"), "InvokeExactGlobalInferenceProfile", platform_global_inference_profile_arn, runtime_bedrock_base_conditions("ap-southeast-1", expires_at))
	valid_runtime_bedrock_statement(policy_statement_by_sid(after_document, "InvokeExactGlobalInferenceProfileRegionalModel"), "InvokeExactGlobalInferenceProfileRegionalModel", platform_regional_foundation_model_arn, runtime_bedrock_profile_conditions("ap-southeast-1", expires_at))
	valid_runtime_bedrock_statement(policy_statement_by_sid(after_document, "InvokeExactGlobalInferenceProfileGlobalModel"), "InvokeExactGlobalInferenceProfileGlobalModel", platform_global_foundation_model_arn, runtime_bedrock_profile_conditions("unspecified", expires_at))
	before_other := policy_statement_set_without_sids(before_document, {platform_runtime_policy_legacy_bedrock_sid})
	after_other := policy_statement_set_without_sids(after_document, platform_runtime_policy_expiry_statement_sids)
	before_other == after_other
	count(after_document.Statement) == count(before_document.Statement) + 2
}

valid_fis_discovery_statement(statement, actions) if {
	object.keys(statement) == {"Action", "Effect", "Resource"}
	statement.Effect == "Allow"
	statement.Resource == ["*"]
	is_array(statement.Action)
	count(statement.Action) == count(actions)
	{action | some action in statement.Action} == actions
}

valid_fis_cluster_statement(statement) if {
	object.keys(statement) == {"Action", "Effect", "Resource"}
	statement.Effect == "Allow"
	statement.Resource == [platform_fis_cluster_arn]
	is_array(statement.Action)
	count(statement.Action) == 2
	{action | some action in statement.Action} == {
		"eks:AccessKubernetesApi",
		"eks:DescribeCluster",
	}
}

valid_fis_policy(document, discovery_actions) if {
	object.keys(document) == {"Statement", "Version"}
	document.Version == "2012-10-17"
	is_array(document.Statement)
	count(document.Statement) == 2

	discovery := [
	statement |
		some statement in document.Statement
		valid_fis_discovery_statement(statement, discovery_actions)
	]
	count(discovery) == 1

	cluster := [
	statement |
		some statement in document.Statement
		valid_fis_cluster_statement(statement)
	]
	count(cluster) == 1
}

valid_fis_subnet_discovery_repair(before_policy, after_policy) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	valid_fis_policy(before_document, {
		"ec2:DescribeInstances",
		"tag:GetResources",
	})
	valid_fis_policy(after_document, {
		"ec2:DescribeInstances",
		"ec2:DescribeSubnets",
		"tag:GetResources",
	})
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == platform_fis_policy_address
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})
	valid_fis_subnet_discovery_repair(before_values.policy, after_values.policy)
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.iam.aws_iam_role_policy.runtime"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})

	valid_iam_index_root_resource_repair(
		before_values.policy,
		after_values.policy,
		"RuntimeOpenSearchExactIndexQuery",
	)
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.iam.aws_iam_role_policy.runtime"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})
	valid_runtime_global_bedrock_profile_repair(before_values.policy, after_values.policy)
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.iam.aws_iam_role_policy.ingestion"
	change.type == "aws_iam_role_policy"
	change.change.actions == ["update"]
	rule.update_paths == ["policy"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"policy"}) == object.remove(after_values, {"policy"})

	valid_iam_index_root_resource_repair(
		before_values.policy,
		after_values.policy,
		"IngestionOpenSearchDataPlane",
	)
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.opensearch.aws_opensearch_domain.this"
	change.type == "aws_opensearch_domain"
	change.change.actions == ["update"]
	rule.update_paths == ["access_policies"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"access_policies"}) == object.remove(after_values, {"access_policies"})

	valid_runtime_opensearch_root_resource_repair(
		before_values.access_policies,
		after_values.access_policies,
	)
}

valid_runtime_opensearch_statement(statement) if {
	object.keys(statement) == {"Action", "Effect", "Principal", "Resource", "Sid"}
	statement.Sid == "RuntimeExactReadAccess"
	statement.Effect == "Allow"
	statement.Principal == {"AWS": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"}
	exact_string_members(statement.Action, {"es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost"})
	exact_string_members(statement.Resource, {
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/_cluster/health",
		"arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox/enterprise_ai_sandbox/*",
	})
}

valid_runtime_opensearch_policy_addition(before_policy, after_policy) if {
	is_string(before_policy)
	is_string(after_policy)
	before_document := json.unmarshal(before_policy)
	after_document := json.unmarshal(after_policy)
	object.remove(before_document, {"Statement"}) == object.remove(after_document, {"Statement"})

	before_statements := before_document.Statement
	after_statements := after_document.Statement
	count(after_statements) == count(before_statements) + 1

	before_runtime := [statement | some statement in before_statements; object.get(statement, "Sid", "") == "RuntimeExactReadAccess"]
	after_runtime := [statement | some statement in after_statements; object.get(statement, "Sid", "") == "RuntimeExactReadAccess"]
	count(before_runtime) == 0
	count(after_runtime) == 1
	valid_runtime_opensearch_statement(after_runtime[0])

	before_other := {json.marshal(statement) | some statement in before_statements; object.get(statement, "Sid", "") != "RuntimeExactReadAccess"}
	after_other := {json.marshal(statement) | some statement in after_statements; object.get(statement, "Sid", "") != "RuntimeExactReadAccess"}
	count(before_other) == count(before_statements)
	count(after_other) == count(after_statements) - 1
	before_other == after_other
}

w6_004_stage3_recovery_delta(change, rule) if {
	change.address == "module.opensearch.aws_opensearch_domain.this"
	change.type == "aws_opensearch_domain"
	change.change.actions == ["update"]
	rule.update_paths == ["access_policies", "tags.ExpiresAt", "tags_all.ExpiresAt"]

	before_values := change.change.before
	after_values := change.change.after
	object.remove(before_values, {"access_policies", "tags", "tags_all"}) == object.remove(after_values, {"access_policies", "tags", "tags_all"})
	valid_runtime_opensearch_policy_addition(before_values.access_policies, after_values.access_policies)
	valid_expiry_reconciliation(before_values.tags, after_values.tags, operational.resource_expires_at)
	valid_expiry_reconciliation(before_values.tags_all, after_values.tags_all, operational.resource_expires_at)
}

operational_change_valid(change, rule) if {
	operational.profile == "PARTIAL_RECOVERY"
	rule.delta_rule == "W6_004_STAGE3_RECOVERY"
	w6_004_stage3_recovery_delta(change, rule)
	valid_change(change)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_apply_profile_valid if {
	is_object(operational)
	object.keys(operational) == {
		"schema_version", "operation_id", "action", "profile", "rules", "state_lineage",
		"state_serial", "inventory_sha256", "source_sha256", "resource_expires_at", "expires_at",
	}
	operational.schema_version == "w5-004.lifecycle.v2"
	is_string(operational.operation_id)
	operational.operation_id != ""
	operational.action in {"BOOTSTRAP-APPLY", "PLATFORM-APPLY"}
	operational.profile in {"INITIAL", "PARTIAL_RECOVERY"}
	valid_utc_timestamp(operational.expires_at)
	time.parse_rfc3339_ns(operational.expires_at) > evaluation_time_ns
	valid_utc_timestamp(operational.resource_expires_at)
	resource_expires_at_ns := time.parse_rfc3339_ns(operational.resource_expires_at)
	resource_expires_at_ns > evaluation_time_ns
	resource_expires_at_ns <= evaluation_time_ns + day_ns
	regex.match("^[0-9a-f]{64}$", operational.inventory_sha256)
	regex.match("^[0-9a-f]{64}$", operational.source_sha256)
	is_array(operational.rules)
	count(operational.rules) > 0
	count(operational.rules) == count(resource_changes)
	count(operational.rules) == count({rule.address | some rule in operational.rules})
	every change in resource_changes {
		rule := operational_rule(change)
		object.keys(rule) == {"address", "resource_type", "actions", "update_paths", "delta_rule"}
		operational_change_valid(change, rule)
	}
}

operational_profile_valid if operational_apply_profile_valid

operational_profile_valid if operational_destroy_profile_valid

operational_destroy_resource_valid(change) if {
	change.type in supported_aws_resource_types
	valid_resource_address(change.address)
}

operational_destroy_resource_valid(change) if {
	change.address == "terraform_data.owner_expiry_gate"
	change.type == "terraform_data"
}

operational_destroy_change_valid(change, rule) if {
	operational_destroy_resource_valid(change)
	rule.update_paths == []
	rule.delta_rule == "NONE"
	change.change.actions == ["delete"]
	is_object(change.change.before)
	change.change.after == null
	change.change.after_unknown == {}
	change_has_no_sensitive_markers(change)
}

operational_destroy_change_valid(change, rule) if {
	rule.update_paths == []
	rule.delta_rule == "NONE"
	change.change.actions in [["read"], ["no-op"]]
	valid_change(change)
	change_has_no_sensitive_markers(change)
	not critical_unknown_present(change)
}

operational_destroy_profile_valid if {
	valid_before_sensitive_context
	input.terraform_version == "1.16.1"
	input.variables.aws_region.value == "ap-southeast-1"
	is_string(input.format_version)
	object.keys(operational) == {
		"schema_version", "operation_id", "action", "profile", "rules", "state_lineage",
		"state_serial", "inventory_sha256", "source_sha256", "resource_expires_at", "expires_at",
	}
	operational.schema_version == "w5-004.lifecycle.v2"
	operational.profile == "DESTROY"
	operational.action in {"PLATFORM-DESTROY", "BOOTSTRAP-DESTROY"}
	is_string(operational.operation_id)
	operational.operation_id != ""
	is_string(operational.state_lineage)
	operational.state_lineage != ""
	is_number(operational.state_serial)
	operational.state_serial >= 0
	floor(operational.state_serial) == operational.state_serial
	valid_utc_timestamp(operational.expires_at)
	time.parse_rfc3339_ns(operational.expires_at) > evaluation_time_ns
	time.parse_rfc3339_ns(operational.expires_at) <= evaluation_time_ns + 3600000000000
	regex.match("^[0-9a-f]{64}$", operational.inventory_sha256)
	regex.match("^[0-9a-f]{64}$", operational.source_sha256)
	is_array(operational.rules)
	count(operational.rules) > 0
	count(operational.rules) == count(resource_changes)
	count(operational.rules) == count({rule.address | some rule in operational.rules})
	count(resource_changes) == count({candidate.address | some candidate in resource_changes})
	some change in resource_changes
	change.change.actions == ["delete"]
	every candidate in resource_changes {
		rule := operational_rule(candidate)
		object.keys(rule) == {"address", "resource_type", "actions", "update_paths", "delta_rule"}
		operational_destroy_change_valid(candidate, rule)
	}
}

critical_unknown_present(change) if {
	walk(object.get(change.change, "after_unknown", {}), [path, true])
	some part in path
	part in {"account_id", "aws_region", "cidr_block", "egress", "ingress", "kms_key_id", "policy", "publicly_accessible", "security_group_ids", "subnet_id", "subnet_ids", "tags", "tags_all", "vpc_id"}
}

partial_platform_recovery_plan_valid if {
	operational.profile == "PARTIAL_RECOVERY"
	operational.action == "PLATFORM-APPLY"
	operational_profile_valid
}

production_findings contains item if {
	operational.profile != "DESTROY"
	some item in effective_findings
}

# Destroy reviews use deletion/ownership rules rather than requiring resources
# being removed to satisfy create-only configuration tests. Privacy and the
# exception registry remain mandatory, and the dispatch gate binds native ownership.
production_findings contains item if {
	operational.profile == "DESTROY"
	not registry_valid
	item := safe_finding(violation("W5-EXC-001", "policy.exceptions"))
}

production_findings contains item if {
	operational.profile == "DESTROY"
	secret_material_present
	item := safe_finding(violation("W5-SEC-001", "policy.input"))
}

production_findings contains item if {
	not operational_profile_valid
	item := safe_finding(violation("W5-PLAN-002", "policy.operation"))
}

decision := {
	"schema_version": "w5-004.policy-decision.v2",
	"allow": count(production_findings) == 0,
	"findings": sort(production_findings),
}

valid_before_sensitive_context if {
	bindings := object.get(evaluation_context, "provider_sensitive_before_nulls", [])
	is_array(bindings)
	count(bindings) <= 1
	every binding in bindings {
		object.keys(binding) == {"address", "type", "field_path", "relationship", "source_address"}
		binding.address == opensearch_domain_address
		binding.type == "aws_opensearch_domain"
		binding.field_path == opensearch_password_field_path
		binding.relationship == opensearch_existing_sensitive_relationship
		binding.source_address == opensearch_admin_role_address
		domain := changes_by_address[opensearch_domain_address]
		domain.type == "aws_opensearch_domain"
		before := domain.change.before
		is_object(before)
		count(before.advanced_security_options) == 1
		advanced := before.advanced_security_options[0]
		advanced.enabled == true
		advanced.internal_user_database_enabled == false
		count(advanced.master_user_options) == 1
		master := advanced.master_user_options[0]
		object.get(master, "master_user_name", null) in {null, ""}
		object.get(master, "master_user_password", null) == null
		is_string(master.master_user_arn)
		master.master_user_arn != ""
		role := changes_by_address[opensearch_admin_role_address]
		role.type == "aws_iam_role"
		role.change.before.arn == master.master_user_arn
		is_string(role.change.before.assume_role_policy)
		valid_false_only_sensitive_shape(object.get(role.change, "before_sensitive", {}))
		change_has_no_sensitive_markers(domain)
	}
}
