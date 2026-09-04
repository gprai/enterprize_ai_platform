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

taggable_resource_types := {
  "aws_cloudwatch_log_group",
  "aws_dynamodb_table",
  "aws_ecr_repository",
  "aws_iam_policy",
  "aws_iam_role",
  "aws_kms_key",
  "aws_opensearch_domain",
  "aws_route_table",
  "aws_s3_bucket",
  "aws_secretsmanager_secret",
  "aws_security_group",
  "aws_subnet",
  "aws_vpc",
  "aws_vpc_endpoint",
}

supported_aws_resource_types := {
  "aws_cloudwatch_log_group",
  "aws_cloudwatch_log_resource_policy",
  "aws_default_security_group",
  "aws_dynamodb_table",
  "aws_ecr_lifecycle_policy",
  "aws_ecr_repository",
  "aws_iam_policy",
  "aws_iam_role",
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

approved_endpoint_services := {
  "com.amazonaws.ap-southeast-1.s3",
  "com.amazonaws.ap-southeast-1.dynamodb",
  "com.amazonaws.ap-southeast-1.ecr.api",
  "com.amazonaws.ap-southeast-1.ecr.dkr",
  "com.amazonaws.ap-southeast-1.eks",
  "com.amazonaws.ap-southeast-1.sts",
  "com.amazonaws.ap-southeast-1.logs",
  "com.amazonaws.ap-southeast-1.kms",
  "com.amazonaws.ap-southeast-1.secretsmanager",
  "com.amazonaws.ap-southeast-1.bedrock-runtime",
}

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

change_has_no_unknown_values(change_body) if {
  unknowns := object.get(change_body, "after_unknown", {})
  not regex.match(`(^|[:,\[])true([,}\]]|$)`, json.marshal(unknowns))
}

valid_change(change) if {
  is_object(change)
  address := object.get(change, "address", "")
  valid_resource_address(address)
  resource_type := object.get(change, "type", "")
  is_string(resource_type)
  supported_change_type(resource_type)
  change_body := object.get(change, "change", null)
  is_object(change_body)
  actions := object.get(change_body, "actions", [])
  is_array(actions)
  json.marshal(actions) in supported_action_sequences
  valid_change_after(actions, object.get(change_body, "after", null))
  change_has_no_unknown_values(change_body)
}

valid_policy_context if {
  is_object(evaluation_context)
  timestamp := object.get(evaluation_context, "evaluation_time", "")
  valid_utc_timestamp(timestamp)
  configured_policy_ids := object.get(evaluation_context, "policy_ids", null)
  is_array(configured_policy_ids)
  count(configured_policy_ids) == count(policy_inventory)
  {policy_id | some policy_id in configured_policy_ids} == policy_ids
}

input_contract_valid if {
  is_object(input)
  object.get(input, "format_version", "") != ""
  object.get(input, "terraform_version", "") != ""
  variables := object.get(input, "variables", null)
  is_object(variables)
  changes := object.get(input, "resource_changes", null)
  is_array(changes)
  count(changes) > 0
  valid_policy_context
  every change in changes {
    valid_change(change)
  }
}

evaluated_changes := resource_changes if input_contract_valid
changes_by_address := {change.address: change | some change in evaluated_changes}

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
  related_change(bucket, resource_type)
}

s3_public_access_valid(change) if {
  values := after(change)
  object.get(values, "block_public_acls", false)
  object.get(values, "block_public_policy", false)
  object.get(values, "ignore_public_acls", false)
  object.get(values, "restrict_public_buckets", false)
}

s3_encryption_valid(change) if {
  values := after(change)
  some rule in object.get(values, "rule", [])
  some defaults in object.get(rule, "apply_server_side_encryption_by_default", [])
  object.get(defaults, "sse_algorithm", "") == "aws:kms"
  object.get(defaults, "kms_master_key_id", "") != ""
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

opensearch_security_valid(change) if {
  values := after(change)
  count(object.get(values, "vpc_options", [])) > 0
  some at_rest in object.get(values, "encrypt_at_rest", [])
  object.get(at_rest, "enabled", false)
  object.get(at_rest, "kms_key_id", "") != ""
  some node in object.get(values, "node_to_node_encryption", [])
  object.get(node, "enabled", false)
  some endpoint in object.get(values, "domain_endpoint_options", [])
  object.get(endpoint, "enforce_https", false)
  object.get(endpoint, "tls_security_policy", "") == "Policy-Min-TLS-1-2-2019-07"
}

opensearch_logs_valid(change) if {
  values := after(change)
  options := object.get(values, "log_publishing_options", [])
  count(options) == 4
  {object.get(option, "log_type", "") | some option in options} == approved_log_types
  every option in options {
    object.get(option, "enabled", false)
    object.get(option, "cloudwatch_log_group_arn", "") != ""
  }
  access_policy := object.get(values, "access_policies", "")
  is_string(access_policy)
  contains(access_policy, "526338061652")
  not regex.match(`(?i)"Principal"\s*:\s*("\*"|\{[^}]*"AWS"\s*:\s*"\*")`, access_policy)
}

opensearch_log_groups_valid if {
  groups := [change | some change in evaluated_changes; change.type == "aws_cloudwatch_log_group"]
  count(groups) == 4
  every group in groups {
    object.get(after(group), "retention_in_days", 0) == 30
    object.get(after(group), "kms_key_id", "") != ""
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

ecr_security_valid(change) if {
  values := after(change)
  object.get(values, "image_tag_mutability", "") == "IMMUTABLE"
  some scanning in object.get(values, "image_scanning_configuration", [])
  object.get(scanning, "scan_on_push", false)
  some encryption in object.get(values, "encryption_configuration", [])
  object.get(encryption, "encryption_type", "") == "KMS"
  object.get(encryption, "kms_key", "") != ""
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
    `(?i)"(secret_string|secret_binary|password|passwd|access_key|secret_key|private_key|credential|client_secret|auth_token|api_key)"\s*:`,
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
}

raw_violations contains violation("W5-PLAN-002", change.address) if {
  some change in evaluated_changes
  destructive_change(change)
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
  not s3_tls_policy_valid(change)
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

finding_map := {
  sprintf("%s|%s|%s", [finding.policy_id, finding.resource_address, finding.remediation_code]): finding |
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
