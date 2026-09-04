package enterprise_ai.terraform.plan

import rego.v1

required_tags := {
  "Project": "enterprise-ai-platform",
  "Environment": "sandbox",
  "Owner": "Gyan-Prakash-Rai",
  "ManagedBy": "terraform",
  "CostCenter": "Personal-Learning",
  "Feature": "MVP-001",
  "Repository": "enterprise-ai-platform",
}

resource_changes := object.get(input, "resource_changes", [])

taggable_resource_types := {
  "aws_cloudwatch_log_group",
  "aws_dynamodb_table",
  "aws_ecr_repository",
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

after(change) := object.get(object.get(change, "change", {}), "after", null)

deny contains "aws_region_outside_approved_boundary" if {
  variables := object.get(input, "variables", {})
  region := object.get(object.get(variables, "aws_region", {}), "value", "")
  region != "ap-southeast-1"
}

deny contains sprintf("missing_or_invalid_tag:%s:%s", [change.address, key]) if {
  some change in resource_changes
  change.type in taggable_resource_types
  values := after(change)
  values != null
  tags := object.get(values, "tags_all", object.get(values, "tags", {}))
  some key, expected in required_tags
  object.get(tags, key, "") != expected
}

deny contains sprintf("missing_expires_at:%s", [change.address]) if {
  some change in resource_changes
  change.type in taggable_resource_types
  values := after(change)
  values != null
  tags := object.get(values, "tags_all", object.get(values, "tags", {}))
  object.get(tags, "ExpiresAt", "TODO_OWNER") == "TODO_OWNER"
}

deny contains sprintf("public_subnet_addressing:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_subnet"
  object.get(after(change), "map_public_ip_on_launch", true)
}

deny contains sprintf("unapproved_internet_egress:%s", [change.address]) if {
  some change in resource_changes
  change.type in {"aws_internet_gateway", "aws_nat_gateway"}
  after(change) != null
}

deny contains sprintf("unrestricted_ingress:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_security_group"
  some rule in object.get(after(change), "ingress", [])
  some cidr in object.get(rule, "cidr_blocks", [])
  cidr in {"0.0.0.0/0", "::/0"}
}

deny contains sprintf("s3_public_access_not_blocked:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_public_access_block"
  values := after(change)
  not object.get(values, "block_public_acls", false)
}

deny contains sprintf("s3_public_access_not_blocked:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_public_access_block"
  values := after(change)
  not object.get(values, "block_public_policy", false)
}

deny contains sprintf("s3_public_access_not_blocked:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_public_access_block"
  values := after(change)
  not object.get(values, "ignore_public_acls", false)
}

deny contains sprintf("s3_public_access_not_blocked:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_public_access_block"
  values := after(change)
  not object.get(values, "restrict_public_buckets", false)
}

deny contains sprintf("s3_encryption_not_kms:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  some rule in object.get(after(change), "rule", [])
  some defaults in object.get(rule, "apply_server_side_encryption_by_default", [])
  object.get(defaults, "sse_algorithm", "") != "aws:kms"
}

deny contains sprintf("s3_encryption_not_kms:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  count(object.get(after(change), "rule", [])) == 0
}

deny contains sprintf("kms_rotation_disabled:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_kms_key"
  not object.get(after(change), "enable_key_rotation", false)
}

deny contains sprintf("opensearch_not_private:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  count(object.get(after(change), "vpc_options", [])) == 0
}

deny contains sprintf("opensearch_encryption_disabled:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  some encryption in object.get(after(change), "encrypt_at_rest", [])
  not object.get(encryption, "enabled", false)
}

deny contains sprintf("opensearch_encryption_disabled:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  count(object.get(after(change), "encrypt_at_rest", [])) == 0
}

deny contains sprintf("opensearch_node_encryption_disabled:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  some encryption in object.get(after(change), "node_to_node_encryption", [])
  not object.get(encryption, "enabled", false)
}

deny contains sprintf("opensearch_node_encryption_disabled:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  count(object.get(after(change), "node_to_node_encryption", [])) == 0
}

deny contains sprintf("opensearch_https_not_enforced:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  some endpoint in object.get(after(change), "domain_endpoint_options", [])
  not object.get(endpoint, "enforce_https", false)
}

deny contains sprintf("opensearch_https_not_enforced:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_opensearch_domain"
  count(object.get(after(change), "domain_endpoint_options", [])) == 0
}

deny contains sprintf("ecr_encryption_not_kms:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_ecr_repository"
  some encryption in object.get(after(change), "encryption_configuration", [])
  object.get(encryption, "encryption_type", "") != "KMS"
}

deny contains sprintf("ecr_encryption_not_kms:%s", [change.address]) if {
  some change in resource_changes
  change.type == "aws_ecr_repository"
  count(object.get(after(change), "encryption_configuration", [])) == 0
}

deny contains sprintf("iam_action_wildcard:%s", [change.address]) if {
  some change in resource_changes
  change.type in {"aws_iam_policy", "aws_iam_role_policy"}
  policy := object.get(after(change), "policy", "")
  regex.match(`(?i)"[a-z0-9-]+:[^"\n]*\*"`, policy)
}

deny contains sprintf("iam_prohibited_action:%s", [change.address]) if {
  some change in resource_changes
  change.type in {"aws_iam_policy", "aws_iam_role_policy"}
  policy := object.get(after(change), "policy", "")
  regex.match(`(?i)ecr:GetAuthorizationToken|iam:(List|Describe)`, policy)
}
