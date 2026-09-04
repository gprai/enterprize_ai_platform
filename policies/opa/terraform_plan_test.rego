package enterprise_ai.terraform.plan

import rego.v1

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

approved_plan := {
  "format_version": "1.2",
  "terraform_version": "1.14.0",
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
  plan := object.union(approved_plan, {
    "variables": {"aws_region": {"value": "us-east-1"}},
  })
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
  values := object.union(approved_ecr_values, {
    "encryption_configuration": [{"encryption_type": "AES256"}],
  })
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

test_missing_context_fails_closed if {
  plan := object.remove(approved_plan, {"evaluation_context"})
  policy_ids_for(plan) == {"W5-PLAN-001"}
}

test_unsupported_aws_change_fails_closed if {
  unsupported := change("aws_lambda_function.unapproved", "aws_lambda_function", {})
  policy_ids_for(plan_with_changes([unsupported])) == {"W5-PLAN-001"}
}

test_unknown_after_value_fails_closed if {
  body := object.union(safe_anchor.change, {
    "after_unknown": {"subnet_id": true},
  })
  change_with_unknown := object.union(safe_anchor, {"change": body})
  policy_ids_for(plan_with_changes([change_with_unknown])) == {"W5-PLAN-001"}
}

test_missing_policy_id_fails_closed if {
  context := object.union(approved_context, {
    "policy_ids": array.slice(policy_order, 0, count(policy_order) - 1),
  })
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
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  policy_ids_for(plan_with_changes([destructive])) == {"W5-PLAN-002"}
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
    {"rule": [{
      "apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}],
    }]},
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
  body := object.union(safe_anchor.change, {
    "after_sensitive": {"subnet_id": true},
  })
  sensitive_change := object.union(safe_anchor, {"change": body})
  policy_ids_for(plan_with_changes([sensitive_change])) == {"W5-SEC-001"}
}

test_invalid_exception_registry_fails_closed if {
  result := policy_ids_for(approved_plan) with data.exceptions as [{"invalid": true}]
  result == {"W5-EXC-001"}
}

test_invalid_exception_never_suppresses_an_existing_denial if {
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  plan := plan_with_changes([destructive])
  result := policy_ids_for(plan) with data.exceptions as [{"invalid": true}]
  result == {"W5-PLAN-002", "W5-EXC-001"}
}

test_active_exact_exception_suppresses_only_matching_finding if {
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  plan := plan_with_changes([destructive])
  result := findings_for(plan) with data.exceptions as [
    active_exception("W5-PLAN-002", safe_anchor.address),
  ]
  count(result) == 0
}

test_wrong_resource_exception_does_not_suppress if {
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  plan := plan_with_changes([destructive])
  result := policy_ids_for(plan) with data.exceptions as [
    active_exception("W5-PLAN-002", "aws_route_table_association.other[0]"),
  ]
  result == {"W5-PLAN-002"}
}

test_wrong_policy_exception_does_not_suppress if {
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  plan := plan_with_changes([destructive])
  result := policy_ids_for(plan) with data.exceptions as [
    active_exception("W5-TAG-001", safe_anchor.address),
  ]
  result == {"W5-PLAN-002"}
}

test_expired_future_and_revoked_exceptions_do_not_suppress if {
  destructive := object.union(safe_anchor, {
    "change": {"actions": ["delete"], "after": null},
  })
  plan := plan_with_changes([destructive])

  expired := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
    "issued_at": "2026-09-02T00:00:00Z",
    "expires_at": "2026-09-03T00:00:00Z",
  })
  future := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
    "issued_at": "2026-09-04T01:00:00Z",
    "expires_at": "2026-09-05T01:00:00Z",
  })
  revoked := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
    "status": "REVOKED",
  })

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
  invalid := object.union(active_exception("W5-PLAN-002", safe_anchor.address), {
    "resource_addresses": ["aws_route_table_association.*"],
  })
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
  plan := object.union(plan_with_changes([group, gateway]), {
    "variables": {"aws_region": {"value": "us-east-1"}},
  })
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
    "terraform_version": "1.14.0",
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
