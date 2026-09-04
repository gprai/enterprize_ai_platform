package enterprise_ai.terraform.plan

import rego.v1

approved_tags := {
  "Project": "enterprise-ai-platform",
  "Environment": "sandbox",
  "Owner": "Gyan-Prakash-Rai",
  "ManagedBy": "terraform",
  "CostCenter": "Personal-Learning",
  "Feature": "MVP-001",
  "ExpiresAt": "2026-09-04T00:00:00Z",
  "Repository": "enterprise-ai-platform",
}

approved_plan := {
  "variables": {"aws_region": {"value": "ap-southeast-1"}},
  "resource_changes": [
    {
      "address": "aws_subnet.private[0]",
      "type": "aws_subnet",
      "change": {"after": {"map_public_ip_on_launch": false, "tags_all": approved_tags}},
    },
    {
      "address": "aws_kms_key.platform",
      "type": "aws_kms_key",
      "change": {"after": {"enable_key_rotation": true, "tags_all": approved_tags}},
    },
    {
      "address": "aws_ecr_repository.api",
      "type": "aws_ecr_repository",
      "change": {"after": {
        "encryption_configuration": [{"encryption_type": "KMS"}],
        "tags_all": approved_tags,
      }},
    },
  ],
}

test_approved_inline_plan_has_no_denials if {
  denials := deny with input as approved_plan
  count(denials) == 0
}

test_wrong_region_is_denied if {
  plan := object.union(approved_plan, {
    "variables": {"aws_region": {"value": "us-east-1"}},
  })
  "aws_region_outside_approved_boundary" in deny with input as plan
}

test_public_subnet_is_denied if {
  plan := {
    "variables": {"aws_region": {"value": "ap-southeast-1"}},
    "resource_changes": [{
      "address": "aws_subnet.public",
      "type": "aws_subnet",
      "change": {"after": {"map_public_ip_on_launch": true, "tags_all": approved_tags}},
    }],
  }
  "public_subnet_addressing:aws_subnet.public" in deny with input as plan
}

test_nat_gateway_is_denied if {
  plan := {
    "variables": {"aws_region": {"value": "ap-southeast-1"}},
    "resource_changes": [{
      "address": "aws_nat_gateway.unapproved",
      "type": "aws_nat_gateway",
      "change": {"after": {"tags_all": approved_tags}},
    }],
  }
  "unapproved_internet_egress:aws_nat_gateway.unapproved" in deny with input as plan
}

test_missing_mandatory_tag_is_denied if {
  plan := {
    "variables": {"aws_region": {"value": "ap-southeast-1"}},
    "resource_changes": [{
      "address": "aws_kms_key.invalid",
      "type": "aws_kms_key",
      "change": {"after": {
        "enable_key_rotation": true,
        "tags_all": object.remove(approved_tags, {"Owner"}),
      }},
    }],
  }
  "missing_or_invalid_tag:aws_kms_key.invalid:Owner" in deny with input as plan
}

test_unencrypted_ecr_is_denied if {
  plan := {
    "variables": {"aws_region": {"value": "ap-southeast-1"}},
    "resource_changes": [{
      "address": "aws_ecr_repository.invalid",
      "type": "aws_ecr_repository",
      "change": {"after": {
        "encryption_configuration": [{"encryption_type": "AES256"}],
        "tags_all": approved_tags,
      }},
    }],
  }
  "ecr_encryption_not_kms:aws_ecr_repository.invalid" in deny with input as plan
}
