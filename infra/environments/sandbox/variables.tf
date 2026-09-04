variable "aws_account_id" {
  type        = string
  description = "Exact personal learning sandbox AWS account."
  validation {
    condition     = var.aws_account_id == "526338061652"
    error_message = "aws_account_id must equal 526338061652."
  }
}

variable "aws_region" {
  type        = string
  description = "Exact application and Terraform provider Region."
  validation {
    condition     = var.aws_region == "ap-southeast-1"
    error_message = "aws_region must equal ap-southeast-1."
  }
}

# Contract-only owner decision; validation enforces the approved no-fallback value.
# tflint-ignore: terraform_unused_declarations
variable "aws_fallback_region" {
  type        = string
  nullable    = true
  description = "No fallback application Region is approved."
  validation {
    condition     = var.aws_fallback_region == null
    error_message = "aws_fallback_region must remain null."
  }
}

# Contract-only owner decision; validation fixes the selected ownership mode.
# tflint-ignore: terraform_unused_declarations
variable "network_ownership_mode" {
  type        = string
  description = "Approved network ownership boundary."
  validation {
    condition     = var.network_ownership_mode == "project_owned"
    error_message = "network_ownership_mode must be project_owned."
  }
}

# Contract-only owner decision; project-owned networking requires this to remain null.
# tflint-ignore: terraform_unused_declarations
variable "vpc_id" {
  type        = string
  nullable    = true
  description = "Existing VPC input; null for the project-owned topology."
  validation {
    condition     = var.vpc_id == null
    error_message = "vpc_id must remain null for project_owned networking."
  }
}

# Contract-only owner decision; project-owned networking requires this to remain empty.
# tflint-ignore: terraform_unused_declarations
variable "private_subnet_ids" {
  type        = list(string)
  description = "Existing subnet input; empty for the project-owned topology."
  validation {
    condition     = length(var.private_subnet_ids) == 0
    error_message = "private_subnet_ids must remain empty for project_owned networking."
  }
}

variable "vpc_cidr" {
  type        = string
  description = "Exact owner-approved sandbox VPC CIDR."
  validation {
    condition     = var.vpc_cidr == "10.60.0.0/16"
    error_message = "vpc_cidr must equal 10.60.0.0/16."
  }
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "Exact ordered private subnet CIDRs."
  validation {
    condition = var.private_subnet_cidrs == tolist([
      "10.60.10.0/24",
      "10.60.11.0/24",
    ])
    error_message = "private_subnet_cidrs must preserve the two approved CIDRs and order."
  }
}

# Contract-only owner decision; validation preserves the no-DNS boundary.
# tflint-ignore: terraform_unused_declarations
variable "dns_domain" {
  type        = string
  nullable    = true
  description = "No private DNS domain is approved for creation."
  validation {
    condition     = var.dns_domain == null
    error_message = "dns_domain must remain null."
  }
}

variable "egress_mode" {
  type        = string
  description = "Exact private endpoint-only egress policy."
  validation {
    condition     = var.egress_mode == "private_endpoints_only"
    error_message = "egress_mode must be private_endpoints_only."
  }
}

variable "vpc_endpoint_services" {
  type        = list(string)
  description = "Exact ordered endpoint-service labels approved by the owner."
  validation {
    condition = var.vpc_endpoint_services == tolist([
      "S3",
      "DynamoDB",
      "ECR API/DKR",
      "EKS",
      "STS",
      "CloudWatch Logs",
      "KMS",
      "Secrets Manager",
      "Bedrock Runtime",
    ])
    error_message = "vpc_endpoint_services must match the exact approved ordered labels."
  }
}

variable "allow_public_ingress" {
  type        = bool
  description = "Public ingress is prohibited."
  validation {
    condition     = !var.allow_public_ingress
    error_message = "allow_public_ingress must be false."
  }
}

variable "allow_nat_gateway" {
  type        = bool
  description = "NAT and unapproved internet egress are prohibited."
  validation {
    condition     = !var.allow_nat_gateway
    error_message = "allow_nat_gateway must be false."
  }
}

variable "mandatory_tags" {
  type        = map(string)
  description = "Exact owner-approved resource and lifecycle tags."
  validation {
    condition = (
      length(var.mandatory_tags) == 8 &&
      var.mandatory_tags["Project"] == "enterprise-ai-platform" &&
      var.mandatory_tags["Environment"] == "sandbox" &&
      var.mandatory_tags["Owner"] == "Gyan-Prakash-Rai" &&
      var.mandatory_tags["ManagedBy"] == "terraform" &&
      var.mandatory_tags["CostCenter"] == "Personal-Learning" &&
      var.mandatory_tags["Feature"] == "MVP-001" &&
      var.mandatory_tags["Repository"] == "enterprise-ai-platform" &&
      contains(keys(var.mandatory_tags), "ExpiresAt")
    )
    error_message = "mandatory_tags must contain exactly the eight owner-approved keys and fixed values."
  }
}

# Governance-only processing-policy label; it is not a resource Region list.
# tflint-ignore: terraform_unused_declarations
variable "allowed_data_regions" {
  type        = list(string)
  description = "Bedrock processing-policy label; not a concrete Region allowlist."
  validation {
    condition     = var.allowed_data_regions == tolist(["Global Cross-Region"])
    error_message = "allowed_data_regions must equal the approved processing-policy label."
  }
}

# Governance-only data boundary; no Terraform resource consumes classifications.
# tflint-ignore: terraform_unused_declarations
variable "permitted_data_classifications" {
  type        = list(string)
  description = "Only synthetic PUBLIC and INTERNAL learning-project data are permitted."
  validation {
    condition     = var.permitted_data_classifications == tolist(["PUBLIC", "INTERNAL"])
    error_message = "permitted_data_classifications must equal PUBLIC, INTERNAL in that order."
  }
}

# Policy-only cost ceiling; no AWS Budgets resource is authorized in this task.
# tflint-ignore: terraform_unused_declarations
variable "monthly_budget_usd" {
  type        = number
  description = "Approved monthly policy ceiling."
  validation {
    condition     = var.monthly_budget_usd == 60
    error_message = "monthly_budget_usd must equal 60."
  }
}

# Policy-only alert threshold; no AWS Budgets resource is authorized in this task.
# tflint-ignore: terraform_unused_declarations
variable "daily_budget_alert_usd" {
  type        = number
  description = "Approved daily budget alert value."
  validation {
    condition     = var.daily_budget_alert_usd == 3
    error_message = "daily_budget_alert_usd must equal 3."
  }
}

# Owner authorization ceiling; paid evaluation remains outside Terraform.
# tflint-ignore: terraform_unused_declarations
variable "max_paid_evaluation_usd" {
  type        = number
  description = "Hard owner-approved ceiling for separately authorized paid evaluation."
  validation {
    condition     = var.max_paid_evaluation_usd == 5
    error_message = "max_paid_evaluation_usd must equal 5."
  }
}

variable "kms_deletion_window_days" {
  type        = number
  description = "Exact sandbox key deletion window."
  validation {
    condition     = var.kms_deletion_window_days == 7
    error_message = "kms_deletion_window_days must equal 7."
  }
}

# Governance-only lifecycle owner; it must not be emitted into a cloud resource.
# tflint-ignore: terraform_unused_declarations
variable "kms_follow_up_owner" {
  type        = string
  description = "Named owner for later KMS lifecycle follow-up."
  validation {
    condition     = var.kms_follow_up_owner == "Gyan Prakash Rai"
    error_message = "kms_follow_up_owner must remain Gyan Prakash Rai."
  }
}

variable "github_organization" {
  type        = string
  description = "Exact GitHub organization/user owner."
  validation {
    condition     = var.github_organization == "gprai"
    error_message = "github_organization must equal gprai."
  }
}

variable "github_repository" {
  type        = string
  description = "Exact GitHub repository name."
  validation {
    condition     = var.github_repository == "enterprise-ai-platform"
    error_message = "github_repository must equal enterprise-ai-platform."
  }
}

variable "github_environment" {
  type        = string
  description = "Exact protected GitHub environment."
  validation {
    condition     = var.github_environment == "sandbox"
    error_message = "github_environment must equal sandbox."
  }
}

variable "github_oidc_role_name" {
  type        = string
  description = "Trust-only GitHub OIDC role name."
  validation {
    condition     = var.github_oidc_role_name == "enterprise-ai-platform-sandbox-github-oidc"
    error_message = "github_oidc_role_name differs from the approved value."
  }
}

variable "github_allowed_ref" {
  type        = string
  description = "Owner-approved protected branch reference."
  validation {
    condition     = var.github_allowed_ref == "refs/heads/main"
    error_message = "github_allowed_ref must equal refs/heads/main."
  }
}

variable "bedrock_model_id" {
  type        = string
  description = "Exact Global Cross-Region inference-profile ID."
  validation {
    condition     = var.bedrock_model_id == "global.amazon.nova-2-lite-v1:0"
    error_message = "bedrock_model_id must equal global.amazon.nova-2-lite-v1:0."
  }
}

# Verification-only request Region; no Bedrock resource is provisioned by this task.
# tflint-ignore: terraform_unused_declarations
variable "bedrock_region" {
  type        = string
  description = "Exact Bedrock request source Region."
  validation {
    condition     = var.bedrock_region == "ap-southeast-1"
    error_message = "bedrock_region must equal ap-southeast-1."
  }
}

# Verification-only status; it remains pending until owner-executed TEST-001.
# tflint-ignore: terraform_unused_declarations
variable "bedrock_access_status" {
  type        = string
  description = "Owner verification remains pending until TEST-001."
  validation {
    condition     = var.bedrock_access_status == "pending_verification"
    error_message = "bedrock_access_status must remain pending_verification."
  }
}

# Governance-only fallback prohibition; no fallback resource is authorized.
# tflint-ignore: terraform_unused_declarations
variable "bedrock_fallback_policy" {
  type        = string
  nullable    = true
  description = "No automatic model, profile, provider, or Region fallback is approved."
  validation {
    condition     = var.bedrock_fallback_policy == null
    error_message = "bedrock_fallback_policy must remain null."
  }
}
