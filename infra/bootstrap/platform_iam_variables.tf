variable "adopt_existing_platform_iam" {
  type        = bool
  default     = false
  description = "One-time adoption only, after the sandbox removed blocks have forgotten the 31 workload IAM objects. False creates missing IAM during a fresh bootstrap."
}

variable "platform_iam_binding_overrides" {
  type        = map(string)
  default     = {}
  description = "Explicit owner-reviewed replacement for captured physical identities and expiry times. Never substitute wildcard ARNs. Bootstrap KMS is derived from this root."
  validation {
    condition = alltrue([for k, v in var.platform_iam_binding_overrides :
      contains(["sandbox_kms_key_arn", "sandbox_vpc_arn", "sandbox_route_table_arn", "sandbox_default_security_group_arn", "sandbox_endpoint_security_group_arn", "sandbox_subnet_a_arn", "sandbox_subnet_b_arn", "administrator_role_arn", "administrator_trust_expires_at", "workload_expires_at", "bedrock_model_id"], k) &&
      !can(regex("[\"*?$]", v)) && !strcontains(v, "\n")
    ])
    error_message = "Use only the named exact identity bindings; wildcards, quotes, template interpolation and newlines are prohibited."
  }
  validation {
    condition = alltrue([for k, v in var.platform_iam_binding_overrides :
      endswith(k, "_expires_at") ? can(timecmp(v, "2000-01-01T00:00:00Z")) :
      endswith(k, "_arn") ? can(regex("^arn:aws:(kms:ap-southeast-1:526338061652:key/[a-f0-9-]+|ec2:ap-southeast-1:526338061652:(vpc/vpc-|subnet/subnet-|security-group/sg-|route-table/rtb-)[a-f0-9]+|iam::526338061652:role/[A-Za-z0-9_+=,.@/-]+)$", v)) : length(v) > 0
    ])
    error_message = "Physical bindings must be exact ARNs in the approved account/region; expiry values must be UTC timestamps."
  }
}

variable "platform_iam_tags" {
  type        = map(string)
  description = "Retained workload IAM tags. ExpiresAt is controlled by platform_iam_binding_overrides.workload_expires_at."
  default = {
    "Owner"       = "Gyan-Prakash-Rai",
    "CostCenter"  = "Personal-Learning",
    "Environment" = "sandbox",
    "ManagedBy"   = "terraform",
    "Project"     = "enterprise-ai-platform",
    "Feature"     = "MVP-001",
    "Repository"  = "enterprise-ai-platform"
  }
}
