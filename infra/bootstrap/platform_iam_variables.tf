variable "adopt_existing_platform_iam" {
  type        = bool
  default     = false
  description = "One-time adoption only, after the sandbox removed blocks have forgotten the 31 workload IAM objects. False creates missing IAM during a fresh bootstrap."
}

variable "platform_iam_binding_overrides" {
  type        = map(string)
  default     = {}
  description = "Required current, owner-reviewed physical identities and expiries from the HCP handoff. Captured bindings are historical evidence only."
  validation {
    condition = alltrue([for key in concat(
      ["sandbox_kms_key_arn", "sandbox_vpc_arn", "sandbox_default_security_group_arn", "administrator_role_arn", "administrator_trust_expires_at", "workload_expires_at", "bedrock_model_id"],
      var.platform_iam_binding_phase == "complete" ? ["sandbox_route_table_arn", "sandbox_endpoint_security_group_arn", "sandbox_subnet_a_arn", "sandbox_subnet_b_arn"] : []
    ) : contains(keys(var.platform_iam_binding_overrides), key)])
    error_message = "Supply every current binding required by this phase; historical identities are never substituted."
  }
  validation {
    condition = try(
      timecmp(var.platform_iam_approval_issued_at, plantimestamp()) <= 0 &&
      timecmp(var.platform_iam_binding_overrides.administrator_trust_expires_at, plantimestamp()) > 0 &&
      timecmp(var.platform_iam_binding_overrides.workload_expires_at, var.platform_iam_binding_overrides.administrator_trust_expires_at) >= 0 &&
      timecmp(var.platform_iam_binding_overrides.workload_expires_at, timeadd(var.platform_iam_approval_issued_at, "24h")) <= 0,
      false
    )
    error_message = "IAM trust must remain current; workload expiry must cover trust and stay within 24 hours of owner approval."
  }
  validation {
    condition = alltrue([for key, value in var.platform_iam_binding_overrides :
      !startswith(key, "sandbox_") || can(regex(lookup({
        sandbox_kms_key_arn                 = "^arn:aws:kms:ap-southeast-1:526338061652:key/[a-f0-9-]{36}$"
        sandbox_vpc_arn                     = "^arn:aws:ec2:ap-southeast-1:526338061652:vpc/vpc-[a-f0-9]+$"
        sandbox_route_table_arn             = "^arn:aws:ec2:ap-southeast-1:526338061652:route-table/rtb-[a-f0-9]+$"
        sandbox_default_security_group_arn  = "^arn:aws:ec2:ap-southeast-1:526338061652:security-group/sg-[a-f0-9]+$"
        sandbox_endpoint_security_group_arn = "^arn:aws:ec2:ap-southeast-1:526338061652:security-group/sg-[a-f0-9]+$"
        sandbox_subnet_a_arn                = "^arn:aws:ec2:ap-southeast-1:526338061652:subnet/subnet-[a-f0-9]+$"
        sandbox_subnet_b_arn                = "^arn:aws:ec2:ap-southeast-1:526338061652:subnet/subnet-[a-f0-9]+$"
      }, key, "^INVALID$"), value))
    ])
    error_message = "A binding must match its exact resource kind, account and region."
  }
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

variable "platform_iam_binding_phase" {
  type    = string
  default = "complete"
  validation {
    condition     = contains(["seed", "complete"], var.platform_iam_binding_phase)
    error_message = "Only seed and complete HCP binding handoffs are supported."
  }
}

variable "platform_iam_approval_issued_at" {
  type        = string
  default     = "OWNER_APPROVAL_REQUIRED"
  description = "Fresh owner approval timestamp; supplied by the bounded lifecycle context."
}

variable "platform_iam_source_state" {
  type    = object({ workspace_id = string, state_version_id = string, serial = number })
  default = null
  validation {
    condition = try(
      var.platform_iam_source_state.workspace_id == "ws-mCJeYzAnwyAUffuH" &&
      can(regex("^sv-[A-Za-z0-9]+$", var.platform_iam_source_state.state_version_id)) &&
      var.platform_iam_source_state.serial > 0, false
    )
    error_message = "A finalized sandbox HCP state identity is required for the binding handoff."
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
