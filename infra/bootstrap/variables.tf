variable "aws_account_id" {
  description = "Exact owner-approved sandbox AWS account."
  type        = string
  default     = "526338061652"

  validation {
    condition     = var.aws_account_id == "526338061652"
    error_message = "aws_account_id must match the approved sandbox account."
  }
}

variable "aws_region" {
  description = "Exact bootstrap Region."
  type        = string
  default     = "ap-southeast-1"

  validation {
    condition     = var.aws_region == "ap-southeast-1"
    error_message = "aws_region must be ap-southeast-1."
  }
}

variable "state_bucket_name" {
  description = "Exact sandbox remote-state bucket name."
  type        = string
  default     = "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"

  validation {
    condition = (
      var.state_bucket_name ==
      "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
    )
    error_message = "state_bucket_name must match the exact approved sandbox bucket."
  }
}

variable "lock_table_name" {
  description = "Exact sandbox state-lock table name."
  type        = string
  default     = "enterprise-ai-platform-sandbox-tflock"

  validation {
    condition     = var.lock_table_name == "enterprise-ai-platform-sandbox-tflock"
    error_message = "lock_table_name must match the exact approved sandbox table."
  }
}

variable "state_kms_alias" {
  description = "Exact dedicated bootstrap state-key alias."
  type        = string
  default     = "alias/enterprise-ai-platform-sandbox-terraform-state"

  validation {
    condition = (
      var.state_kms_alias == "alias/enterprise-ai-platform-sandbox-terraform-state"
    )
    error_message = "state_kms_alias must match the exact approved sandbox alias."
  }
}

variable "kms_deletion_window_days" {
  description = "Owner-approved sandbox KMS deletion window."
  type        = number
  default     = 7

  validation {
    condition     = var.kms_deletion_window_days == 7
    error_message = "kms_deletion_window_days must remain 7."
  }
}

variable "mandatory_tags" {
  description = "Exact lifecycle and ownership tags; ExpiresAt remains owner-supplied."
  type        = map(string)
  default = {
    Project     = "enterprise-ai-platform"
    Environment = "sandbox"
    Owner       = "Gyan-Prakash-Rai"
    ManagedBy   = "terraform"
    CostCenter  = "Personal-Learning"
    Feature     = "MVP-001"
    ExpiresAt   = "TODO_OWNER"
    Repository  = "enterprise-ai-platform"
  }

  validation {
    condition = (
      length(var.mandatory_tags) == 8 &&
      var.mandatory_tags["Project"] == "enterprise-ai-platform" &&
      var.mandatory_tags["Environment"] == "sandbox" &&
      var.mandatory_tags["Owner"] == "Gyan-Prakash-Rai" &&
      var.mandatory_tags["ManagedBy"] == "terraform" &&
      var.mandatory_tags["CostCenter"] == "Personal-Learning" &&
      var.mandatory_tags["Feature"] == "MVP-001" &&
      var.mandatory_tags["Repository"] == "enterprise-ai-platform"
    )
    error_message = "mandatory_tags must preserve all exact owner-approved values."
  }
}
