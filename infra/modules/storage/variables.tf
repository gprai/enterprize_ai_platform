variable "bucket_name" {
  type = string
  validation {
    condition     = var.bucket_name == "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
    error_message = "bucket_name must equal the exact owner-approved sandbox name."
  }
}

variable "kms_key_arn" {
  type = string
}

variable "aws_account_id" {
  type = string
  validation {
    condition     = var.aws_account_id == "526338061652"
    error_message = "aws_account_id must equal the owner-approved sandbox account."
  }
}

variable "aws_region" {
  type = string
  validation {
    condition     = var.aws_region == "ap-southeast-1"
    error_message = "aws_region must equal ap-southeast-1."
  }
}

variable "bedrock_log_prefix" {
  type = string
  validation {
    condition     = var.bedrock_log_prefix == "bedrock-model-invocations"
    error_message = "bedrock_log_prefix differs from the approved bounded prefix."
  }
}

variable "data_zone_prefixes" {
  type        = map(string)
  description = "Exact W7-001 governed data-zone prefixes in the existing platform bucket."
  validation {
    condition = var.data_zone_prefixes == {
      raw        = "raw/"
      quarantine = "quarantine/"
      processed  = "processed/"
      evidence   = "evidence/"
    }
    error_message = "data_zone_prefixes must contain the exact four W7-001 prefixes."
  }
}

variable "data_zone_retention_days" {
  type        = map(number)
  description = "Exact W7-001 object-zone retention periods."
  validation {
    condition = var.data_zone_retention_days == {
      raw        = 7
      quarantine = 7
      processed  = 30
      evidence   = 30
    }
    error_message = "data_zone_retention_days must equal raw/quarantine 7 and processed/evidence 30."
  }
}

variable "tags" {
  type = map(string)
}
