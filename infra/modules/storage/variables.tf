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

variable "tags" {
  type = map(string)
}
