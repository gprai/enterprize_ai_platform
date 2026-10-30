variable "aws_account_id" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "platform_bucket_name" {
  type = string
}

variable "data_zone_prefixes" {
  type        = map(string)
  description = "Exact W7-001 governed prefixes used for least-privilege S3 policies."
  validation {
    condition = var.data_zone_prefixes == tomap({
      raw        = "raw/"
      quarantine = "quarantine/"
      processed  = "processed/"
      evidence   = "evidence/"
    })
    error_message = "data_zone_prefixes must contain the exact four W7-001 prefixes."
  }
}

variable "kms_key_arn" {
  type = string
}

variable "opensearch_domain_name" {
  type = string
}

variable "bedrock_inference_profile_id" {
  type = string
}

variable "expires_at" {
  type = string
}

variable "github_organization" {
  type = string

  validation {
    condition     = var.github_organization == "gprai"
    error_message = "github_organization must equal gprai."
  }
}

variable "github_organization_id" {
  type = string

  validation {
    condition     = var.github_organization_id == "82297871"
    error_message = "github_organization_id must equal the verified immutable GitHub owner ID."
  }
}

variable "github_repository" {
  type = string

  validation {
    condition     = var.github_repository == "enterprize_ai_platform"
    error_message = "github_repository must equal enterprize_ai_platform."
  }
}

variable "github_repository_id" {
  type = string

  validation {
    condition     = var.github_repository_id == "1340913005"
    error_message = "github_repository_id must equal the verified immutable GitHub repository ID."
  }
}

variable "github_environment" {
  type = string
}

variable "github_oidc_role_name" {
  type = string
}

variable "github_allowed_ref" {
  type = string
}

variable "external_administrator_arn" {
  type = string
}

variable "administrator_trust_expires_at" {
  type = string
}

variable "eks_namespace" {
  type = string
}

variable "runtime_service_account" {
  type = string
}

variable "ingestion_service_account" {
  type = string
}

variable "eks_cluster_name" {
  type = string
}

variable "tags" {
  type = map(string)
}
