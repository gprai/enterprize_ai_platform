variable "aws_account_id" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "platform_bucket_name" {
  type = string
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
}

variable "github_repository" {
  type = string
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

variable "tags" {
  type = map(string)
}
