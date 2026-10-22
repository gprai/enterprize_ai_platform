variable "cluster_name" {
  type = string
}
variable "kubernetes_version" {
  type = string
}
variable "subnet_ids" {
  type = list(string)
}
variable "kms_key_arn" {
  type = string
}
variable "administrator_role_arn" {
  type = string
}
variable "deployment_role_arn" {
  type = string
}

variable "capstone_deploy_role_arn" {
  type        = string
  description = "Reviewed regular CodeBuild role for namespaced RBAC."
}

variable "capstone_pki_role_arn" {
  type        = string
  description = "Reviewed temporary PKI bootstrap role."
}

variable "capstone_enabled" {
  type        = bool
  description = "Owner activation of regular W12 access entry."
}

variable "pki_bootstrap_enabled" {
  type        = bool
  description = "Temporary owner activation of PKI bootstrap access."
}
variable "resilience_role_arn" {
  type = string
}
variable "public_access_cidrs" {
  type = list(string)
}
variable "node_instance_types" {
  type = list(string)
}
variable "node_minimum" {
  type = number
}
variable "node_desired" {
  type = number
}
variable "node_maximum" {
  type = number
}
variable "addon_versions" {
  type = map(string)
}
variable "metrics_server_image" {
  type = string
}
variable "runtime_role_arn" {
  type = string
}
variable "ingestion_role_arn" {
  type = string
}
variable "namespace" {
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
