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
