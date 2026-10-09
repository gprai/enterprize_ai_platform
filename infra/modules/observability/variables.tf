variable "name" {
  type = string
}
variable "aws_region" {
  type = string
}
variable "aws_account_id" {
  type = string
}
variable "platform_bucket_name" {
  type = string
}
variable "bedrock_invocation_logging_enabled" {
  type = bool
}
variable "retention_days" {
  type = number
}
variable "alert_email_endpoints" {
  type    = list(string)
  default = []
}
variable "fis_role_arn" {
  type = string
}
variable "cluster_arn" {
  type = string
}
variable "namespace" {
  type = string
}
variable "fis_service_account" {
  type = string
}
variable "tags" {
  type = map(string)
}
