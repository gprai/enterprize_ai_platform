variable "name" {
  type = string
}
variable "aws_region" {
  type = string
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
