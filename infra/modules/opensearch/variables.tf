variable "aws_account_id" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "engine_version" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "instance_count" {
  type = number
}

variable "ebs_volume_type" {
  type = string
}

variable "ebs_volume_size" {
  type = number
}

variable "log_retention_days" {
  type = number
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "runtime_role_arn" {
  type = string
}

variable "ingestion_role_arn" {
  type = string
}

variable "administrator_role_arn" {
  type = string
}

variable "tags" {
  type = map(string)
}
