variable "secret_names" {
  type        = set(string)
  description = "Metadata-only secret names; no values or versions are accepted."
  default     = []

  validation {
    condition = alltrue([
      for name in var.secret_names : can(regex("^/enterprise-ai/sandbox/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$", name))
    ])
    error_message = "Every secret metadata name must match /enterprise-ai/sandbox/<component>/<purpose>."
  }
}

variable "kms_key_arn" {
  type = string
}

variable "tags" {
  type = map(string)
}
