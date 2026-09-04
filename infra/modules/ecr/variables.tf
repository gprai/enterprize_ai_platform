variable "repository_name" {
  type = string
  validation {
    condition     = var.repository_name == "enterprise-ai/sandbox/api"
    error_message = "repository_name must equal enterprise-ai/sandbox/api."
  }
}

variable "retained_image_count" {
  type = number
  validation {
    condition     = var.retained_image_count == 10
    error_message = "retained_image_count must equal 10."
  }
}

variable "kms_key_arn" {
  type = string
}

variable "tags" {
  type = map(string)
}
