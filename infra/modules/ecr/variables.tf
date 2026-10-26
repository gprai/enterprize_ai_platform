variable "repository_name" {
  type = string
  validation {
    condition = contains([
      "enterprise-ai/sandbox/api",
      "enterprise-ai/sandbox/w12-toolchain",
      "enterprise-ai/sandbox/w12-codebuild",
    ], var.repository_name)
    error_message = "repository_name must be one of the three exact sandbox image repositories."
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
