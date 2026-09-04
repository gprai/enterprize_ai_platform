variable "bucket_name" {
  type = string
  validation {
    condition     = var.bucket_name == "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
    error_message = "bucket_name must equal the exact owner-approved sandbox name."
  }
}

variable "kms_key_arn" {
  type = string
}

variable "tags" {
  type = map(string)
}
