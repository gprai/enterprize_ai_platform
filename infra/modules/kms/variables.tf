variable "aws_account_id" {
  type = string
}

variable "alias_name" {
  type = string
  validation {
    condition     = startswith(var.alias_name, "alias/enterprise-ai-platform-sandbox")
    error_message = "KMS alias must remain inside the approved sandbox namespace."
  }
}

variable "deletion_window_days" {
  type = number
  validation {
    condition     = var.deletion_window_days == 7
    error_message = "Sandbox KMS deletion window must equal 7 days."
  }
}

variable "runtime_role_name" {
  type = string
}

variable "ingestion_role_name" {
  type = string
}

variable "opensearch_log_group_arns" {
  type = list(string)
  validation {
    condition = var.opensearch_log_group_arns == tolist([
      "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs",
      "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/audit-logs",
      "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/index-slow-logs",
      "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/search-slow-logs",
    ])
    error_message = "OpenSearch log encryption must remain bound to the four exact approved sandbox log groups."
  }
}

variable "tags" {
  type = map(string)
}
