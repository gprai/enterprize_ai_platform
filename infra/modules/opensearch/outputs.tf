output "domain_arn" {
  value = aws_opensearch_domain.this.arn
}

output "domain_endpoint" {
  value = aws_opensearch_domain.this.endpoint
}

output "log_group_names" {
  value = { for kind, group in aws_cloudwatch_log_group.this : kind => group.name }
}
