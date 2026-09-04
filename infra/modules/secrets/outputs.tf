output "secret_arns" {
  value       = { for name, secret in aws_secretsmanager_secret.metadata : name => secret.arn }
  description = "Metadata-only secret ARNs; empty when no names are approved."
}

output "secret_count" {
  value       = length(aws_secretsmanager_secret.metadata)
  description = "Zero for the approved W5-001 sandbox composition."
}
