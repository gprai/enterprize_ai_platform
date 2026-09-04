output "runtime_role_arn" {
  value = aws_iam_role.runtime.arn
}

output "ingestion_role_arn" {
  value = aws_iam_role.ingestion.arn
}

output "opensearch_administrator_role_arn" {
  value = aws_iam_role.opensearch_administrator.arn
}

output "github_oidc_role_arn" {
  value       = aws_iam_role.github_oidc.arn
  description = "Trust-only role; no permissions policy is attached by W5-001."
}
