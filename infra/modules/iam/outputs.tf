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
  description = "Environment-protected CI/CD deployment role scoped to the exact sandbox cluster."
}

output "fis_role_arn" {
  value       = aws_iam_role.fis.arn
  description = "Role used only by an owner-approved bounded FIS experiment."
}
