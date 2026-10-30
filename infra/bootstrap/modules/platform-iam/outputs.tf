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

output "capstone_build_role_arn" {
  value       = aws_iam_role.capstone_build.arn
  description = "Main-ref OIDC source and immutable image producer; separate from protected apply authority."
}

output "capstone_deploy_caller_role_arn" {
  value       = aws_iam_role.capstone_deploy_caller.arn
  description = "Post-apply main-ref OIDC identity limited to exact CodeBuild and source handoff operations."
}

output "capstone_rollback_reader_role_arn" {
  value       = aws_iam_role.capstone_rollback_reader.arn
  description = "Read-only main-ref OIDC identity for exact prior rollback evidence versions."
}

output "capstone_codebuild_role_arn" {
  value       = aws_iam_role.capstone_codebuild.arn
  description = "Regular namespaced deployment executor role; no Secret read."
}

output "bedrock_inference_profile_arn" {
  value       = local.inference_profile_arn
  description = "Configured Bedrock inference profile ARN for exact-state W12 rendering."
}

output "capstone_pki_bootstrap_role_arn" {
  value       = aws_iam_role.capstone_pki_bootstrap.arn
  description = "Time-bound owner bootstrap role; EKS access is separately toggled."
}

output "fis_role_arn" {
  value       = aws_iam_role.fis.arn
  description = "Role used only by an owner-approved bounded FIS experiment."
}
