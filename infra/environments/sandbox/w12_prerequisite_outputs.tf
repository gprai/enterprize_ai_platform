output "w12_toolchain_ecr_repository_url" {
  value       = module.w12_toolchain_ecr.repository_url
  description = "Private prerequisite toolchain repository; publication is a separate owner action."
}

output "w12_codebuild_ecr_repository_url" {
  value       = module.w12_codebuild_ecr.repository_url
  description = "Private prerequisite CodeBuild repository; publication is a separate owner action."
}

output "w12_image_publisher_role_arn" {
  value       = module.iam.w12_image_publisher_role_arn
  description = "Environment-scoped OIDC role for exact prerequisite image repositories."
}
