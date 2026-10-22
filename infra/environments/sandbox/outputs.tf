output "vpc_id" {
  value       = module.network.vpc_id
  description = "Project-owned private sandbox VPC ID."
}

output "private_subnet_ids" {
  value       = module.network.private_subnet_ids
  description = "Exact ordered two-AZ private subnet IDs."
}

output "platform_bucket_name" {
  value       = module.storage.bucket_name
  description = "Exact encrypted platform bucket."
}

output "w7_data_zone_prefixes" {
  value       = module.storage.data_zone_prefixes
  description = "Exact non-secret W7-001 prefixes in the existing platform bucket."
}

output "w7_s3_eventbridge_notifications_enabled" {
  value       = module.storage.eventbridge_notifications_enabled
  description = "S3 EventBridge notification contract; no rule or target is created."
}

output "runtime_role_arn" {
  value       = module.iam.runtime_role_arn
  description = "Least-privilege runtime workload role."
}

output "ingestion_role_arn" {
  value       = module.iam.ingestion_role_arn
  description = "Least-privilege ingestion workload role."
}

output "opensearch_domain_arn" {
  value       = module.opensearch.domain_arn
  description = "Private sandbox OpenSearch domain ARN."
}

output "opensearch_https_endpoint" {
  value       = "https://${module.opensearch.domain_endpoint}"
  description = "Non-sensitive HTTPS origin from the exact applied sandbox state."
}

output "bedrock_inference_profile_arn" {
  value       = module.iam.bedrock_inference_profile_arn
  description = "Owner-selected inference profile identity from the applied sandbox state."
}

output "ecr_repository_arn" {
  value       = module.ecr.repository_arn
  description = "Encrypted sandbox ECR repository ARN."
}

output "eks_cluster_arn" {
  value       = var.w6_004_enabled ? module.eks[0].cluster_arn : null
  description = "W6-004 EKS cluster ARN when owner-bound deployment is enabled."
}

output "alert_topic_arn" {
  value       = var.w6_004_enabled ? module.observability[0].alert_topic_arn : null
  description = "W6-004 live alert topic ARN."
}

output "metrics_server_image" {
  value       = var.w6_004_enabled ? module.eks[0].metrics_server_image : null
  description = "Owner-bound immutable Metrics Server artifact for the Kubernetes stage."
}

output "capstone_codebuild_project_arn" {
  value       = var.w12_capstone_enabled ? aws_codebuild_project.capstone_deploy[0].arn : null
  description = "Exact private CodeBuild project identity for owner preflight."
}

output "capstone_codebuild_project_name" {
  value       = var.w12_capstone_enabled ? aws_codebuild_project.capstone_deploy[0].name : null
  description = "Exact CodeBuild project name for the approved source-versioned start request."
}

output "capstone_release_source_bucket_name" {
  value       = module.storage.bucket_name
  description = "Versioned, encrypted source and result bucket for W12."
}

output "capstone_release_source_bucket_arn" {
  value       = module.storage.bucket_arn
  description = "Exact bucket IAM and owner preflight identity."
}

output "capstone_codebuild_role_arn" {
  value       = module.iam.capstone_codebuild_role_arn
  description = "Regular executor IAM principal; no Kubernetes Secret read grant."
}

output "capstone_build_role_arn" {
  value       = module.iam.capstone_build_role_arn
  description = "Main-ref OIDC source and image builder; identity requires live owner review."
}

output "capstone_deploy_caller_role_arn" {
  value       = module.iam.capstone_deploy_caller_role_arn
  description = "Exact post-apply OIDC CodeBuild caller; owner must bind the GitHub variable to this ARN."
}

output "capstone_rollback_reader_role_arn" {
  value       = module.iam.capstone_rollback_reader_role_arn
  description = "Exact read-only OIDC role for prior rollback lineage preflight."
}

output "capstone_pki_bootstrap_role_arn" {
  value       = module.iam.capstone_pki_bootstrap_role_arn
  description = "Owner bootstrap IAM principal; EKS access defaults disabled."
}

output "capstone_codebuild_security_group_id" {
  value       = module.network.capstone_codebuild_security_group_id
  description = "Private endpoint-only executor egress group."
}
