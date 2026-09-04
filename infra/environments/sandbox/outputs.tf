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

output "ecr_repository_arn" {
  value       = module.ecr.repository_arn
  description = "Encrypted sandbox ECR repository ARN."
}
