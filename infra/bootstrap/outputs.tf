output "state_bucket_name" {
  description = "Exact state bucket for the later owner-reviewed backend configuration."
  value       = aws_s3_bucket.terraform_state.id
}

output "lock_table_name" {
  description = "Exact DynamoDB state-lock table."
  value       = aws_dynamodb_table.terraform_lock.name
}

output "state_kms_key_arn" {
  description = "Dedicated state-encryption KMS key ARN."
  value       = aws_kms_key.terraform_state.arn
}
