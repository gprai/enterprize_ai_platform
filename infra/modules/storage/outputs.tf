output "bucket_name" {
  value = aws_s3_bucket.this.id
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}

output "data_zone_prefixes" {
  value       = var.data_zone_prefixes
  description = "Exact non-secret W7-001 data-zone prefix contract."
}

output "eventbridge_notifications_enabled" {
  value       = aws_s3_bucket_notification.eventbridge.eventbridge
  description = "Whether the existing bucket emits S3 events to EventBridge."
}
