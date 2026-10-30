output "w12_image_publisher_role_arn" {
  value       = aws_iam_role.w12_image_publisher.arn
  description = "Dedicated GitHub environment OIDC publisher for only two prerequisite repositories."
}
