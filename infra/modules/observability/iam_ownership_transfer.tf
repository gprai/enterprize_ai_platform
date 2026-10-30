# State-only ownership transfer. Applying these blocks forgets IAM objects; it does not delete them.

removed {
  from = aws_iam_role.bedrock_log_delivery
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.bedrock_log_delivery
  lifecycle {
    destroy = false
  }
}
