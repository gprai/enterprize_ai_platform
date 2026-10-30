# State-only ownership transfer. Applying these blocks forgets IAM objects; it does not delete them.

removed {
  from = aws_iam_role.cluster
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy_attachment.cluster
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.node
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy_attachment.node
  lifecycle {
    destroy = false
  }
}
