# State-only ownership transfer. Applying these blocks forgets IAM objects; it does not delete them.

removed {
  from = aws_iam_role.runtime
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.ingestion
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.opensearch_administrator
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.fis
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.fis
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.github_oidc
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.capstone_build
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.capstone_build
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.github_eks_deployment
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.capstone_deploy_caller
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.capstone_deploy_caller
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.capstone_rollback_reader
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.capstone_rollback_reader
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.capstone_codebuild
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.capstone_codebuild
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.capstone_pki_bootstrap
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.runtime
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.ingestion
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.w12_image_publisher
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.w12_public_ecr_reader
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.w12_public_ecr_reader
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.w12_image_publisher
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.w12_codebuild_executor_pull
  lifecycle {
    destroy = false
  }
}
