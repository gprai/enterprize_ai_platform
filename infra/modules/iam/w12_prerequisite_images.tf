locals {
  w12_toolchain_ecr_arn = "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/enterprise-ai/sandbox/w12-toolchain"
  w12_codebuild_ecr_arn = "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/enterprise-ai/sandbox/w12-codebuild"
}

data "aws_iam_policy_document" "w12_image_publisher_trust" {
  statement {
    sid     = "ExactSandboxGitHubEnvironment"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_organization}/${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "w12_image_publisher" {
  name               = "enterprise-ai-w12-prerequisite-image-publisher"
  assume_role_policy = data.aws_iam_policy_document.w12_image_publisher_trust.json
  tags               = var.tags
}

resource "aws_iam_role" "w12_public_ecr_reader" {
  name               = "enterprise-ai-w12-public-ecr-reader"
  assume_role_policy = data.aws_iam_policy_document.w12_image_publisher_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "w12_public_ecr_reader" {
  #checkov:skip=CKV_AWS_107:AWS requires sts:GetServiceBearerToken for authenticated Public ECR; constrained to ecr-public.amazonaws.com and a token-only role.
  statement {
    sid       = "AuthorizePublicEcrLogin"
    actions   = ["ecr-public:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "AuthorizePublicEcrServiceBearerToken"
    actions   = ["sts:GetServiceBearerToken"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "sts:AWSServiceName"
      values   = ["ecr-public.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "w12_public_ecr_reader" {
  name   = "enterprise-ai-w12-public-ecr-reader"
  role   = aws_iam_role.w12_public_ecr_reader.id
  policy = data.aws_iam_policy_document.w12_public_ecr_reader.json
}

data "aws_iam_policy_document" "w12_image_publisher" {
  statement {
    sid       = "AuthorizeEcrLoginInExactRegion"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
  statement {
    sid = "PublishAndVerifyTwoPrerequisiteRepositories"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload", "ecr:DescribeImages",
      "ecr:DescribeRepositories", "ecr:GetLifecyclePolicy",
      "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload",
      "ecr:PutImage", "ecr:UploadLayerPart",
    ]
    resources = [local.w12_toolchain_ecr_arn, local.w12_codebuild_ecr_arn]
  }
}

resource "aws_iam_role_policy" "w12_image_publisher" {
  name   = "enterprise-ai-w12-prerequisite-image-publisher"
  role   = aws_iam_role.w12_image_publisher.id
  policy = data.aws_iam_policy_document.w12_image_publisher.json
}

data "aws_iam_policy_document" "w12_codebuild_executor_pull" {
  statement {
    sid       = "AuthorizeExactExecutorImagePull"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
  statement {
    sid       = "PullExactExecutorImage"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [local.w12_codebuild_ecr_arn]
  }
}

resource "aws_iam_role_policy" "w12_codebuild_executor_pull" {
  name   = "enterprise-ai-w12-codebuild-executor-pull"
  role   = aws_iam_role.capstone_codebuild.id
  policy = data.aws_iam_policy_document.w12_codebuild_executor_pull.json
}
