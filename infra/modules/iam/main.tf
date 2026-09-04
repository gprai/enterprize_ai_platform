locals {
  runtime_role_name       = "enterprise-ai-sandbox-runtime"
  ingestion_role_name     = "enterprise-ai-sandbox-ingestion"
  administrator_role_name = "enterprise-ai-sandbox-opensearch-admin"
  runtime_role_arn        = "arn:aws:iam::${var.aws_account_id}:role/${local.runtime_role_name}"
  platform_bucket_arn     = "arn:aws:s3:::${var.platform_bucket_name}"
  opensearch_domain_arn   = "arn:aws:es:${var.aws_region}:${var.aws_account_id}:domain/${var.opensearch_domain_name}"
  inference_profile_arn   = "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:inference-profile/${var.bedrock_inference_profile_id}"
  github_provider_arn     = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "runtime_trust" {
  statement {
    sid     = "ExactPodIdentityRuntimeTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [var.eks_namespace]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [var.runtime_service_account]
    }
  }
}

data "aws_iam_policy_document" "ingestion_trust" {
  statement {
    sid     = "ExactPodIdentityIngestionTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [var.eks_namespace]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [var.ingestion_service_account]
    }
  }
}

data "aws_iam_policy_document" "administrator_trust" {
  statement {
    sid     = "TimeBoundExactSandboxAdministrator"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.external_administrator_arn]
    }
    condition {
      test     = "DateLessThan"
      variable = "aws:CurrentTime"
      values   = [var.administrator_trust_expires_at]
    }
  }
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    sid     = "ExactGitHubEnvironmentTrust"
    effect  = "Allow"
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
      values = [
        "repo:${var.github_organization}/${var.github_repository}:environment:${var.github_environment}",
      ]
    }
  }
}

resource "aws_iam_role" "runtime" {
  name               = local.runtime_role_name
  assume_role_policy = data.aws_iam_policy_document.runtime_trust.json
  tags               = var.tags
}

resource "aws_iam_role" "ingestion" {
  name               = local.ingestion_role_name
  assume_role_policy = data.aws_iam_policy_document.ingestion_trust.json
  tags               = var.tags
}

resource "aws_iam_role" "opensearch_administrator" {
  name               = local.administrator_role_name
  assume_role_policy = data.aws_iam_policy_document.administrator_trust.json
  tags               = var.tags

  lifecycle {
    precondition {
      condition = (
        var.external_administrator_arn == "arn:aws:iam::526338061652:user/finopsinfra" &&
        var.administrator_trust_expires_at == "2026-09-30T15:59:59Z"
      )
      error_message = "OpenSearch administrator trust must retain the exact principal and UTC expiry."
    }
  }
}

resource "aws_iam_role" "github_oidc" {
  name               = var.github_oidc_role_name
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
  tags               = var.tags

  lifecycle {
    precondition {
      condition     = var.github_allowed_ref == "refs/heads/main"
      error_message = "GitHub environment protection must remain bound to refs/heads/main."
    }
  }
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid       = "InvokeExactApprovedInferenceProfile"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.inference_profile_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.runtime_role_arn]
    }
    condition {
      test     = "DateLessThan"
      variable = "aws:CurrentTime"
      values   = [var.expires_at]
    }
  }

  statement {
    sid       = "RuntimeReadPlatformObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.platform_bucket_arn}/*"]
  }

  statement {
    sid       = "RuntimeListPlatformBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [local.platform_bucket_arn]
  }

  statement {
    sid       = "RuntimeUsePlatformKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }

  statement {
    sid    = "RuntimeOpenSearchDataPlane"
    effect = "Allow"
    actions = [
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPost",
    ]
    resources = ["${local.opensearch_domain_arn}/*"]
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "enterprise-ai-sandbox-runtime"
  role   = aws_iam_role.runtime.id
  policy = data.aws_iam_policy_document.runtime.json
}

data "aws_iam_policy_document" "ingestion" {
  statement {
    sid    = "IngestionPlatformObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ]
    resources = ["${local.platform_bucket_arn}/*"]
  }

  statement {
    sid       = "IngestionListPlatformBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [local.platform_bucket_arn]
  }

  statement {
    sid    = "IngestionUsePlatformKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = [var.kms_key_arn]
  }

  statement {
    sid    = "IngestionOpenSearchDataPlane"
    effect = "Allow"
    actions = [
      "es:ESHttpDelete",
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPatch",
      "es:ESHttpPost",
      "es:ESHttpPut",
    ]
    resources = ["${local.opensearch_domain_arn}/*"]
  }
}

resource "aws_iam_role_policy" "ingestion" {
  name   = "enterprise-ai-sandbox-ingestion"
  role   = aws_iam_role.ingestion.id
  policy = data.aws_iam_policy_document.ingestion.json
}
