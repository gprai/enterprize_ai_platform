locals {
  runtime_role_name         = "enterprise-ai-sandbox-runtime"
  ingestion_role_name       = "enterprise-ai-sandbox-ingestion"
  administrator_role_name   = "enterprise-ai-sandbox-opensearch-admin"
  runtime_role_arn          = "arn:aws:iam::${var.aws_account_id}:role/${local.runtime_role_name}"
  platform_bucket_arn       = "arn:aws:s3:::${var.platform_bucket_name}"
  opensearch_domain_arn     = "arn:aws:es:${var.aws_region}:${var.aws_account_id}:domain/${var.opensearch_domain_name}"
  opensearch_index_root_arn = "${local.opensearch_domain_arn}/enterprise_ai_sandbox"
  opensearch_index_arn      = "${local.opensearch_domain_arn}/enterprise_ai_sandbox/*"
  inference_profile_arn     = "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:inference-profile/${var.bedrock_inference_profile_id}"
  foundation_model_id       = trimprefix(var.bedrock_inference_profile_id, "global.")
  regional_model_arn        = "arn:aws:bedrock:${var.aws_region}::foundation-model/${local.foundation_model_id}"
  global_model_arn          = "arn:aws:bedrock:::foundation-model/${local.foundation_model_id}"
  github_provider_arn       = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
  eks_cluster_arn           = "arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.eks_cluster_name}"
  application_log_arn       = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/enterprise-ai-platform/sandbox/application:*"
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
        can(regex("^arn:aws:iam::526338061652:role/", var.external_administrator_arn)) &&
        can(timecmp(var.administrator_trust_expires_at, timestamp()))
      )
      error_message = "OpenSearch administrator trust requires an approved account role and UTC expiry."
    }
  }
}

data "aws_iam_policy_document" "fis_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["fis.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fis" {
  name               = "enterprise-ai-sandbox-fis"
  assume_role_policy = data.aws_iam_policy_document.fis_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "fis" {
  #checkov:skip=CKV_AWS_111:Read-only EC2 and tagging discovery APIs do not support resource-level permissions; FIS execution remains separately owner-approved.
  #checkov:skip=CKV_AWS_355:The owner-approved read-only discovery wildcards are limited to APIs without resource-level permissions.
  statement {
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSubnets", "tag:GetResources"]
    resources = ["*"]
  }
  statement {
    actions   = ["eks:DescribeCluster", "eks:AccessKubernetesApi"]
    resources = [local.eks_cluster_arn]
  }
}

resource "aws_iam_role_policy" "fis" {
  name   = "bounded-eks-pod-delete-discovery"
  role   = aws_iam_role.fis.id
  policy = data.aws_iam_policy_document.fis.json
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

data "aws_iam_policy_document" "github_eks_deployment" {
  statement {
    actions   = ["eks:DescribeCluster", "eks:AccessKubernetesApi"]
    resources = [local.eks_cluster_arn]
  }
}

resource "aws_iam_role_policy" "github_eks_deployment" {
  name   = "enterprise-ai-sandbox-eks-deployment"
  role   = aws_iam_role.github_oidc.id
  policy = data.aws_iam_policy_document.github_eks_deployment.json
}

data "aws_iam_policy_document" "runtime" {
  #checkov:skip=CKV_AWS_111:The approved CloudWatch PutMetricData and X-Ray ingestion APIs do not support resource-level permissions; namespace, principal, region, role expiry and Pod Identity constrain use.
  #checkov:skip=CKV_AWS_355:The approved telemetry wildcard resources are limited to CloudWatch and X-Ray APIs without resource-level authorization support.
  statement {
    sid       = "InvokeExactGlobalInferenceProfile"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.inference_profile_arn]
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
    sid       = "InvokeExactGlobalInferenceProfileRegionalModel"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.regional_model_arn]
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
    sid       = "InvokeExactGlobalInferenceProfileGlobalModel"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.global_model_arn]
    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.inference_profile_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["unspecified"]
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
    sid     = "RuntimeOpenSearchHealthRead"
    effect  = "Allow"
    actions = ["es:ESHttpGet"]
    resources = [
      "${local.opensearch_domain_arn}/_cluster/health",
    ]
  }

  statement {
    sid    = "RuntimeOpenSearchExactIndexQuery"
    effect = "Allow"
    actions = [
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPost",
    ]
    resources = [
      local.opensearch_index_root_arn,
      local.opensearch_index_arn,
    ]
  }

  statement {
    sid    = "RuntimeWriteSafeApplicationLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = [local.application_log_arn]
  }

  statement {
    sid       = "RuntimeWriteBoundedMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["EnterpriseAI/Sandbox"]
    }
  }

  statement {
    sid       = "RuntimeWriteXRayTelemetry"
    effect    = "Allow"
    actions   = ["xray:PutTelemetryRecords", "xray:PutTraceSegments"]
    resources = ["*"]
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
    resources = [
      local.opensearch_index_root_arn,
      local.opensearch_index_arn,
    ]
  }
}

resource "aws_iam_role_policy" "ingestion" {
  name   = "enterprise-ai-sandbox-ingestion"
  role   = aws_iam_role.ingestion.id
  policy = data.aws_iam_policy_document.ingestion.json
}
