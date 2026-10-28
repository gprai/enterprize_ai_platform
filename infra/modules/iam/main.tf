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
  github_repository_subject = "repo:${var.github_organization}@${var.github_organization_id}/${var.github_repository}@${var.github_repository_id}"
  eks_cluster_arn           = "arn:aws:eks:${var.aws_region}:${var.aws_account_id}:cluster/${var.eks_cluster_name}"
  capstone_ecr_arn          = "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/enterprise-ai/sandbox/api"
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
  #checkov:skip=CKV_AWS_358:Owner-approved GitHub immutable owner and repository ID subjects are stricter than legacy repo subjects but are not recognized by Checkov 3.3.16.
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
        "${local.github_repository_subject}:environment:${var.github_environment}",
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

data "aws_iam_policy_document" "capstone_build_trust" {
  #checkov:skip=CKV_AWS_358:Owner-approved GitHub immutable owner and repository ID subjects are stricter than legacy repo subjects but are not recognized by Checkov 3.3.16.
  statement {
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
      values   = ["${local.github_repository_subject}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "capstone_build" {
  name               = "enterprise-ai-capstone-build"
  assume_role_policy = data.aws_iam_policy_document.capstone_build_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "capstone_build" {
  statement {
    sid       = "ReadExactEcrAuthorization"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
  statement {
    sid = "BuildAndInspectExactEcrRepository"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
      "ecr:DescribeImages", "ecr:DescribeImageScanFindings", "ecr:InitiateLayerUpload",
      "ecr:PutImage", "ecr:StartImageScan", "ecr:UploadLayerPart",
    ]
    resources = [local.capstone_ecr_arn]
  }
  statement {
    sid       = "InspectExactSourceVersions"
    actions   = ["s3:ListBucketVersions"]
    resources = [local.platform_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["w12-001/source/source.zip"]
    }
  }
  statement {
    sid       = "RequireSourceBucketVersioning"
    actions   = ["s3:GetBucketVersioning"]
    resources = [local.platform_bucket_arn]
  }
  statement {
    sid       = "WriteAndReadExactPrimarySource"
    actions   = ["s3:PutObject", "s3:GetObjectVersion"]
    resources = ["${local.platform_bucket_arn}/w12-001/source/source.zip"]
  }
  statement {
    sid       = "EncryptAndReadPrimarySource"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "capstone_build" {
  name   = "enterprise-ai-capstone-build"
  role   = aws_iam_role.capstone_build.id
  policy = data.aws_iam_policy_document.capstone_build.json
}

data "aws_iam_policy_document" "github_eks_deployment" {
  statement {
    sid       = "InspectExactVersionedCapstoneInputs"
    actions   = ["s3:ListBucketVersions"]
    resources = [local.platform_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["w12-001/source/source.zip", "w12-001/control/control.zip", "w12-001/results/*"]
    }
  }
  statement {
    sid       = "RequireVersionedCapstoneBucket"
    actions   = ["s3:GetBucketVersioning"]
    resources = [local.platform_bucket_arn]
  }
  statement {
    sid       = "StartOnlyExactCapstoneProject"
    actions   = ["codebuild:StartBuild", "codebuild:BatchGetBuilds"]
    resources = ["arn:aws:codebuild:${var.aws_region}:${var.aws_account_id}:project/enterprise-ai-capstone-deploy"]
  }
  statement {
    sid     = "WriteVersionedCapstoneSource"
    actions = ["s3:PutObject", "s3:GetObjectVersion"]
    resources = [
      "${local.platform_bucket_arn}/w12-001/source/source.zip",
      "${local.platform_bucket_arn}/w12-001/control/control.zip",
      "${local.platform_bucket_arn}/w12-001/results/*",
      "${local.platform_bucket_arn}/w12-001/releases/*",
    ]
  }
  statement {
    sid       = "EncryptExactCapstoneSource"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "github_eks_deployment" {
  name   = "enterprise-ai-sandbox-eks-deployment"
  role   = aws_iam_role.github_oidc.id
  policy = data.aws_iam_policy_document.github_eks_deployment.json
}

# The post-apply job has no protected environment prompt of its own. It uses a
# main-ref OIDC identity limited to one CodeBuild project and exact S3 prefixes.
resource "aws_iam_role" "capstone_deploy_caller" {
  name               = "enterprise-ai-capstone-deploy-caller"
  assume_role_policy = data.aws_iam_policy_document.capstone_build_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "capstone_deploy_caller" {
  name   = "enterprise-ai-capstone-deploy-caller"
  role   = aws_iam_role.capstone_deploy_caller.id
  policy = data.aws_iam_policy_document.github_eks_deployment.json
}

resource "aws_iam_role" "capstone_rollback_reader" {
  name               = "enterprise-ai-capstone-rollback-reader"
  assume_role_policy = data.aws_iam_policy_document.capstone_build_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "capstone_rollback_reader" {
  statement {
    sid     = "ReadExactPriorReleaseVersions"
    actions = ["s3:GetObjectVersion"]
    resources = [
      "${local.platform_bucket_arn}/w12-001/releases/*",
      "${local.platform_bucket_arn}/w12-001/control/control.zip",
      "${local.platform_bucket_arn}/w12-001/source/source.zip",
    ]
  }
  statement {
    sid       = "DecryptPriorReleaseEvidence"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "capstone_rollback_reader" {
  name   = "enterprise-ai-capstone-rollback-reader"
  role   = aws_iam_role.capstone_rollback_reader.id
  policy = data.aws_iam_policy_document.capstone_rollback_reader.json
}

data "aws_iam_policy_document" "capstone_codebuild_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:codebuild:${var.aws_region}:${var.aws_account_id}:project/enterprise-ai-capstone-deploy"]
    }
  }
}

resource "aws_iam_role" "capstone_codebuild" {
  name               = "enterprise-ai-capstone-codebuild"
  assume_role_policy = data.aws_iam_policy_document.capstone_codebuild_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "capstone_codebuild" {
  statement {
    sid       = "DescribeExactCluster"
    actions   = ["eks:DescribeCluster"]
    resources = [local.eks_cluster_arn]
  }
  statement {
    sid     = "ReadExactVersionedSource"
    actions = ["s3:GetObjectVersion"]
    resources = [
      "${local.platform_bucket_arn}/w12-001/source/source.zip",
      "${local.platform_bucket_arn}/w12-001/control/control.zip",
      "${local.platform_bucket_arn}/w12-001/results/*",
      "${local.platform_bucket_arn}/w12-001/releases/*",
    ]
  }
  statement {
    sid       = "WriteRedactedBuildResult"
    actions   = ["s3:PutObject"]
    resources = ["${local.platform_bucket_arn}/w12-001/results/*"]
  }
  statement {
    sid       = "VerifyExactRenderResources"
    actions   = ["es:DescribeDomain"]
    resources = [local.opensearch_domain_arn]
  }
  statement {
    sid       = "VerifyExactInferenceProfile"
    actions   = ["bedrock:GetInferenceProfile"]
    resources = [local.inference_profile_arn]
  }
  statement {
    sid       = "DecryptExactSource"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "WriteBoundedLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/codebuild/enterprise-ai-capstone-deploy:*"]
  }
  statement {
    sid       = "VpcNetworkInterfaceLifecycle"
    actions   = ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
  statement {
    sid       = "VpcNetworkInterfacePermission"
    actions   = ["ec2:CreateNetworkInterfacePermission"]
    resources = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:AuthorizedService"
      values   = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "capstone_codebuild" {
  name   = "enterprise-ai-capstone-deploy-only"
  role   = aws_iam_role.capstone_codebuild.id
  policy = data.aws_iam_policy_document.capstone_codebuild.json
}

# Separate short-lived owner bootstrap identity. Kubernetes ClusterAdmin access
# is controlled by a separately toggled EKS access entry, not this IAM policy.
resource "aws_iam_role" "capstone_pki_bootstrap" {
  name               = "enterprise-ai-capstone-pki-bootstrap"
  assume_role_policy = data.aws_iam_policy_document.administrator_trust.json
  tags               = var.tags
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
    sid     = "RuntimeReadGovernedObjects"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "${local.platform_bucket_arn}/${var.data_zone_prefixes["processed"]}*",
      "${local.platform_bucket_arn}/${var.data_zone_prefixes["evidence"]}*",
    ]
  }

  statement {
    sid       = "RuntimeListGovernedObjects"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [local.platform_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        "${var.data_zone_prefixes["processed"]}*",
        "${var.data_zone_prefixes["evidence"]}*",
      ]
    }
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
    sid    = "IngestionReadRawObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetObject",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ]
    resources = ["${local.platform_bucket_arn}/${var.data_zone_prefixes["raw"]}*"]
  }

  statement {
    sid     = "IngestionWriteQuarantineObjects"
    effect  = "Allow"
    actions = ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:PutObject"]
    resources = [
      "${local.platform_bucket_arn}/${var.data_zone_prefixes["quarantine"]}*",
    ]
  }

  statement {
    sid     = "IngestionWriteProcessedAndEvidenceObjects"
    effect  = "Allow"
    actions = ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:PutObject"]
    resources = [
      "${local.platform_bucket_arn}/${var.data_zone_prefixes["processed"]}*",
      "${local.platform_bucket_arn}/${var.data_zone_prefixes["evidence"]}*",
    ]
  }

  statement {
    sid       = "IngestionListPlatformBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [local.platform_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        "${var.data_zone_prefixes["raw"]}*",
        "${var.data_zone_prefixes["quarantine"]}*",
        "${var.data_zone_prefixes["processed"]}*",
        "${var.data_zone_prefixes["evidence"]}*",
      ]
    }
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
