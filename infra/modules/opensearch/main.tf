locals {
  domain_arn = "arn:aws:es:${var.aws_region}:${var.aws_account_id}:domain/${var.domain_name}"
  log_groups = {
    application = "/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs"
    audit       = "/aws/OpenSearchService/domains/enterprise-ai-sandbox/audit-logs"
    index_slow  = "/aws/OpenSearchService/domains/enterprise-ai-sandbox/index-slow-logs"
    search_slow = "/aws/OpenSearchService/domains/enterprise-ai-sandbox/search-slow-logs"
  }
  log_stream_arns = [
    "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/application-logs:*",
    "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/audit-logs:*",
    "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/index-slow-logs:*",
    "arn:aws:logs:ap-southeast-1:526338061652:log-group:/aws/OpenSearchService/domains/enterprise-ai-sandbox/search-slow-logs:*",
  ]
}

resource "aws_cloudwatch_log_group" "this" {
  #checkov:skip=CKV_AWS_338:The owner-approved learning-sandbox retention is exactly 30 days, not a production one-year period.
  for_each = local.log_groups

  name              = each.value
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "log_delivery" {
  statement {
    sid    = "ExactOpenSearchLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = local.log_stream_arns
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["526338061652"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:es:ap-southeast-1:526338061652:domain/enterprise-ai-sandbox"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name     = "enterprise-ai-sandbox-opensearch-log-delivery"
  policy_document = data.aws_iam_policy_document.log_delivery.json
}

data "aws_iam_policy_document" "domain_access" {
  statement {
    sid    = "ExactSandboxRoleDataPlaneAccess"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        var.ingestion_role_arn,
        var.administrator_role_arn,
      ]
    }
    actions = [
      "es:ESHttpDelete",
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPatch",
      "es:ESHttpPost",
      "es:ESHttpPut",
    ]
    resources = ["${local.domain_arn}/*"]
  }

  statement {
    sid    = "RuntimeExactReadAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.runtime_role_arn]
    }
    actions = [
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPost",
    ]
    resources = [
      "${local.domain_arn}/_cluster/health",
      "${local.domain_arn}/enterprise_ai_sandbox",
      "${local.domain_arn}/enterprise_ai_sandbox/*",
    ]
  }
}

resource "aws_opensearch_domain" "this" {
  #checkov:skip=CKV_AWS_318:The owner-approved sandbox is one data node with dedicated masters disabled and makes no production availability claim.
  #checkov:skip=CKV2_AWS_59:The owner-approved sandbox is one data node with dedicated masters disabled and makes no production availability claim.
  domain_name    = var.domain_name
  engine_version = var.engine_version

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    dedicated_master_enabled = false
    zone_awareness_enabled   = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = var.ebs_volume_type
    volume_size = var.ebs_volume_size
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = var.kms_key_arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = var.administrator_role_arn
    }
  }

  vpc_options {
    subnet_ids         = [var.subnet_id]
    security_group_ids = [var.security_group_id]
  }

  access_policies = data.aws_iam_policy_document.domain_access.json

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.this["application"].arn
    log_type                 = "ES_APPLICATION_LOGS"
    enabled                  = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.this["audit"].arn
    log_type                 = "AUDIT_LOGS"
    enabled                  = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.this["index_slow"].arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.this["search_slow"].arn
    log_type                 = "SEARCH_SLOW_LOGS"
    enabled                  = true
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition = (
        var.aws_account_id == "526338061652" &&
        var.aws_region == "ap-southeast-1" &&
        var.domain_name == "enterprise-ai-sandbox" &&
        var.engine_version == "OpenSearch_2.19" &&
        var.instance_type == "t3.small.search" &&
        var.instance_count == 1 &&
        var.ebs_volume_type == "gp3" &&
        var.ebs_volume_size == 10 &&
        var.log_retention_days == 30
      )
      error_message = "OpenSearch values must match the exact approved sandbox-only sizing."
    }
  }

  depends_on = [aws_cloudwatch_log_resource_policy.opensearch]
}
