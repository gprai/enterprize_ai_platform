resource "aws_cloudwatch_log_group" "application" {
  #checkov:skip=CKV_AWS_158:The approved W5 customer-key policy is intentionally unchanged; CloudWatch service encryption is retained until fresh KMS compatibility evidence is approved.
  #checkov:skip=CKV_AWS_338:Owner-approved sandbox-only 14-day retention for deployment/teardown testing; older application logs may expire. Not approved for production.
  name              = "/aws/enterprise-ai-platform/sandbox/application"
  retention_in_days = var.retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "eks" {
  #checkov:skip=CKV_AWS_158:The approved W5 customer-key policy is intentionally unchanged; CloudWatch service encryption is retained until fresh KMS compatibility evidence is approved.
  #checkov:skip=CKV_AWS_338:Owner-approved sandbox-only 14-day retention for deployment/teardown testing; older EKS cluster logs may expire. Not approved for production.
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = var.retention_days
  tags              = var.tags
}

locals {
  bedrock_log_prefix     = "bedrock-model-invocations"
  bedrock_log_group_name = "/aws/bedrock/${var.name}/model-invocations"
}

resource "aws_cloudwatch_log_group" "bedrock_invocations" {
  #checkov:skip=CKV_AWS_158:Owner-approved CloudWatch service-side encryption is used for this seven-day synthetic-only evidence window; large payloads use the platform KMS-encrypted bucket.
  #checkov:skip=CKV_AWS_338:Owner-approved synthetic transcript retention is exactly seven days, followed by expiry.
  name              = local.bedrock_log_group_name
  retention_in_days = 7
  tags              = var.tags
}

data "aws_iam_role" "bedrock_log_delivery" {
  name = "${var.name}-bedrock-log-delivery"
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  count = var.bedrock_invocation_logging_enabled ? 1 : 0

  logging_config {
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true
    video_data_delivery_enabled     = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_invocations.name
      role_arn       = data.aws_iam_role.bedrock_log_delivery.arn

      large_data_delivery_s3_config {
        bucket_name = var.platform_bucket_name
        key_prefix  = local.bedrock_log_prefix
      }
    }

    s3_config {
      bucket_name = var.platform_bucket_name
      key_prefix  = local.bedrock_log_prefix
    }
  }

}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_email_endpoints)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_metric_alarm" "availability" {
  alarm_name          = "${var.name}-availability-burn"
  namespace           = "EnterpriseAI/Sandbox"
  metric_name         = "AvailabilityBad"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "safety" {
  alarm_name          = "${var.name}-safety"
  namespace           = "EnterpriseAI/Sandbox"
  metric_name         = "SafetyViolations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Sandbox availability and safety signals"
          region = var.aws_region
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
          metrics = [
            ["EnterpriseAI/Sandbox", "AvailabilityBad"],
            [".", "SafetyViolations"],
            [".", "ExportFailures"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Sandbox latency review targets"
          region = var.aws_region
          view   = "timeSeries"
          period = 300
          metrics = [
            ["EnterpriseAI/Sandbox", "RequestLatency", { stat = "p95" }],
            [".", ".", { stat = "p99" }],
            [".", "RetrievalLatency", { stat = "p99" }],
          ]
        }
      },
    ]
  })
}

resource "aws_fis_experiment_template" "pod_delete" {
  description = "W6-004 bounded one-pod resilience exercise; execution requires separate approval"
  role_arn    = var.fis_role_arn
  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = aws_cloudwatch_metric_alarm.availability.arn
  }
  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = aws_cloudwatch_metric_alarm.safety.arn
  }
  target {
    name           = "one-application-pod"
    resource_type  = "aws:eks:pod"
    selection_mode = "COUNT(1)"
    parameters = {
      clusterIdentifier = var.cluster_arn
      namespace         = var.namespace
      selectorType      = "labelSelector"
      selectorValue     = "app.kubernetes.io/name=enterprise-ai-api"
    }
  }
  action {
    name      = "delete-one-pod"
    action_id = "aws:eks:pod-delete"
    parameter {
      key   = "kubernetesServiceAccount"
      value = var.fis_service_account
    }
    target {
      key   = "Pods"
      value = "one-application-pod"
    }
  }
  tags = var.tags

  lifecycle {
    ignore_changes = [tags["ExpiresAt"]]
  }
}
