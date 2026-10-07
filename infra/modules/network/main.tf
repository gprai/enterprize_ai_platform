locals {
  gateway_endpoint_services = {
    S3       = "com.amazonaws.${var.aws_region}.s3"
    DynamoDB = "com.amazonaws.${var.aws_region}.dynamodb"
  }
  interface_endpoint_services = {
    "ECR API"               = "com.amazonaws.${var.aws_region}.ecr.api"
    "ECR DKR"               = "com.amazonaws.${var.aws_region}.ecr.dkr"
    EKS                     = "com.amazonaws.${var.aws_region}.eks"
    "EKS Auth"              = "com.amazonaws.${var.aws_region}.eks-auth"
    STS                     = "com.amazonaws.${var.aws_region}.sts"
    EC2                     = "com.amazonaws.${var.aws_region}.ec2"
    "CloudWatch Logs"       = "com.amazonaws.${var.aws_region}.logs"
    "CloudWatch Monitoring" = "com.amazonaws.${var.aws_region}.monitoring"
    "X-Ray"                 = "com.amazonaws.${var.aws_region}.xray"
    KMS                     = "com.amazonaws.${var.aws_region}.kms"
    "Secrets Manager"       = "com.amazonaws.${var.aws_region}.secretsmanager"
    "Bedrock Runtime"       = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  }
  gateway_endpoint_actions = {
    S3 = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListBucketVersions",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ]
    DynamoDB = [
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]
  }
  interface_endpoint_actions = {
    "ECR API" = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
    ]
    "ECR DKR" = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
    ]
    EKS        = ["eks:AccessKubernetesApi", "eks:DescribeCluster"]
    "EKS Auth" = ["eks-auth:AssumeRoleForPodIdentity"]
    STS        = ["sts:AssumeRole", "sts:GetCallerIdentity"]
    EC2 = [
      "ec2:AssignPrivateIpAddresses",
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:CreateTags",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DetachNetworkInterface",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:UnassignPrivateIpAddresses",
    ]
    "CloudWatch Logs"       = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
    "CloudWatch Monitoring" = ["cloudwatch:PutMetricData"]
    "X-Ray"                 = ["xray:PutTelemetryRecords", "xray:PutTraceSegments"]
    KMS                     = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
    "Secrets Manager"       = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    "Bedrock Runtime"       = ["bedrock:InvokeModel"]
  }
}

data "aws_iam_policy_document" "gateway_endpoint" {
  for_each = local.gateway_endpoint_services

  statement {
    sid       = "ExactSandboxAccount${replace(replace(each.key, " ", ""), "-", "")}"
    effect    = "Allow"
    actions   = local.gateway_endpoint_actions[each.key]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.aws_account_id]
    }
  }

  # ECR returns presigned S3 layer URLs.  Those requests are made by the ECR
  # service rather than a principal in this account, so they cannot satisfy
  # the account condition above.  This permits only read access to the
  # regional ECR layer bucket used by private EKS nodes.
  dynamic "statement" {
    for_each = each.key == "S3" ? [1] : []

    content {
      sid       = "AllowEcrLayerDownloads"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"]
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
    }
  }
}

data "aws_iam_policy_document" "interface_endpoint" {
  for_each = local.interface_endpoint_services

  statement {
    sid       = "ExactSandboxAccount${replace(replace(each.key, " ", ""), "-", "")}"
    effect    = "Allow"
    actions   = local.interface_endpoint_actions[each.key]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_vpc" "this" {
  #checkov:skip=CKV2_AWS_11:VPC flow-log destination resources and recurring ingestion cost are not approved for this bounded learning sandbox.
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "enterprise-ai-sandbox" })

  lifecycle {
    precondition {
      condition     = !var.allow_public_ingress && !var.allow_nat_gateway
      error_message = "Public ingress and NAT must remain disabled."
    }
    precondition {
      condition     = var.egress_mode == "private_endpoints_only"
      error_message = "Only private_endpoints_only egress is approved."
    }
    precondition {
      condition = var.vpc_endpoint_services == tolist([
        "S3",
        "DynamoDB",
        "ECR API",
        "ECR DKR",
        "EKS",
        "EKS Auth",
        "STS",
        "EC2",
        "CloudWatch Logs",
        "CloudWatch Monitoring",
        "X-Ray",
        "KMS",
        "Secrets Manager",
        "Bedrock Runtime",
      ])
      error_message = "Endpoint labels differ from the exact approved list."
    }
  }
}

resource "aws_default_security_group" "restricted" {
  vpc_id = aws_vpc.this.id

  ingress = []
  egress  = []
  tags    = merge(var.tags, { Name = "enterprise-ai-sandbox-default-restricted" })
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  tags = merge(var.tags, {
    Name = "enterprise-ai-sandbox-private-${count.index + 1}"
    Tier = "private"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "enterprise-ai-sandbox-private" })
}

resource "aws_route_table_association" "private" {
  count = 2

  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private[count.index].id
}

resource "aws_security_group" "endpoints" {
  name        = "enterprise-ai-sandbox-vpc-endpoints"
  description = "HTTPS from the exact private sandbox VPC only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "TLS from the exact sandbox VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress = []
  tags   = merge(var.tags, { Name = "enterprise-ai-sandbox-vpc-endpoints" })
}

resource "aws_vpc_endpoint" "gateway" {
  for_each = local.gateway_endpoint_services

  vpc_id            = aws_vpc.this.id
  service_name      = each.value
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = data.aws_iam_policy_document.gateway_endpoint[each.key].json
  tags              = merge(var.tags, { Name = "enterprise-ai-sandbox-${lower(each.key)}" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.this.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  policy              = data.aws_iam_policy_document.interface_endpoint[each.key].json
  tags = merge(var.tags, {
    Name = "enterprise-ai-sandbox-${replace(lower(each.key), " ", "-")}"
  })
}
