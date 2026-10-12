locals {
  bucket_arn = "arn:aws:s3:::${var.bucket_name}"
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_144:Cross-region replication conflicts with the approved single-region sandbox and no-fallback design.
  #checkov:skip=CKV_AWS_18:Access-log destination resources and their recurring cost are not approved for this bounded learning sandbox.
  bucket        = var.bucket_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "abort-incomplete-and-expire-noncurrent"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "expire-tmp"
    status = "Enabled"

    filter {
      prefix = "tmp/"
    }

    expiration {
      days = 30
    }
  }

  rule {
    id     = "expire-test"
    status = "Enabled"

    filter {
      prefix = "test/"
    }

    expiration {
      days = 30
    }
  }

  rule {
    id     = "expire-bedrock-model-invocation-logs"
    status = "Enabled"

    filter {
      prefix = "${var.bedrock_log_prefix}/"
    }

    expiration {
      days = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  dynamic "rule" {
    for_each = var.data_zone_retention_days
    content {
      id     = "expire-w7-${rule.key}"
      status = "Enabled"

      filter {
        prefix = var.data_zone_prefixes[rule.key]
      }

      expiration {
        days = rule.value
      }

      noncurrent_version_expiration {
        noncurrent_days = rule.value
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_notification" "eventbridge" {
  bucket      = aws_s3_bucket.this.id
  eventbridge = true

  depends_on = [aws_s3_bucket_public_access_block.this]
}

data "aws_iam_policy_document" "tls_only" {
  statement {
    sid    = "DenyNonTLSPlatformAccess"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AllowExactBedrockInvocationLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    resources = [
      "${local.bucket_arn}/${var.bedrock_log_prefix}/AWSLogs/${var.aws_account_id}/BedrockModelInvocationLogs/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.this]
}
