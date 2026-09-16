provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.mandatory_tags
  }
}

locals {
  state_bucket_arn = "arn:aws:s3:::${var.state_bucket_name}"
}

resource "terraform_data" "owner_expiry_gate" {
  input = var.mandatory_tags["ExpiresAt"]

  lifecycle {
    precondition {
      condition = (
        var.mandatory_tags["ExpiresAt"] != "TODO_OWNER" &&
        try(timecmp(var.mandatory_tags["ExpiresAt"], plantimestamp()) > 0, false) &&
        try(
          timecmp(
            var.mandatory_tags["ExpiresAt"],
            timeadd(plantimestamp(), "24h")
          ) <= 0,
          false
        )
      )
      error_message = "Owner must replace TODO_OWNER with a future UTC ExpiresAt no more than 24 hours after creation."
    }
  }
}

data "aws_iam_policy_document" "terraform_state_key" {
  #checkov:skip=CKV_AWS_109:KMS key-policy Resource star represents only the attached state key; actions and principals are explicitly bounded.
  #checkov:skip=CKV_AWS_111:KMS key-policy Resource star represents only the attached state key; write actions and principals are explicitly bounded.
  #checkov:skip=CKV_AWS_356:KMS key policies require Resource star to identify the attached key; no unrelated resource is authorized.
  statement {
    sid    = "EnableExactAccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowExactAccountStateCryptography"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowExactAccountDynamoDBStateGrant"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions   = ["kms:CreateGrant"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["dynamodb.*.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "terraform_state" {
  description             = "W5 sandbox Terraform state encryption"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.terraform_state_key.json
  tags                    = var.mandatory_tags

  depends_on = [terraform_data.owner_expiry_gate]
}

resource "aws_kms_alias" "terraform_state" {
  name          = var.state_kms_alias
  target_key_id = aws_kms_key.terraform_state.key_id
}

resource "aws_s3_bucket" "terraform_state" {
  #checkov:skip=CKV2_AWS_62:No event-notification destination is approved for the bounded learning-sandbox state bucket.
  #checkov:skip=CKV_AWS_144:Cross-region replication conflicts with the approved single-region sandbox and no-fallback design.
  #checkov:skip=CKV_AWS_18:Access-log destination resources and their recurring cost are not approved for this bounded learning sandbox.
  bucket        = var.state_bucket_name
  force_destroy = false
  tags          = var.mandatory_tags

  depends_on = [terraform_data.owner_expiry_gate]
}

resource "aws_s3_bucket_ownership_controls" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.terraform_state]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_state.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "terraform_state_tls" {
  statement {
    sid    = "DenyNonTLSStateAccess"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [
      local.state_bucket_arn,
      "${local.state_bucket_arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "terraform_state_tls" {
  bucket = aws_s3_bucket.terraform_state.id
  policy = data.aws_iam_policy_document.terraform_state_tls.json

  depends_on = [aws_s3_bucket_public_access_block.terraform_state]
}

resource "aws_dynamodb_table" "terraform_lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  tags       = var.mandatory_tags
  depends_on = [terraform_data.owner_expiry_gate]
}
