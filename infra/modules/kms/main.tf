locals {
  account_root_arn   = "arn:aws:iam::${var.aws_account_id}:root"
  runtime_role_arn   = "arn:aws:iam::${var.aws_account_id}:role/${var.runtime_role_name}"
  ingestion_role_arn = "arn:aws:iam::${var.aws_account_id}:role/${var.ingestion_role_name}"
}

data "aws_iam_policy_document" "this" {
  #checkov:skip=CKV_AWS_109:KMS key-policy Resource star represents only the attached platform key; actions and principals are explicitly bounded.
  #checkov:skip=CKV_AWS_111:KMS key-policy Resource star represents only the attached platform key; write actions and principals are explicitly bounded.
  #checkov:skip=CKV_AWS_356:KMS key policies require Resource star to identify the attached key; no unrelated resource is authorized.
  statement {
    sid    = "EnableExactAccountKeyAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [local.account_root_arn]
    }
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:CreateGrant",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListGrants",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:RevokeGrant",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowExactWorkloadCryptography"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [local.account_root_arn]
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
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.runtime_role_arn, local.ingestion_role_arn]
    }
  }

  statement {
    sid    = "AllowExactOpenSearchLogEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.ap-southeast-1.amazonaws.com"]
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
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = var.opensearch_log_group_arns
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "Enterprise AI sandbox platform data encryption"
  deletion_window_in_days = var.deletion_window_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.this.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = var.alias_name
  target_key_id = aws_kms_key.this.key_id
}
