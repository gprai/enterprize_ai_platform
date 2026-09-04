# Deliberately metadata-only: this module has no value-bearing input and creates
# no aws_secretsmanager_secret_version resource.
resource "aws_secretsmanager_secret" "metadata" {
  #checkov:skip=CKV2_AWS_57:This module is metadata-only with zero secret values, so no rotation Lambda or schedule can be attached.
  for_each = var.secret_names

  name                    = each.value
  description             = "Enterprise AI sandbox secret metadata"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 7
  tags                    = var.tags
}
