# IAM persists independently of sandbox workloads. This alias avoids changing
# captured HCP tags through the state-store provider's default_tags.
provider "aws" {
  alias               = "platform_iam"
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
}

locals {
  platform_iam_hcp = jsondecode(file("${path.module}/platform-iam-config/hcp-resources.json"))
  platform_iam_bindings = merge(
    jsondecode(file("${path.module}/platform-iam-config/bindings.captured.json")),
    var.platform_iam_binding_overrides,
    { bootstrap_kms_key_arn = aws_kms_key.terraform_state.arn }
  )
  platform_iam_tags = merge(var.platform_iam_tags, { ExpiresAt = local.platform_iam_bindings.workload_expires_at })
}

# Shared OIDC providers stay under their existing ownership; this migration
# does not adopt the pre-existing provider tagged for another project.
data "aws_iam_openid_connect_provider" "hcp" {
  provider = aws.platform_iam
  url      = "https://app.terraform.io"
}
data "aws_iam_openid_connect_provider" "github" {
  provider = aws.platform_iam
  url      = "https://token.actions.githubusercontent.com"
}

module "platform_iam" {
  source                         = "./modules/platform-iam"
  providers                      = { aws = aws.platform_iam }
  aws_account_id                 = var.aws_account_id
  aws_region                     = var.aws_region
  platform_bucket_name           = "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
  data_zone_prefixes             = { raw = "raw/", quarantine = "quarantine/", processed = "processed/", evidence = "evidence/" }
  kms_key_arn                    = local.platform_iam_bindings.sandbox_kms_key_arn
  opensearch_domain_name         = "enterprise-ai-sandbox"
  bedrock_inference_profile_id   = local.platform_iam_bindings.bedrock_model_id
  expires_at                     = local.platform_iam_bindings.workload_expires_at
  github_organization            = "gprai"
  github_organization_id         = "82297871"
  github_repository              = "enterprize_ai_platform"
  github_repository_id           = "1340913005"
  github_environment             = "sandbox"
  github_oidc_role_name          = "enterprise-ai-platform-sandbox-github-oidc"
  github_allowed_ref             = "refs/heads/main"
  external_administrator_arn     = local.platform_iam_bindings.administrator_role_arn
  administrator_trust_expires_at = local.platform_iam_bindings.administrator_trust_expires_at
  eks_namespace                  = "enterprise-ai-sandbox"
  runtime_service_account        = "enterprise-ai-runtime"
  ingestion_service_account      = "enterprise-ai-ingestion"
  eks_cluster_name               = "enterprise-ai-sandbox"
  tags                           = local.platform_iam_tags
  depends_on                     = [data.aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role" "hcp" {
  provider             = aws.platform_iam
  for_each             = local.platform_iam_hcp.roles
  name                 = each.key
  path                 = each.value.path
  description          = each.value.description
  max_session_duration = each.value.max_session_duration
  permissions_boundary = each.value.permissions_boundary
  assume_role_policy   = templatefile("${path.module}/platform-iam-config/${each.key}.trust.json.tftpl", local.platform_iam_bindings)
  tags                 = each.value.tags
  depends_on           = [data.aws_iam_openid_connect_provider.hcp]
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_policy" "hcp" {
  provider    = aws.platform_iam
  for_each    = local.platform_iam_hcp.policies
  name        = each.key
  path        = each.value.path
  description = each.value.description
  policy      = templatefile("${path.module}/platform-iam-config/${each.key}.json.tftpl", local.platform_iam_bindings)
  tags        = each.value.tags
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy" "hcp" {
  provider = aws.platform_iam
  for_each = local.platform_iam_hcp.inline_policies
  name     = each.value.name
  role     = aws_iam_role.hcp[each.value.role].name
  policy   = templatefile("${path.module}/platform-iam-config/${each.value.file}", local.platform_iam_bindings)
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy_attachment" "hcp" {
  provider   = aws.platform_iam
  for_each   = local.platform_iam_hcp.attachments
  role       = aws_iam_role.hcp[each.value.role].name
  policy_arn = aws_iam_policy.hcp[each.value.policy].arn
  lifecycle { prevent_destroy = true }
}

output "platform_iam_role_arns" {
  description = "Bootstrap-owned persistent role identities. Workload state must not own these roles."
  value = merge(
    module.platform_iam.all_role_arns,
    { for name, role in aws_iam_role.hcp : name => role.arn }
  )
  depends_on = [module.platform_iam]
}
