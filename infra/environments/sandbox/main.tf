provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.mandatory_tags
  }
}

locals {
  availability_zones = ["ap-southeast-1a", "ap-southeast-1b"]
  platform_bucket    = "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
  opensearch_domain  = "enterprise-ai-sandbox"
  ecr_repository     = "enterprise-ai/sandbox/api"
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

module "network" {
  source = "../../modules/network"

  aws_region            = var.aws_region
  vpc_cidr              = var.vpc_cidr
  private_subnet_cidrs  = var.private_subnet_cidrs
  availability_zones    = local.availability_zones
  vpc_endpoint_services = var.vpc_endpoint_services
  allow_public_ingress  = var.allow_public_ingress
  allow_nat_gateway     = var.allow_nat_gateway
  egress_mode           = var.egress_mode
  tags                  = var.mandatory_tags
  depends_on            = [terraform_data.owner_expiry_gate]
}

module "kms" {
  source = "../../modules/kms"

  aws_account_id       = var.aws_account_id
  alias_name           = "alias/enterprise-ai-platform-sandbox"
  deletion_window_days = var.kms_deletion_window_days
  runtime_role_name    = "enterprise-ai-sandbox-runtime"
  ingestion_role_name  = "enterprise-ai-sandbox-ingestion"
  opensearch_log_group_arns = [
    "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/OpenSearchService/domains/${local.opensearch_domain}/application-logs",
    "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/OpenSearchService/domains/${local.opensearch_domain}/audit-logs",
    "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/OpenSearchService/domains/${local.opensearch_domain}/index-slow-logs",
    "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/OpenSearchService/domains/${local.opensearch_domain}/search-slow-logs",
  ]
  tags = var.mandatory_tags
}

module "storage" {
  source = "../../modules/storage"

  bucket_name = local.platform_bucket
  kms_key_arn = module.kms.key_arn
  tags        = var.mandatory_tags
}

module "secrets" {
  source = "../../modules/secrets"

  secret_names = []
  kms_key_arn  = module.kms.key_arn
  tags         = var.mandatory_tags
  depends_on   = [terraform_data.owner_expiry_gate]
}

module "iam" {
  source = "../../modules/iam"

  aws_account_id                 = var.aws_account_id
  aws_region                     = var.aws_region
  platform_bucket_name           = local.platform_bucket
  kms_key_arn                    = module.kms.key_arn
  opensearch_domain_name         = local.opensearch_domain
  bedrock_inference_profile_id   = var.bedrock_model_id
  expires_at                     = var.mandatory_tags["ExpiresAt"]
  github_organization            = var.github_organization
  github_repository              = var.github_repository
  github_environment             = var.github_environment
  github_oidc_role_name          = var.github_oidc_role_name
  github_allowed_ref             = var.github_allowed_ref
  external_administrator_arn     = "arn:aws:iam::526338061652:user/finopsinfra"
  administrator_trust_expires_at = "2026-09-30T15:59:59Z"
  eks_namespace                  = "enterprise-ai-sandbox"
  runtime_service_account        = "enterprise-ai-runtime"
  ingestion_service_account      = "enterprise-ai-ingestion"
  tags                           = var.mandatory_tags
}

module "opensearch" {
  source = "../../modules/opensearch"

  aws_account_id         = var.aws_account_id
  aws_region             = var.aws_region
  domain_name            = local.opensearch_domain
  engine_version         = "OpenSearch_2.19"
  instance_type          = "t3.small.search"
  instance_count         = 1
  ebs_volume_type        = "gp3"
  ebs_volume_size        = 10
  log_retention_days     = 30
  subnet_id              = module.network.private_subnet_ids[0]
  security_group_id      = module.network.endpoint_security_group_id
  kms_key_arn            = module.kms.key_arn
  runtime_role_arn       = module.iam.runtime_role_arn
  ingestion_role_arn     = module.iam.ingestion_role_arn
  administrator_role_arn = module.iam.opensearch_administrator_role_arn
  tags                   = var.mandatory_tags
}

module "ecr" {
  source = "../../modules/ecr"

  repository_name      = local.ecr_repository
  retained_image_count = 10
  kms_key_arn          = module.kms.key_arn
  tags                 = var.mandatory_tags
  depends_on           = [terraform_data.owner_expiry_gate]
}
