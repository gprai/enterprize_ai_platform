locals {
  w12_toolchain_repository = "enterprise-ai/sandbox/w12-toolchain"
  w12_codebuild_repository = "enterprise-ai/sandbox/w12-codebuild"
}

module "w12_toolchain_ecr" {
  source = "../../modules/ecr"

  repository_name      = local.w12_toolchain_repository
  retained_image_count = 10
  kms_key_arn          = module.kms.key_arn
  tags                 = var.mandatory_tags
  depends_on           = [terraform_data.owner_expiry_gate]
}

module "w12_codebuild_ecr" {
  source = "../../modules/ecr"

  repository_name      = local.w12_codebuild_repository
  retained_image_count = 10
  kms_key_arn          = module.kms.key_arn
  tags                 = var.mandatory_tags
  depends_on           = [terraform_data.owner_expiry_gate]
}
