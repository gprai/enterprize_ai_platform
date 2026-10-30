# Read-only bindings to persistent bootstrap IAM.
locals {
  inference_profile_arn = "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:inference-profile/${var.bedrock_inference_profile_id}"
}

data "aws_iam_role" "runtime" {
  name = "enterprise-ai-sandbox-runtime"
}

data "aws_iam_role" "ingestion" {
  name = "enterprise-ai-sandbox-ingestion"
}

data "aws_iam_role" "opensearch_administrator" {
  name = "enterprise-ai-sandbox-opensearch-admin"
}

data "aws_iam_role" "fis" {
  name = "enterprise-ai-sandbox-fis"
}

data "aws_iam_role" "github_oidc" {
  name = var.github_oidc_role_name
  lifecycle {
    postcondition {
      condition = var.github_allowed_ref == "refs/heads/main" && try(contains(flatten([
        jsondecode(self.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      ]), "repo:${var.github_organization}@${var.github_organization_id}/${var.github_repository}@${var.github_repository_id}:environment:${var.github_environment}"), false)
      error_message = "Bootstrap-owned GitHub role must retain the owner-approved immutable repository and protected environment trust."
    }
  }
}

data "aws_iam_role" "capstone_build" {
  name = "enterprise-ai-capstone-build"
}

data "aws_iam_role" "capstone_deploy_caller" {
  name = "enterprise-ai-capstone-deploy-caller"
}

data "aws_iam_role" "capstone_rollback_reader" {
  name = "enterprise-ai-capstone-rollback-reader"
}

data "aws_iam_role" "capstone_codebuild" {
  name = "enterprise-ai-capstone-codebuild"
}

data "aws_iam_role" "capstone_pki_bootstrap" {
  name = "enterprise-ai-capstone-pki-bootstrap"
}
