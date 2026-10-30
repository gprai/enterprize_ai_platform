# Import is opt-in. First forget sandbox IAM with destroy=false; see IAM-MIGRATION.md.

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.runtime
  id       = "enterprise-ai-sandbox-runtime"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.ingestion
  id       = "enterprise-ai-sandbox-ingestion"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.opensearch_administrator
  id       = "enterprise-ai-sandbox-opensearch-admin"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.fis
  id       = "enterprise-ai-sandbox-fis"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.github_oidc
  id       = "enterprise-ai-platform-sandbox-github-oidc"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.capstone_build
  id       = "enterprise-ai-capstone-build"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.capstone_deploy_caller
  id       = "enterprise-ai-capstone-deploy-caller"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.capstone_rollback_reader
  id       = "enterprise-ai-capstone-rollback-reader"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.capstone_codebuild
  id       = "enterprise-ai-capstone-codebuild"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.capstone_pki_bootstrap
  id       = "enterprise-ai-capstone-pki-bootstrap"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.w12_image_publisher
  id       = "enterprise-ai-w12-prerequisite-image-publisher"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.w12_public_ecr_reader
  id       = "enterprise-ai-w12-public-ecr-reader"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.cluster
  id       = "enterprise-ai-sandbox-cluster"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.node
  id       = "enterprise-ai-sandbox-node"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role.bedrock_log_delivery
  id       = "enterprise-ai-sandbox-bedrock-log-delivery"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.bedrock_log_delivery
  id       = "enterprise-ai-sandbox-bedrock-log-delivery:write-exact-bedrock-invocation-log"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.fis
  id       = "enterprise-ai-sandbox-fis:bounded-eks-pod-delete-discovery"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.capstone_build
  id       = "enterprise-ai-capstone-build:enterprise-ai-capstone-build"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.github_eks_deployment
  id       = "enterprise-ai-platform-sandbox-github-oidc:enterprise-ai-sandbox-eks-deployment"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.capstone_deploy_caller
  id       = "enterprise-ai-capstone-deploy-caller:enterprise-ai-capstone-deploy-caller"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.capstone_rollback_reader
  id       = "enterprise-ai-capstone-rollback-reader:enterprise-ai-capstone-rollback-reader"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.capstone_codebuild
  id       = "enterprise-ai-capstone-codebuild:enterprise-ai-capstone-deploy-only"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.runtime
  id       = "enterprise-ai-sandbox-runtime:enterprise-ai-sandbox-runtime"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.ingestion
  id       = "enterprise-ai-sandbox-ingestion:enterprise-ai-sandbox-ingestion"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.w12_public_ecr_reader
  id       = "enterprise-ai-w12-public-ecr-reader:enterprise-ai-w12-public-ecr-reader"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.w12_image_publisher
  id       = "enterprise-ai-w12-prerequisite-image-publisher:enterprise-ai-w12-prerequisite-image-publisher"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy.w12_codebuild_executor_pull
  id       = "enterprise-ai-capstone-codebuild:enterprise-ai-w12-codebuild-executor-pull"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy_attachment.cluster
  id       = "enterprise-ai-sandbox-cluster/arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]
  id       = "enterprise-ai-sandbox-node/arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]
  id       = "enterprise-ai-sandbox-node/arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = module.platform_iam.aws_iam_role_policy_attachment.node["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"]
  id       = "enterprise-ai-sandbox-node/arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role.hcp["enterprise-ai-capstone-hcp-apply"]
  id       = "enterprise-ai-capstone-hcp-apply"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role.hcp["enterprise-ai-capstone-hcp-plan"]
  id       = "enterprise-ai-capstone-hcp-plan"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-bootstrap-kms-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-bootstrap-kms-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-bootstrap-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-bootstrap-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-capstone-codebuild-logs-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-capstone-codebuild-logs-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-capstone-codebuild-project-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-capstone-codebuild-project-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-sandbox-core-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-core-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-sandbox-iam-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-iam-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-w6-eks-iam-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-w6-eks-iam-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-apply-w6-observability-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-w6-observability-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-plan-read-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-plan-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_policy.hcp["enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"]
  id       = "arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-eks-nodegroup-sns-recovery-v1"]
  id       = "enterprise-ai-capstone-hcp-apply:enterprise-ai-capstone-hcp-apply-eks-nodegroup-sns-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-fis-template-recovery-v1"]
  id       = "enterprise-ai-capstone-hcp-apply:enterprise-ai-capstone-hcp-apply-fis-template-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-w6-read-recovery-v1"]
  id       = "enterprise-ai-capstone-hcp-apply:enterprise-ai-capstone-hcp-w6-read-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy.hcp["enterprise-ai-capstone-hcp-plan/enterprise-ai-capstone-hcp-w6-read-recovery-v1"]
  id       = "enterprise-ai-capstone-hcp-plan:enterprise-ai-capstone-hcp-w6-read-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-bootstrap-kms-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-bootstrap-kms-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-bootstrap-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-bootstrap-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-capstone-codebuild-logs-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-capstone-codebuild-logs-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-capstone-codebuild-project-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-capstone-codebuild-project-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-sandbox-core-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-core-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-sandbox-iam-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-iam-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-w6-eks-iam-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-w6-eks-iam-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-apply-w6-observability-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-apply-w6-observability-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-plan-read-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-plan-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-apply/enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"]
  id       = "enterprise-ai-capstone-hcp-apply/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-plan/enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"]
  id       = "enterprise-ai-capstone-hcp-plan/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-bootstrap-dynamodb-ttl-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-plan/enterprise-ai-capstone-hcp-plan-read-v1"]
  id       = "enterprise-ai-capstone-hcp-plan/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-plan-read-v1"
}

import {
  for_each = var.adopt_existing_platform_iam ? toset(["existing"]) : toset([])
  to       = aws_iam_role_policy_attachment.hcp["enterprise-ai-capstone-hcp-plan/enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"]
  id       = "enterprise-ai-capstone-hcp-plan/arn:aws:iam::526338061652:policy/enterprise-ai-capstone-hcp-read-capstone-codebuild-project-v1"
}
