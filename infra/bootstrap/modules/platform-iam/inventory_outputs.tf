output "all_role_arns" {
  value = {
    "enterprise-ai-sandbox-runtime"                  = aws_iam_role.runtime.arn
    "enterprise-ai-sandbox-ingestion"                = aws_iam_role.ingestion.arn
    "enterprise-ai-sandbox-opensearch-admin"         = aws_iam_role.opensearch_administrator.arn
    "enterprise-ai-sandbox-fis"                      = aws_iam_role.fis.arn
    "enterprise-ai-platform-sandbox-github-oidc"     = aws_iam_role.github_oidc.arn
    "enterprise-ai-capstone-build"                   = aws_iam_role.capstone_build.arn
    "enterprise-ai-capstone-deploy-caller"           = aws_iam_role.capstone_deploy_caller.arn
    "enterprise-ai-capstone-rollback-reader"         = aws_iam_role.capstone_rollback_reader.arn
    "enterprise-ai-capstone-codebuild"               = aws_iam_role.capstone_codebuild.arn
    "enterprise-ai-capstone-pki-bootstrap"           = aws_iam_role.capstone_pki_bootstrap.arn
    "enterprise-ai-w12-prerequisite-image-publisher" = aws_iam_role.w12_image_publisher.arn
    "enterprise-ai-w12-public-ecr-reader"            = aws_iam_role.w12_public_ecr_reader.arn
    "enterprise-ai-sandbox-cluster"                  = aws_iam_role.cluster.arn
    "enterprise-ai-sandbox-node"                     = aws_iam_role.node.arn
    "enterprise-ai-sandbox-bedrock-log-delivery"     = aws_iam_role.bedrock_log_delivery.arn
  }
}
