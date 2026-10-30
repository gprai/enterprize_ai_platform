# Read-only bindings to persistent bootstrap IAM.

data "aws_iam_role" "w12_image_publisher" {
  name = "enterprise-ai-w12-prerequisite-image-publisher"
}

data "aws_iam_role" "w12_public_ecr_reader" {
  name = "enterprise-ai-w12-public-ecr-reader"
}
