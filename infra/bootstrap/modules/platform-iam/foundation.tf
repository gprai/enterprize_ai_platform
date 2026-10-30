data "aws_iam_policy_document" "cluster_assume" {
  statement {
    sid     = "ExactEKSClusterServiceTrust"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    sid     = "ExactEKSNodeServiceTrust"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.eks_cluster_name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.eks_cluster_name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  ])
  role       = aws_iam_role.node.name
  policy_arn = each.value
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "bedrock_log_delivery" {
  name = "${var.eks_cluster_name}-bedrock-log-delivery"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ExactBedrockLogDeliveryTrust"
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "bedrock.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*" }
      }
    }]
  })
  tags = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "bedrock_log_delivery" {
  name = "write-exact-bedrock-invocation-log"
  role = aws_iam_role.bedrock_log_delivery.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WriteExactBedrockLogStream"
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/bedrock/${var.eks_cluster_name}/model-invocations:log-stream:aws/bedrock/modelinvocations"
    }]
  })
  lifecycle {
    prevent_destroy = true
  }
}
