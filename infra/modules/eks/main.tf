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
  name               = "${var.cluster_name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "node" {
  name               = "${var.cluster_name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  ])
  role       = aws_iam_role.node.name
  policy_arn = each.value
}

resource "aws_eks_cluster" "this" {
  #checkov:skip=CKV_AWS_39:The owner-approved W6-004 boundary permits only the owner's temporary exact /32 during the bounded deployment window; workloads remain private.
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"]
  }
  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.public_access_cidrs
  }
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  tags                      = var.tags
  depends_on                = [aws_iam_role_policy_attachment.cluster]
}

resource "aws_eks_access_entry" "administrator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.administrator_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "administrator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.administrator_role_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.administrator]
}

resource "aws_eks_access_entry" "deployment" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.deployment_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "deployment" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.deployment_role_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
  access_scope {
    type       = "namespace"
    namespaces = [var.namespace]
  }
  depends_on = [aws_eks_access_entry.deployment]
}

resource "aws_eks_access_entry" "resilience" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.resilience_role_arn
  type          = "STANDARD"
  user_name     = "fis-experiment"
}

resource "aws_eks_access_policy_association" "resilience" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.resilience_role_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
  access_scope {
    type       = "namespace"
    namespaces = [var.namespace]
  }
  depends_on = [aws_eks_access_entry.resilience]
}

resource "aws_eks_node_group" "application" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "application"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.node_instance_types
  capacity_type   = "ON_DEMAND"
  scaling_config {
    min_size     = var.node_minimum
    desired_size = var.node_desired
    max_size     = var.node_maximum
  }
  update_config {
    max_unavailable = 1
  }
  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_addon" "this" {
  for_each                    = var.addon_versions
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = each.value
  resolve_conflicts_on_create = "NONE"
  resolve_conflicts_on_update = "PRESERVE"
  tags                        = var.tags
}

resource "aws_eks_pod_identity_association" "runtime" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.runtime_service_account
  role_arn        = var.runtime_role_arn
}

resource "aws_eks_pod_identity_association" "ingestion" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.ingestion_service_account
  role_arn        = var.ingestion_role_arn
}
