output "cluster_name" {
  value = aws_eks_cluster.this.name
}
output "cluster_arn" {
  value = aws_eks_cluster.this.arn
}
output "cluster_endpoint" {
  value     = aws_eks_cluster.this.endpoint
  sensitive = true
}
output "cluster_certificate_authority" {
  value     = aws_eks_cluster.this.certificate_authority[0].data
  sensitive = true
}
output "node_group_name" {
  value = aws_eks_node_group.application.node_group_name
}
output "metrics_server_image" {
  value       = var.metrics_server_image
  description = "Owner-bound immutable Metrics Server artifact for the later Kubernetes deployment stage."
}
