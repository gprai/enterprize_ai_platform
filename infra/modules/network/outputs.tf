output "vpc_id" {
  value = aws_vpc.this.id
}

output "iam_seed_bindings" {
  value = {
    sandbox_vpc_arn                    = aws_vpc.this.arn
    sandbox_default_security_group_arn = "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:security-group/${aws_vpc.this.default_security_group_id}"
  }
}

output "iam_network_bindings" {
  value = {
    sandbox_route_table_arn             = aws_route_table.private.arn
    sandbox_endpoint_security_group_arn = aws_security_group.endpoints.arn
    sandbox_subnet_a_arn                = aws_subnet.private[0].arn
    sandbox_subnet_b_arn                = aws_subnet.private[1].arn
  }
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "capstone_codebuild_security_group_id" {
  value       = aws_security_group.capstone_codebuild.id
  description = "Egress-only TLS group for the private capstone executor."
}

output "gateway_endpoint_ids" {
  value = { for label, endpoint in aws_vpc_endpoint.gateway : label => endpoint.id }
}

output "interface_endpoint_ids" {
  value = { for label, endpoint in aws_vpc_endpoint.interface : label => endpoint.id }
}
