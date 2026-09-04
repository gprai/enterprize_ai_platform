output "vpc_id" {
  value = aws_vpc.this.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "gateway_endpoint_ids" {
  value = { for label, endpoint in aws_vpc_endpoint.gateway : label => endpoint.id }
}

output "interface_endpoint_ids" {
  value = { for label, endpoint in aws_vpc_endpoint.interface : label => endpoint.id }
}
