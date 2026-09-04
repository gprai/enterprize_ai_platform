variable "aws_region" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "private_subnet_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.private_subnet_cidrs) == 2
    error_message = "Exactly two private subnet CIDRs are required."
  }
}

variable "availability_zones" {
  type = list(string)
  validation {
    condition = var.availability_zones == tolist([
      "ap-southeast-1a",
      "ap-southeast-1b",
    ])
    error_message = "Availability zones must remain the exact approved root-local values."
  }
}

variable "vpc_endpoint_services" {
  type = list(string)
}

variable "allow_public_ingress" {
  type = bool
}

variable "allow_nat_gateway" {
  type = bool
}

variable "egress_mode" {
  type = string
}

variable "tags" {
  type = map(string)
}
