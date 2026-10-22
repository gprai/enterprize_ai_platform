terraform {
  cloud {
    organization = "Enterprise_AI_AWS_Arch"
    workspaces {
      name = "enterprise-ai-sandbox"
    }
  }

  required_version = "= 1.16.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.55.0"
    }
  }
}
