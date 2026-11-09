# These non-secret outputs bind the two HCP prerequisite stages to bootstrap IAM.
output "platform_iam_seed_bindings" {
  value = merge(module.network.iam_seed_bindings, { sandbox_kms_key_arn = module.kms.key_arn })
}

output "platform_iam_network_bindings" {
  value = merge(module.network.iam_seed_bindings, module.network.iam_network_bindings, { sandbox_kms_key_arn = module.kms.key_arn })
}
