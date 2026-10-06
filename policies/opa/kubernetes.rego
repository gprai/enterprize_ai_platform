package enterprise_ai.kubernetes.w6_001

import rego.v1

sentinel := "enterprise-ai.invalid/w6-001:OWNER_BINDING_REQUIRED"
collector_sentinel := "enterprise-ai.invalid/w6-004-otel:OWNER_BINDING_REQUIRED"
namespace := "enterprise-ai-sandbox"
approved_repository := "enterprise-ai/sandbox/api"

deny contains "artifact context is invalid" if {
  not valid_context
}

valid_context if {
  input.artifact_type == "w6-001-source-template"
  input.deployable == false
}

valid_context if {
  input.artifact_type == "w6-001-release-package"
  input.deployable == true
}

deny contains "object namespace differs" if {
  some object in input.objects
  object.kind != "Namespace"
  object.metadata.namespace != namespace
}

deny contains "Namespace identity differs" if {
  some object in input.objects
  object.kind == "Namespace"
  object.metadata.name != namespace
}

deny contains "unexpected Kubernetes kind" if {
  some object in input.objects
  not object.kind in {"Namespace", "Deployment", "Service", "ServiceAccount", "ConfigMap", "NetworkPolicy", "HorizontalPodAutoscaler", "PodDisruptionBudget", "Role", "RoleBinding"}
}

deny contains "object inventory differs" if {
  count(input.objects) != 16
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "Deployment"]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "Service"]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "ServiceAccount"]) != 3
}

deny contains "FIS service account differs" if {
  count([object | some object in input.objects; object.kind == "ServiceAccount"; object.metadata.name == "fis-experiment"; object.automountServiceAccountToken == true]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "Role"]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "RoleBinding"]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "ConfigMap"]) != 2
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "NetworkPolicy"]) != 4
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "HorizontalPodAutoscaler"]) != 1
}

deny contains "object inventory differs" if {
  count([object | some object in input.objects; object.kind == "PodDisruptionBudget"]) != 1
}

deny contains "duplicate Kubernetes object identity" if {
  some i, j
  i < j
  left := input.objects[i]
  right := input.objects[j]
  [left.apiVersion, left.kind, left.metadata.name] == [right.apiVersion, right.kind, right.metadata.name]
}

deployment := object if {
  some object in input.objects
  object.kind == "Deployment"
}

container := deployment.spec.template.spec.containers[0]
collector := deployment.spec.template.spec.containers[1]

deny contains "container inventory differs" if {
  count(deployment.spec.template.spec.containers) != 2
}

deny contains "source template requires exact sentinel" if {
  input.artifact_type == "w6-001-source-template"
  container.image != sentinel
}

deny contains "source template requires exact collector sentinel" if {
  input.artifact_type == "w6-001-source-template"
  collector.image != collector_sentinel
}

deny contains "source sentinel is forbidden in a release package" if {
  input.artifact_type == "w6-001-release-package"
  container.image == sentinel
}

deny contains "collector sentinel is forbidden in a release package" if {
  input.artifact_type == "w6-001-release-package"
  collector.image == collector_sentinel
}

deny contains "release collector image is not the approved immutable ECR identity" if {
  input.artifact_type == "w6-001-release-package"
  not regex.match(sprintf(`^%s\.dkr\.ecr\.%s\.amazonaws\.com/enterprise-ai/sandbox/otel-collector@sha256:[0-9a-f]{64}$`, [input.binding.aws_account_id, input.binding.aws_region]), collector.image)
}

deny contains "release collector digest differs from evidence" if {
  input.artifact_type == "w6-001-release-package"
  not endswith(collector.image, sprintf("@%s", [input.binding.collector.digest]))
}

deny contains "release image is not the approved immutable ECR identity" if {
  input.artifact_type == "w6-001-release-package"
  not regex.match(sprintf(`^%s\.dkr\.ecr\.%s\.amazonaws\.com/%s@sha256:[0-9a-f]{64}$`, [input.binding.aws_account_id, input.binding.aws_region, approved_repository]), container.image)
}

deny contains "release image digest differs from evidence" if {
  input.artifact_type == "w6-001-release-package"
  not endswith(container.image, sprintf("@%s", [input.binding.digest]))
}

deny contains "release evidence is incomplete" if {
  input.artifact_type == "w6-001-release-package"
  not complete_release_evidence
}

complete_release_evidence if {
  input.binding.aws_account_id != ""
  input.binding.aws_region != ""
  input.binding.digest != "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  input.binding.digest == input.binding.oci_identity.image_digest
  input.binding.digest == input.binding.trivy.image_digest
  input.binding.digest == input.binding.grype.image_digest
  input.binding.digest == input.binding.provenance.image_digest
  input.binding.digest == input.binding.image_composition_identity.image_digest
  input.binding.trivy.result == "PASS"
  input.binding.grype.result == "PASS"
  regex.match(`^[0-9a-f]{64}$`, input.binding.oci_identity.sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.trivy.report_sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.grype.report_sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.spdx_sbom_sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.cyclonedx_sbom_sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.provenance.sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.image_composition_identity.sha256)
  input.binding.w6_01_operation_identity != ""
  input.binding.owner_approval_identity != ""
  regex.match(`^[0-9a-f]{64}$`, input.binding.source_identity.template_sha256)
  regex.match(`^[0-9a-f]{40}$`, input.binding.source_identity.source_commit)
  time.parse_rfc3339_ns(input.binding.expires_at) > time.parse_rfc3339_ns(input.review_time)
  input.binding.output_private == true
  input.binding.operation_consumed == false
  input.binding.collector.digest == input.binding.collector.oci_identity.image_digest
  input.binding.collector.digest == input.binding.collector.trivy.image_digest
  input.binding.collector.digest == input.binding.collector.grype.image_digest
  input.binding.collector.digest == input.binding.collector.provenance.image_digest
  input.binding.collector.digest == input.binding.collector.image_composition_identity.image_digest
  input.binding.collector.trivy.result == "PASS"
  input.binding.collector.grype.result == "PASS"
  regex.match(`^[0-9a-f]{64}$`, input.binding.collector.spdx_sbom_sha256)
  regex.match(`^[0-9a-f]{64}$`, input.binding.collector.cyclonedx_sbom_sha256)
}

deny contains "default service account is prohibited" if {
  deployment.spec.template.spec.serviceAccountName != "enterprise-ai-runtime"
}

deny contains "pod security context differs" if {
  security := deployment.spec.template.spec.securityContext
  security.runAsNonRoot != true
}

deny contains "pod must run as UID and GID 65532" if {
  security := deployment.spec.template.spec.securityContext
  security.runAsUser != 65532
}

deny contains "pod must run as UID and GID 65532" if {
  security := deployment.spec.template.spec.securityContext
  security.runAsGroup != 65532
}

deny contains "RuntimeDefault seccomp is required" if {
  deployment.spec.template.spec.securityContext.seccompProfile.type != "RuntimeDefault"
}

deny contains "container privilege escalation is prohibited" if {
  container.securityContext.allowPrivilegeEscalation != false
}

deny contains "container root filesystem must be read-only" if {
  container.securityContext.readOnlyRootFilesystem != true
}

deny contains "all Linux capabilities must be dropped" if {
  container.securityContext.capabilities.drop != ["ALL"]
}

deny contains "image pull policy must be Always" if {
  container.imagePullPolicy != "Always"
}

deny contains "collector image pull policy must be Always" if {
  collector.imagePullPolicy != "Always"
}

deny contains "collector privilege boundary differs" if {
  collector.securityContext.allowPrivilegeEscalation != false
}

deny contains "collector privilege boundary differs" if {
  collector.securityContext.readOnlyRootFilesystem != true
}

deny contains "collector privilege boundary differs" if {
  collector.securityContext.capabilities.drop != ["ALL"]
}

deny contains "host namespace is prohibited" if {
  object.get(deployment.spec.template.spec, "hostNetwork", false)
}

deny contains "host namespace is prohibited" if {
  object.get(deployment.spec.template.spec, "hostPID", false)
}

deny contains "host namespace is prohibited" if {
  object.get(deployment.spec.template.spec, "hostIPC", false)
}

deny contains "hostPath is prohibited" if {
  some volume in object.get(deployment.spec.template.spec, "volumes", [])
  object.get(volume, "hostPath", null) != null
}

deny contains "resource contract differs" if {
  container.resources.requests.cpu != "500m"
}

deny contains "resource contract differs" if {
  container.resources.limits.cpu != "1000m"
}

deny contains "required health probe is missing" if {
  container.startupProbe.httpGet.path != "/health"
}

deny contains "required health probe is missing" if {
  container.livenessProbe.httpGet.path != "/health/live"
}

deny contains "required health probe is missing" if {
  container.readinessProbe.httpGet.path != "/health/ready"
}

deny contains "rollout bounds differ" if {
  deployment.spec.strategy.rollingUpdate.maxUnavailable != 0
}

deny contains "rollout bounds differ" if {
  deployment.spec.strategy.rollingUpdate.maxSurge != 1
}

deny contains "public Service exposure is prohibited" if {
  some object in input.objects
  object.kind == "Service"
  object.spec.type != "ClusterIP"
}

deny contains "Service selector or port differs" if {
  some object in input.objects
  object.kind == "Service"
  object.spec.selector != {"app.kubernetes.io/name": "enterprise-ai-api"}
}

deny contains "Service selector or port differs" if {
  some object in input.objects
  object.kind == "Service"
  object.spec.ports != [{"name": "http", "protocol": "TCP", "port": 8000, "targetPort": "http"}]
}

deny contains "HPA bounds differ" if {
  some object in input.objects
  object.kind == "HorizontalPodAutoscaler"
  object.spec.minReplicas != 2
}

deny contains "HPA bounds differ" if {
  some object in input.objects
  object.kind == "HorizontalPodAutoscaler"
  object.spec.maxReplicas != 4
}

deny contains "PDB is incompatible" if {
  some object in input.objects
  object.kind == "PodDisruptionBudget"
  object.spec.minAvailable != 1
}

deny contains "default deny is missing" if {
  count([object | some object in input.objects; object.kind == "NetworkPolicy"; object.metadata.name == "enterprise-ai-default-deny"; object.spec.podSelector == {}; object.spec.policyTypes == ["Ingress", "Egress"]]) != 1
}

deny contains "unapproved ingress is present" if {
  some resource in input.objects
  resource.kind == "NetworkPolicy"
  not resource.metadata.name in {"enterprise-ai-default-deny", "enterprise-ai-api-ingress"}
  object.get(resource.spec, "ingress", []) != []
}

deny contains "private AWS egress boundary differs" if {
  some resource in input.objects
  resource.kind == "NetworkPolicy"
  resource.metadata.name == "enterprise-ai-private-aws-egress"
  resource.spec.egress != [{"to": [{"ipBlock": {"cidr": "10.60.0.0/16"}}], "ports": [{"protocol": "TCP", "port": 443}]}]
}

deny contains "FIS role differs" if {
  role := [object | some object in input.objects; object.kind == "Role"][0]
  role.metadata.name != "fis-pod-delete"
}

deny contains "FIS role differs" if {
  role := [object | some object in input.objects; object.kind == "Role"][0]
  role.rules != [
    {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "create", "patch", "delete"]},
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["create", "list", "get", "delete", "deletecollection"]},
  ]
}

deny contains "FIS role binding differs" if {
  binding := [object | some object in input.objects; object.kind == "RoleBinding"][0]
  binding.metadata.name != "fis-pod-delete"
}

deny contains "FIS role binding differs" if {
  binding := [object | some object in input.objects; object.kind == "RoleBinding"][0]
  binding.roleRef != {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fis-pod-delete"}
}

deny contains "FIS role binding differs" if {
  binding := [object | some object in input.objects; object.kind == "RoleBinding"][0]
  binding.subjects != [
    {"kind": "ServiceAccount", "name": "fis-experiment", "namespace": namespace},
    {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "fis-experiment"},
  ]
}

deny contains "plaintext Secret is prohibited" if {
  some object in input.objects
  object.kind == "Secret"
}

deny contains "unrestricted network destination is prohibited" if {
  some object in input.objects
  object.kind == "NetworkPolicy"
  contains(json.marshal(object), "0.0.0.0/0")
}
