package enterprise_ai.kubernetes.w6_001_test

import rego.v1
import data.enterprise_ai.kubernetes.w6_001

template_input := {
  "artifact_type": "w6-001-source-template",
  "deployable": false,
  "objects": [{
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "enterprise-ai-api", "namespace": "enterprise-ai-sandbox"},
    "spec": {
      "strategy": {"rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
      "template": {"spec": {
        "serviceAccountName": "enterprise-ai-runtime",
        "securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
          "image": "enterprise-ai.invalid/w6-001:OWNER_BINDING_REQUIRED",
          "imagePullPolicy": "Always",
          "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
          "resources": {"requests": {"cpu": "500m"}, "limits": {"cpu": "1000m"}},
          "startupProbe": {"httpGet": {"path": "/health"}},
          "livenessProbe": {"httpGet": {"path": "/health/live"}},
          "readinessProbe": {"httpGet": {"path": "/health/ready"}}
        }, {
          "image": "enterprise-ai.invalid/w6-004-otel:OWNER_BINDING_REQUIRED",
          "imagePullPolicy": "Always",
          "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}
        }]
      }}
    }
  }, {
    "apiVersion": "v1",
    "kind": "Namespace",
    "metadata": {"name": "enterprise-ai-sandbox"}
  }, {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {"name": "enterprise-ai-api", "namespace": "enterprise-ai-sandbox"},
    "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": "enterprise-ai-api"}, "ports": [{"name": "http", "protocol": "TCP", "port": 8000, "targetPort": "http"}]}
  }, {
    "apiVersion": "v1",
    "kind": "ServiceAccount",
    "metadata": {"name": "enterprise-ai-runtime", "namespace": "enterprise-ai-sandbox"}
  }, {
    "apiVersion": "v1",
    "kind": "ServiceAccount",
    "metadata": {"name": "enterprise-ai-ingestion", "namespace": "enterprise-ai-sandbox"}
  }, {
    "apiVersion": "v1",
    "kind": "ServiceAccount",
    "metadata": {"name": "fis-experiment", "namespace": "enterprise-ai-sandbox"},
    "automountServiceAccountToken": true
  }, {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "Role",
    "metadata": {"name": "fis-pod-delete", "namespace": "enterprise-ai-sandbox"},
    "rules": [
      {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "create", "patch", "delete"]},
      {"apiGroups": [""], "resources": ["pods"], "verbs": ["create", "list", "get", "delete", "deletecollection"]}
    ]
  }, {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "RoleBinding",
    "metadata": {"name": "fis-pod-delete", "namespace": "enterprise-ai-sandbox"},
    "subjects": [
      {"kind": "ServiceAccount", "name": "fis-experiment", "namespace": "enterprise-ai-sandbox"},
      {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "fis-experiment"}
    ],
    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fis-pod-delete"}
  }, {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "enterprise-ai-runtime", "namespace": "enterprise-ai-sandbox"}
  }, {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "enterprise-ai-otel-collector", "namespace": "enterprise-ai-sandbox"}
  }, {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "enterprise-ai-api-ingress", "namespace": "enterprise-ai-sandbox"},
    "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "enterprise-ai-api"}}, "policyTypes": ["Ingress"], "ingress": []}
  }, {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "enterprise-ai-private-aws-egress", "namespace": "enterprise-ai-sandbox"},
    "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "enterprise-ai-api"}}, "policyTypes": ["Egress"], "egress": [{"to": [{"ipBlock": {"cidr": "10.60.0.0/16"}}], "ports": [{"protocol": "TCP", "port": 443}]}]}
  }, {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "enterprise-ai-default-deny", "namespace": "enterprise-ai-sandbox"},
    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
  }, {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "enterprise-ai-dns-egress", "namespace": "enterprise-ai-sandbox"},
    "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "enterprise-ai-api"}}, "policyTypes": ["Egress"], "egress": []}
  }, {
    "apiVersion": "autoscaling/v2",
    "kind": "HorizontalPodAutoscaler",
    "metadata": {"name": "enterprise-ai-api", "namespace": "enterprise-ai-sandbox"},
    "spec": {"minReplicas": 2, "maxReplicas": 4}
  }, {
    "apiVersion": "policy/v1",
    "kind": "PodDisruptionBudget",
    "metadata": {"name": "enterprise-ai-api", "namespace": "enterprise-ai-sandbox"},
    "spec": {"minAvailable": 1}
  }]
}

release_digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
collector_digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

release_binding := {
  "aws_account_id": "526338061652",
  "aws_region": "ap-southeast-1",
  "digest": release_digest,
  "oci_identity": {"image_digest": release_digest, "sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
  "trivy": {"image_digest": release_digest, "report_sha256": "2222222222222222222222222222222222222222222222222222222222222222", "result": "PASS"},
  "grype": {"image_digest": release_digest, "report_sha256": "3333333333333333333333333333333333333333333333333333333333333333", "result": "PASS"},
  "spdx_sbom_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cyclonedx_sbom_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "provenance": {"image_digest": release_digest, "sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
  "image_composition_identity": {"image_digest": release_digest, "sha256": "5555555555555555555555555555555555555555555555555555555555555555"},
  "w6_01_operation_identity": "w6-01-operation-0001",
  "owner_approval_identity": "owner-approval-0001",
  "source_identity": {
    "template_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "source_commit": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  },
  "expires_at": "2027-01-01T00:00:00Z",
  "output_private": true,
  "operation_consumed": false,
  "collector": {
    "digest": collector_digest,
    "oci_identity": {"image_digest": collector_digest, "sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
    "trivy": {"image_digest": collector_digest, "report_sha256": "2222222222222222222222222222222222222222222222222222222222222222", "result": "PASS"},
    "grype": {"image_digest": collector_digest, "report_sha256": "3333333333333333333333333333333333333333333333333333333333333333", "result": "PASS"},
    "spdx_sbom_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
    "cyclonedx_sbom_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
    "provenance": {"image_digest": collector_digest, "sha256": "6666666666666666666666666666666666666666666666666666666666666666"},
    "image_composition_identity": {"image_digest": collector_digest, "sha256": "7777777777777777777777777777777777777777777777777777777777777777"}
  }
}

release_input := object.union(template_input, {
  "artifact_type": "w6-001-release-package",
  "deployable": true,
  "review_time": "2026-10-01T00:00:00Z",
  "binding": release_binding,
  "objects": json.patch(template_input.objects, [
    {
      "op": "replace",
      "path": "/0/spec/template/spec/containers/0/image",
      "value": sprintf("526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api@%s", [release_digest])
    },
    {
      "op": "replace",
      "path": "/0/spec/template/spec/containers/1/image",
      "value": sprintf("526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/otel-collector@%s", [collector_digest])
    }
  ])
})

test_template_context_accepts_exact_sentinel if {
  count(w6_001.deny) == 0 with input as template_input
}

test_release_context_accepts_complete_immutable_binding if {
  count(w6_001.deny) == 0 with input as release_input
}

test_release_context_rejects_digest_mismatch if {
  mismatched := json.patch(release_input, [{"op": "replace", "path": "/binding/digest", "value": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}])
  "release image digest differs from evidence" in w6_001.deny with input as mismatched
}

test_release_context_rejects_expired_approval if {
  expired := json.patch(release_input, [{"op": "replace", "path": "/binding/expires_at", "value": "2026-01-01T00:00:00Z"}])
  "release evidence is incomplete" in w6_001.deny with input as expired
}

test_release_context_rejects_sentinel if {
  value := object.union(template_input, {"artifact_type": "w6-001-release-package", "deployable": true})
  "source sentinel is forbidden in a release package" in w6_001.deny with input as value
}

test_case_changed_sentinel_is_rejected if {
  value := json.patch(template_input, [{"op": "replace", "path": "/objects/0/spec/template/spec/containers/0/image", "value": "enterprise-ai.invalid/w6-001:owner_binding_required"}])
  "source template requires exact sentinel" in w6_001.deny with input as value
}

test_non_always_pull_policy_is_rejected if {
  value := json.patch(template_input, [{"op": "replace", "path": "/objects/0/spec/template/spec/containers/0/imagePullPolicy", "value": "IfNotPresent"}])
  "image pull policy must be Always" in w6_001.deny with input as value
}

test_public_service_is_rejected if {
  service := {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "enterprise-ai-api", "namespace": "enterprise-ai-sandbox"}, "spec": {"type": "LoadBalancer"}}
  value := object.union(template_input, {"objects": array.concat(template_input.objects, [service])})
  "public Service exposure is prohibited" in w6_001.deny with input as value
}

test_reordered_equivalent_input_has_same_result if {
  reversed := object.union(template_input, {"objects": array.reverse(template_input.objects)})
  original_result := w6_001.deny with input as template_input
  reordered_result := w6_001.deny with input as reversed
  original_result == reordered_result
}

test_duplicate_object_identity_is_rejected if {
  duplicate := object.union(template_input, {"objects": array.concat(template_input.objects, template_input.objects)})
  "duplicate Kubernetes object identity" in w6_001.deny with input as duplicate
}
