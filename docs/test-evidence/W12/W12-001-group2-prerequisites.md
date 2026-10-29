# W12-001 Group 2 prerequisite preparation

This record describes tracked preparation only. It does not claim that a Helm
release, Kubernetes resource, HCP Terraform run, or AWS mutation occurred.

## Corrected metrics-server identity

`deploy/addons/metrics-server.yaml` uses the owner-approved immutable
metrics-server identity already bound in the sandbox Terraform inputs. It no
longer points at the sandbox application repository.

## Pinned PKI supply chain

The exact component identities are recorded in
`deploy/capstone/pki-supply-chain-lock.json`.

- cert-manager chart `v1.21.3`, OCI digest
  `sha256:e482675aec32862d323a9218293ff7de81192337998615e4378c56498473f240`
- trust-manager chart `v0.26.0`, OCI digest
  `sha256:946c6e52f0a6e251c81102de83ffc6e0b11446193bed8670d4cdbfd3cecbc2e8`
- Four cert-manager images and two trust-manager images are pinned by OCI
  digest in their tracked Helm values.

The official cert-manager supported-release table records cert-manager 1.21
as supporting and testing Kubernetes 1.36. The official OCI charts were
rendered with the tracked values to enumerate every image before its registry
digest was recorded.

## Owner-local root ceremony

`deploy/capstone/pki-bootstrap-contract.json` defines the bounded ceremony.
The root key is generated owner-locally, written only to the temporary
owner-local boundary and the exact Kubernetes Secret, and deleted locally
after the Secret is verified. Only public-certificate, SPKI, trust-bundle and
resource-identity hashes may be retained as evidence.

The contract contains no private key, secret, token, credential or live
cluster identity. Deployment and later removal of temporary PKI access remain
separately controlled execution steps.
