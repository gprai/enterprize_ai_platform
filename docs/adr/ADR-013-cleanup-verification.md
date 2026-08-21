# ADR-013 — Cleanup Requires Positive Verification

- Status: Baseline Approved
- Owner: Gyan Prakash Rai
- Original approval: Confirmed; exact original timestamp unavailable
- Owner reaffirmation: 2026-08-18T10:57:45Z

## Decision

Successful teardown requires positive cleanliness verification using required tags
and native service checks. Terraform destroy or tag discovery alone is insufficient.

## Rationale and trade-offs

Tag-only discovery can miss unsupported or untagged resources. Native checks add
maintenance but provide stronger residual-resource evidence.

## Consequences and revisit trigger

Unexpected or unmanaged residuals fail closed. Revisit native checks only when
service coverage makes them redundant. Week 1 uses mocks and creates no resources.
