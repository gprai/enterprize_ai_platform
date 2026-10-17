package enterprise_ai.model_supply_chain.w9_004

import rego.v1

deny contains "eligibility status is not PASS" if {
    input.status != "PASS"
}

deny contains "critical findings are present" if {
    some scanner in input.scanners
    scanner.critical_findings > 0
}

risk_treatment_present(finding_id) if {
    some treatment in input.risk_treatments
    treatment.finding_id == finding_id
    treatment.candidate_sha256 == input.candidate.artifact_sha256
    time.parse_rfc3339_ns(treatment.approved_at) <= time.parse_rfc3339_ns(input.generated_at)
    time.parse_rfc3339_ns(treatment.expires_at) > time.parse_rfc3339_ns(input.generated_at)
}

deny contains "high finding lacks current owner treatment" if {
    some scanner in input.scanners
    some finding in scanner.findings
    finding.severity == "HIGH"
    not risk_treatment_present(finding.finding_id)
}

deny contains "scanner evidence is not PASS" if {
    some scanner in input.scanners
    scanner.status != "PASS"
}

deny contains "SBOM evidence is not PASS" if {
    some sbom in input.sboms
    sbom.status != "PASS"
}

deny contains "provenance evidence is not PASS" if {
    input.provenance.status != "PASS"
}

deny contains "artifact format is unsafe" if {
    input.inventory.status != "PASS"
}

deny contains "source or license evidence is not PASS" if {
    input.source_license.status != "PASS"
}

deny contains "classification is unsupported" if {
    not input.classification in {"PUBLIC", "INTERNAL"}
}

allow if {
    count(deny) == 0
    input.deployment_approval == "NOT_AUTHORIZED"
}
