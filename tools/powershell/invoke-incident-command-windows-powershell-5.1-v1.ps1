[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$RequestPath)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'INCIDENT_RUNNER_REQUIRES_WINDOWS_POWERSHELL_5_1' }
$module = Join-Path $PSScriptRoot 'incident-command-runner-v1.psm1'
Import-Module -Name $module -Force
$requestJson = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8
$requestJson = Assert-IncidentRequestJsonV1 -Json $requestJson
$request = $requestJson | ConvertFrom-Json
$request = Assert-IncidentRequestV1 -Request $request
$result = Invoke-IncidentCommandV1 -Command @($request.command) -WorkingDirectory $request.working_directory -TimeoutSeconds $request.timeout_seconds -ProgressIntervalSeconds $request.progress_interval_seconds -MaximumOutputBytes $request.maximum_output_bytes -ExpectedAbsence $request.expected_absence -ExpectedIdentity $request.expected_identity -ObservedIdentity $request.native_verification.observed_identity -IdentityMatch $request.native_verification.identity_match -IntegrityOk $request.native_verification.integrity_ok -HealthOk $request.native_verification.health_ok -NativeAbsent $request.native_verification.native_absent -ResidueCount $request.native_verification.residue_count
$result | ConvertTo-Json -Depth 8 -Compress
if ($result.Classification -notin @('SUCCEEDED', 'EXPECTED_ABSENT')) { exit 1 }
