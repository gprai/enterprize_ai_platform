$modulePath = Join-Path $PSScriptRoot '..\..\tools\powershell\incident-command-runner-v1.psm1'
Import-Module -Name $modulePath -Force

Describe 'incident-command-runner-v1 exact cross-host contract' {
    BeforeAll {
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $script:hostExecutable = Join-Path $PSHOME 'powershell.exe'
        }
        else {
            $script:hostExecutable = Join-Path $PSHOME 'pwsh.exe'
        }
        $script:workingDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $script:identity = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    }

    It 'captures stdout, exit, version, duration and the exact command array' {
        $command = @($script:hostExecutable, '-NoProfile', '-NonInteractive', '-Command', "Write-Output 'ok'; exit 0")
        $result = Invoke-IncidentCommandV1 -Command $command -WorkingDirectory $script:workingDirectory -TimeoutSeconds 30 -ProgressIntervalSeconds 5 -MaximumOutputBytes 8388608 -ExpectedAbsence $false -ExpectedIdentity $script:identity -ObservedIdentity $script:identity -IdentityMatch $true -IntegrityOk $true -HealthOk $true -NativeAbsent $false -ResidueCount 0
        $result.Classification | Should Be 'SUCCEEDED'
        $result.ExitCode | Should Be 0
        $result.StandardOutput | Should Match 'ok'
        $result.ToolVersion | Should Not BeNullOrEmpty
        $result.ExecutableSha256 | Should Match '^[0-9a-f]{64}$'
        $result.DurationSeconds | Should BeGreaterThan 0
        ($result.Command -join '|') | Should Be ($command -join '|')
    }

    It 'cannot label a nonzero command successful' {
        $command = @($script:hostExecutable, '-NoProfile', '-NonInteractive', '-Command', "Write-Error 'failed'; exit 7")
        $result = Invoke-IncidentCommandV1 -Command $command -WorkingDirectory $script:workingDirectory -TimeoutSeconds 30 -ProgressIntervalSeconds 5 -MaximumOutputBytes 8388608 -ExpectedAbsence $false -ExpectedIdentity $script:identity -ObservedIdentity $script:identity -IdentityMatch $true -IntegrityOk $true -HealthOk $true -NativeAbsent $false -ResidueCount 0
        $result.Classification | Should Not Be 'SUCCEEDED'
        $result.ExitCode | Should Not Be 0
    }

    It 'requires exact native absence before classifying NotFound as expected' {
        (Resolve-IncidentNotFoundV1 -ExitCode 1 -StandardError 'Resource NotFound' -ExpectedAbsence $true -ExpectedIdentity $script:identity -ObservedIdentity $script:identity -IdentityMatch $true -IntegrityOk $true -HealthOk $true -NativeAbsent $true -ResidueCount 0) | Should Be 'EXPECTED_ABSENT'
        (Resolve-IncidentNotFoundV1 -ExitCode 1 -StandardError 'Resource NotFound' -ExpectedAbsence $false -ExpectedIdentity $script:identity -ObservedIdentity $script:identity -IdentityMatch $true -IntegrityOk $true -HealthOk $true -NativeAbsent $true -ResidueCount 0) | Should Be 'FAILED'
    }

    It 'redacts captured credential-shaped output' {
        $accessKey = 'AKIA' + 'ABCDEFGHIJKLMNOP'
        $protected = Protect-IncidentOutputV1 -Text "Authorization=Bearer-value token=secret-value $accessKey"
        $protected | Should Not Match 'Bearer-value'
        $protected | Should Not Match 'secret-value'
        $protected | Should Not Match $accessKey
    }

    It 'rejects missing request schema fields' {
        $request = [pscustomobject]@{ schema_version = 'w11-004.powershell-request.v1'; command = @($script:hostExecutable) }
        $threw = $false
        try { $null = Assert-IncidentRequestV1 -Request $request }
        catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects duplicate JSON request fields' {
        $json = '{"schema_version":"w11-004.powershell-request.v1","schema_version":"duplicate","command":[],"working_directory":"C:\\","timeout_seconds":1,"progress_interval_seconds":1,"maximum_output_bytes":1,"expected_absence":false,"expected_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","native_verification":{"observed_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_match":true,"integrity_ok":true,"health_ok":true,"native_absent":false,"residue_count":0}}'
        $threw = $false
        try { $null = Assert-IncidentRequestJsonV1 -Json $json }
        catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'reports the deadline instead of PASS when execution times out' {
        $command = @($script:hostExecutable, '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 3; exit 0')
        $result = Invoke-IncidentCommandV1 -Command $command -WorkingDirectory $script:workingDirectory -TimeoutSeconds 1 -ProgressIntervalSeconds 1 -MaximumOutputBytes 8388608 -ExpectedAbsence $false -ExpectedIdentity $script:identity -ObservedIdentity $script:identity -IdentityMatch $true -IntegrityOk $true -HealthOk $true -NativeAbsent $false -ResidueCount 0
        $result.Classification | Should Be 'TIMED_OUT'
        $result.TimedOut | Should Be $true
    }
}
