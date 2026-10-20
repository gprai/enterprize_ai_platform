Set-StrictMode -Version 2.0

function ConvertTo-IncidentSha256V1 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Protect-IncidentOutputV1 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $value = $Text -replace '(?i)(authorization\s*[:=]\s*)[^\s,;]+', '$1[REDACTED]'
    $value = $value -replace '(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+', '$1[REDACTED]'
    return ($value -replace '\bAKIA[0-9A-Z]{16}\b', '[REDACTED]')
}

function Assert-IncidentRequestV1 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Request)

    $expected = @('schema_version', 'command', 'working_directory', 'timeout_seconds', 'progress_interval_seconds', 'maximum_output_bytes', 'expected_absence', 'expected_identity', 'native_verification') | Sort-Object
    $actual = @($Request.PSObject.Properties.Name) | Sort-Object
    $differences = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
    if ($differences.Count -ne 0) {
        throw 'INCIDENT_REQUEST_FIELDS_DIFFER'
    }
    if ($Request.schema_version -ne 'w11-004.powershell-request.v1') { throw 'INCIDENT_REQUEST_SCHEMA_INVALID' }
    if (@($Request.command).Count -lt 1 -or -not [System.IO.Path]::IsPathRooted($Request.command[0])) { throw 'INCIDENT_REQUEST_COMMAND_INVALID' }
    foreach ($item in @($Request.command)) {
        if ([string]::IsNullOrEmpty($item) -or $item.Contains([char]0)) { throw 'INCIDENT_REQUEST_ARGUMENT_INVALID' }
    }
    if (-not [System.IO.Path]::IsPathRooted($Request.working_directory)) { throw 'INCIDENT_REQUEST_WORKING_DIRECTORY_INVALID' }
    if ([int]$Request.timeout_seconds -lt 1 -or [int]$Request.timeout_seconds -gt 300) { throw 'INCIDENT_REQUEST_TIMEOUT_INVALID' }
    if ([int]$Request.progress_interval_seconds -lt 1 -or [int]$Request.progress_interval_seconds -gt 30) { throw 'INCIDENT_REQUEST_PROGRESS_INTERVAL_INVALID' }
    if ([int]$Request.maximum_output_bytes -lt 1 -or [int]$Request.maximum_output_bytes -gt 8388608) { throw 'INCIDENT_REQUEST_OUTPUT_BOUND_INVALID' }
    if ($Request.expected_identity -notmatch '^[0-9a-f]{64}$') { throw 'INCIDENT_REQUEST_IDENTITY_INVALID' }
    $nativeExpected = @('observed_identity', 'identity_match', 'integrity_ok', 'health_ok', 'native_absent', 'residue_count') | Sort-Object
    $nativeActual = @($Request.native_verification.PSObject.Properties.Name) | Sort-Object
    $nativeDifferences = @(Compare-Object -ReferenceObject $nativeExpected -DifferenceObject $nativeActual)
    if ($nativeDifferences.Count -ne 0) { throw 'INCIDENT_NATIVE_VERIFICATION_FIELDS_DIFFER' }
    if ($Request.native_verification.observed_identity -notmatch '^[0-9a-f]{64}$' -or [int]$Request.native_verification.residue_count -lt 0) { throw 'INCIDENT_NATIVE_VERIFICATION_INVALID' }
    if ([bool]$Request.native_verification.identity_match -ne ($Request.expected_identity -eq $Request.native_verification.observed_identity)) { throw 'INCIDENT_NATIVE_IDENTITY_MATCH_INVALID' }
    return $Request
}

function Assert-IncidentRequestJsonV1 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Json)

    $requiredNames = @('schema_version', 'command', 'working_directory', 'timeout_seconds', 'progress_interval_seconds', 'maximum_output_bytes', 'expected_absence', 'expected_identity', 'native_verification', 'observed_identity', 'identity_match', 'integrity_ok', 'health_ok', 'native_absent', 'residue_count')
    foreach ($name in $requiredNames) {
        $pattern = '"' + [regex]::Escape($name) + '"\s*:'
        if ([regex]::Matches($Json, $pattern).Count -ne 1) {
            throw "INCIDENT_REQUEST_JSON_FIELD_COUNT_INVALID:$name"
        }
    }
    return $Json
}

function Resolve-IncidentNotFoundV1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$StandardError,
        [Parameter(Mandatory = $true)][bool]$ExpectedAbsence,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][string]$ObservedIdentity,
        [Parameter(Mandatory = $true)][bool]$IdentityMatch,
        [Parameter(Mandatory = $true)][bool]$IntegrityOk,
        [Parameter(Mandatory = $true)][bool]$HealthOk,
        [Parameter(Mandatory = $true)][bool]$NativeAbsent,
        [Parameter(Mandatory = $true)][int]$ResidueCount
    )

    if ($ExitCode -eq 0) {
        if ($ExpectedAbsence -or -not $IdentityMatch -or -not $IntegrityOk -or -not $HealthOk -or $ResidueCount -ne 0) { return 'FAILED' }
        return 'SUCCEEDED'
    }
    $normalized = ($StandardError -replace '\s', '').ToLowerInvariant()
    if (
        $ExpectedAbsence -and
        $normalized.Contains('notfound') -and
        $ExpectedIdentity -eq $ObservedIdentity -and
        $IdentityMatch -and
        $IntegrityOk -and
        $HealthOk -and
        $NativeAbsent -and
        $ResidueCount -eq 0
    ) {
        return 'EXPECTED_ABSENT'
    }
    return 'FAILED'
}

function Invoke-IncidentCommandV1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Command,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][ValidateRange(1, 300)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(1, 30)][int]$ProgressIntervalSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(1, 8388608)][int]$MaximumOutputBytes,
        [Parameter(Mandatory = $true)][bool]$ExpectedAbsence,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][string]$ObservedIdentity,
        [Parameter(Mandatory = $true)][bool]$IdentityMatch,
        [Parameter(Mandatory = $true)][bool]$IntegrityOk,
        [Parameter(Mandatory = $true)][bool]$HealthOk,
        [Parameter(Mandatory = $true)][bool]$NativeAbsent,
        [Parameter(Mandatory = $true)][ValidateRange(0, 2147483647)][int]$ResidueCount
    )

    if ($Command.Count -lt 1 -or -not [System.IO.Path]::IsPathRooted($Command[0])) {
        throw 'INCIDENT_EXECUTABLE_MUST_BE_ABSOLUTE'
    }
    foreach ($item in $Command) {
        if ([string]::IsNullOrEmpty($item) -or $item.Contains([char]0)) {
            throw 'INCIDENT_ARGUMENT_INVALID'
        }
    }
    if (-not (Test-Path -LiteralPath $Command[0] -PathType Leaf)) {
        throw 'INCIDENT_EXECUTABLE_NOT_FOUND'
    }
    if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        throw 'INCIDENT_WORKING_DIRECTORY_INVALID'
    }

    $started = [DateTimeOffset]::UtcNow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $powerShell = [PowerShell]::Create()
    $script = @'
param([string[]]$ExactCommand, [string]$ExactWorkingDirectory)
$previous = [System.Environment]::CurrentDirectory
try {
    [System.Environment]::CurrentDirectory = $ExactWorkingDirectory
    $arguments = @()
    if ($ExactCommand.Count -gt 1) { $arguments = $ExactCommand[1..($ExactCommand.Count - 1)] }
    $combined = @(& $ExactCommand[0] @arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = if ($?) { 0 } else { 1 } }
    $output = @($combined | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() })
    $errors = @($combined | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() })
    [pscustomobject]@{ ExitCode = [int]$exitCode; Output = $output; Errors = $errors }
}
finally {
    [System.Environment]::CurrentDirectory = $previous
}
'@
    [void]$powerShell.AddScript($script).AddArgument($Command).AddArgument($WorkingDirectory)
    $async = $powerShell.BeginInvoke()
    $progress = New-Object System.Collections.Generic.List[string]
    [void]$progress.Add("started deadline_seconds=$TimeoutSeconds")
    $nextProgressSeconds = [double]$ProgressIntervalSeconds
    $timedOut = $false
    try {
        while (-not $async.IsCompleted) {
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                $powerShell.Stop()
                break
            }
            Start-Sleep -Milliseconds 250
            if ($stopwatch.Elapsed.TotalSeconds -ge $nextProgressSeconds) {
                [void]$progress.Add("progress elapsed_seconds=$([Math]::Floor($stopwatch.Elapsed.TotalSeconds))")
                $nextProgressSeconds += $ProgressIntervalSeconds
            }
        }
        $records = @()
        if (-not $timedOut) { $records = @($powerShell.EndInvoke($async)) }
        $stopwatch.Stop()
        $stdout = ''
        $stderr = ''
        $exitCode = -1
        if ($timedOut) {
            $classification = 'TIMED_OUT'
            [void]$progress.Add('timed_out')
        }
        elseif ($powerShell.Streams.Error.Count -gt 0 -or $records.Count -ne 1) {
            $stderr = (($powerShell.Streams.Error | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
            $classification = 'INDETERMINATE'
        }
        else {
            $exitCode = [int]$records[0].ExitCode
            $stdout = (@($records[0].Output) -join [Environment]::NewLine)
            $stderr = (@($records[0].Errors) -join [Environment]::NewLine)
            $classification = Resolve-IncidentNotFoundV1 -ExitCode $exitCode -StandardError $stderr -ExpectedAbsence $ExpectedAbsence -ExpectedIdentity $ExpectedIdentity -ObservedIdentity $ObservedIdentity -IdentityMatch $IdentityMatch -IntegrityOk $IntegrityOk -HealthOk $HealthOk -NativeAbsent $NativeAbsent -ResidueCount $ResidueCount
            [void]$progress.Add("completed exit_code=$exitCode")
        }
        $stdout = Protect-IncidentOutputV1 -Text $stdout
        $stderr = Protect-IncidentOutputV1 -Text $stderr
        $outputBytes = [System.Text.Encoding]::UTF8.GetByteCount($stdout) + [System.Text.Encoding]::UTF8.GetByteCount($stderr)
        if ($outputBytes -gt $MaximumOutputBytes) {
            $stdout = ''
            $stderr = 'PROCESS_OUTPUT_LIMIT_OR_INCOMPLETE'
            $classification = 'INDETERMINATE'
            $exitCode = -1
        }
        $file = Get-Item -LiteralPath $Command[0]
        $executableSha256 = (Get-FileHash -LiteralPath $Command[0] -Algorithm SHA256).Hash.ToLowerInvariant()
        $toolVersion = $file.VersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($toolVersion)) { $toolVersion = $file.VersionInfo.FileVersion }
        if ([string]::IsNullOrWhiteSpace($toolVersion)) { $toolVersion = 'UNAVAILABLE' }
        [pscustomobject]@{
            SchemaVersion = 'w11-004.command-evidence.v1'
            RunnerVersion = 'incident-command-runner-v1'
            Command = @($Command)
            CommandSha256 = ConvertTo-IncidentSha256V1 -Text (($Command | ConvertTo-Json -Compress))
            ExecutablePath = $file.FullName
            ExecutableSha256 = $executableSha256
            StartedAt = $started.ToString('o')
            CompletedAt = [DateTimeOffset]::UtcNow.ToString('o')
            DurationSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 6)
            StandardOutput = $stdout
            StandardOutputSha256 = ConvertTo-IncidentSha256V1 -Text $stdout
            StandardError = $stderr
            StandardErrorSha256 = ConvertTo-IncidentSha256V1 -Text $stderr
            ExitCode = $exitCode
            ToolVersion = $toolVersion
            Classification = $classification
            Progress = @($progress)
            DeadlineSeconds = $TimeoutSeconds
            ProgressIntervalSeconds = $ProgressIntervalSeconds
            TimedOut = $timedOut
        }
    }
    finally {
        $stopwatch.Stop()
        $powerShell.Dispose()
    }
}

Export-ModuleMember -Function ConvertTo-IncidentSha256V1, Protect-IncidentOutputV1, Assert-IncidentRequestV1, Assert-IncidentRequestJsonV1, Resolve-IncidentNotFoundV1, Invoke-IncidentCommandV1
