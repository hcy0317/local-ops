param(
    [Parameter(Mandatory = $true)]
    [string]$PackageExecutable,
    [ValidateRange(9600, 9609)]
    [int]$Port = 9600,
    [switch]$Activate
)

$ErrorActionPreference = 'Stop'

function Wait-ConsoleTaskStopped {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,
        [int]$TimeoutSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $current = Get-ScheduledTask `
            -TaskName $TaskName `
            -ErrorAction SilentlyContinue
        $state = if ($null -eq $current) { 'Missing' } else {
            [string]$current.State
        }
        if ($state -ne 'Running' -and $state -ne 'Queued') {
            Start-Sleep -Milliseconds 250
            return
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)

    throw 'Previous console task instance did not stop.'
}

$taskName = 'LocalOps-Console'
$programFiles = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$brokerRoot = [System.IO.Path]::Combine($programFiles, 'LocalOps', 'Broker')
$executable = [System.IO.Path]::GetFullPath($PackageExecutable)

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'PackageExecutable does not exist.'
}
if ([System.IO.Path]::GetExtension($executable) -ne '.exe') {
    throw 'PackageExecutable must be an executable.'
}
if (-not $executable.StartsWith(
        $brokerRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'PackageExecutable must be inside the protected LocalOps broker root.'
}

$resolved = (Resolve-Path -LiteralPath $executable).Path
if (-not $resolved.StartsWith(
        $brokerRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved package path escaped the protected LocalOps broker root.'
}

$writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
    -bor [System.Security.AccessControl.FileSystemRights]::Delete `
    -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
$usersSid = 'S-1-5-32-545'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = Get-Acl -LiteralPath $resolved
foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    try {
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        continue
    }
    if (($sid -eq $usersSid -or $sid -eq $currentSid) `
            -and (($rule.FileSystemRights -band $writeMask) -ne 0)) {
        throw 'PackageExecutable is writable by a non-system principal.'
    }
}

$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$workingDirectory = [System.IO.Path]::GetDirectoryName($resolved)
$action = New-ScheduledTaskAction `
    -Execute $resolved `
    -Argument ('--no-browser --preferred-port ' + $Port) `
    -WorkingDirectory $workingDirectory
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
$principal = New-ScheduledTaskPrincipal `
    -UserId $account `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -StartWhenAvailable
$definition = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings

if ($Activate) {
    $existingTask = Get-ScheduledTask `
        -TaskName $taskName `
        -ErrorAction SilentlyContinue
    if ($null -ne $existingTask) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Wait-ConsoleTaskStopped -TaskName $taskName
    }
}

Register-ScheduledTask `
    -TaskName $taskName `
    -InputObject $definition `
    -Force | Out-Null

if ($Activate) {
    Start-ScheduledTask -TaskName $taskName
}

$registered = Get-ScheduledTask -TaskName $taskName
$registeredAction = $registered.Actions | Select-Object -First 1
if ($registered.Principal.RunLevel -ne 'Limited' `
        -or $registeredAction.Execute -ne $resolved) {
    throw 'Registered task did not preserve the protected limited contract.'
}

[ordered]@{
    taskName = $taskName
    runLevel = [string]$registered.Principal.RunLevel
    executable = [string]$registeredAction.Execute
    arguments = [string]$registeredAction.Arguments
    state = [string]$registered.State
} | ConvertTo-Json -Compress
