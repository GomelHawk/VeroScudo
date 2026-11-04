# VeroScudo core, part 40: logging and the armed state.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- logging & state
function Write-VeroLog {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Message, [string]$Action = 'core')
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    if ((Test-Path $p.Log) -and (Get-Item $p.Log).Length -gt 2MB) { Move-Item $p.Log "$($p.Log).1" -Force }
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Action, $Message
    Add-Content -Path $p.Log -Value $line -Encoding UTF8
    Write-Host $line
}
function Test-VeroArmed { Test-Path (Get-VeroPath).ArmedFlag }
function Set-VeroArmed {
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Value, [string]$Action = 'core')
    $p = Get-VeroPath
    if ($Value -and -not (Test-Path $p.ArmedFlag)) { New-Item -ItemType File -Path $p.ArmedFlag -Force | Out-Null; Write-VeroLog 'ARMED' $Action }
    if (-not $Value -and (Test-Path $p.ArmedFlag)) { Remove-Item $p.ArmedFlag -Force; Write-VeroLog 'DISARMED' $Action }
}
function Set-VeroActiveProfile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [string]$Action = 'core')
    $p = Get-VeroPath
    $null = Get-VeroConfig -Active $Name                                  # validates the name against config.json
    $cur = if (Test-Path $p.ActiveProfile) { (Get-Content $p.ActiveProfile -Raw).Trim() } else { '' }
    if ($cur -ne $Name) { Set-Content -Path $p.ActiveProfile -Value $Name -Encoding UTF8; Write-VeroLog "active profile -> '$Name'" $Action }
}

# ---------------------------------------------------------------- one holder per lock, across every process
function Test-VeroLockDirAcl {
    <# Pure: $true when these access rules (identities as SIDs) let only SYSTEM and Administrators in, and none is inherited.
       Inherited rules are the state folder's - Users may read there, and read is enough to open a lock file with no sharing
       and hold it. Deny rules take nothing away from the guard and are ignored. #>
    [CmdletBinding()] param($Rules)
    foreach ($r in @($Rules | ForEach-Object { $_ } | Where-Object { $_ })) {
        if ($r.IsInherited) { return $false }
        if ([string]$r.AccessControlType -ne 'Allow') { continue }
        if ([string]$r.IdentityReference -notmatch '^(S-1-5-18|S-1-5-32-544)$') { return $false }
    }
    $true
}
function Set-VeroLockDirAcl([string]$Path) {
    <# Elevated: exactly SYSTEM and Administrators, full control, inherited by the lock files; nothing from the parent. The
       DACL is written whole, so a rule someone added by hand goes too (icacls /grant:r would keep it). #>
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    [IO.Directory]::SetAccessControl($Path, $acl)
}
function Get-VeroLockDir {
    <# The lock files' folder: administrators and SYSTEM only. A named mutex in the session namespace could be created first by
       any process of the account (a planted "watchdog" would stall the real one for good); a file nobody else may open cannot.
       Checked on every call by an elevated caller, not only when created: the installer's reset of the state folder once gave
       it back the inherited "Users: read" - enough for any program of the account to open watchdog.lock first and hold it. #>
    $d = Join-Path (Get-VeroPath).State 'locks'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    if ((Test-VeroElevated) -and -not (Test-VeroLockDirAcl (Get-Acl -LiteralPath $d).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        Set-VeroLockDirAcl $d
        Write-VeroLog 'locks folder: access set to Administrators and SYSTEM only' 'lock'
    }
    $d
}
function Enter-VeroSingleton {
    <# Returns a handle that makes this process the one holder of $Name (Dispose releases it), or $null when another process
       holds it after waiting up to $WaitMs. The handle is an exclusive open of a file in the locks folder. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [int]$WaitMs = 0)
    $f = Join-Path (Get-VeroLockDir) "$Name.lock"
    $deadline = (Get-Date).AddMilliseconds($WaitMs)
    while ($true) {
        try { return (New-Object IO.FileStream($f, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)) }
        catch [IO.IOException] { if ((Get-Date) -ge $deadline) { return $null }; Start-Sleep -Milliseconds 200 }
    }
}
function Test-VeroSingletonHeld {
    <# True when some process holds $Name right now. Needs the rights of the locks folder: for a non-administrator (the tray) the
       answer is always $false - it cannot see the guard's locks, and never could. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    $f = Join-Path (Get-VeroPath).State "locks\$Name.lock"
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    try { $h = New-Object IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None); $h.Dispose(); return $false }
    catch [IO.IOException] { return $true }
    catch { return $false }
}
