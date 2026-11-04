# VeroScudo core, part 10: constants, OS-resolved system folders, the install-folder ACL check.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

$script:Version      = '1.3.0'
$script:LegacyGroup  = 'VeroScudo'                                       # Windows Firewall rule group of 1.0.x (migrated away)
$script:VmRule       = 'VeroScudo-WSL'
$script:WslCreator   = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'          # Hyper-V firewall VM creator id of WSL
# System folders come from the OS, never from environment variables: the guard runs elevated, and a non-admin process can
# plant %ProgramFiles%, %ProgramData% or %SystemRoot% in HKCU\Environment (the SilentCleanup-style UAC bypass).
function Get-VeroSystemDir {
    [CmdletBinding()] param([ValidateSet('System', 'ProgramFiles', 'ProgramData')][string]$Kind)
    $sys = [Environment]::SystemDirectory                                   # GetSystemDirectory(): not the environment
    if (-not $sys) { $sys = 'C:\Windows\System32' }                        # (non-Windows dev harness only)
    if ($Kind -eq 'System') { return $sys }
    $drive = try { [IO.Path]::GetPathRoot($sys).TrimEnd('\') } catch { 'C:' }
    $key, $name = if ($Kind -eq 'ProgramFiles') { 'SOFTWARE\Microsoft\Windows\CurrentVersion', 'ProgramFilesDir' } else { 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', 'ProgramData' }
    try {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key)
        if ($rk) {
            $v = [string]$rk.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $rk.Close()
            if ($v) { return ($v -replace '(?i)%SystemDrive%', $drive) }
        }
    } catch { Write-Verbose "registry: $($_.Exception.Message)" }
    if ($Kind -eq 'ProgramFiles') { $drive + '\Program Files' } else { $drive + '\ProgramData' }
}
function Test-VeroAdminOnlyRules {
    <# Pure: $true when none of these access rules lets a non-administrator rename, delete or re-permission the folder they
       are on. Dangerous rights: Delete (rename the folder itself), DeleteSubdirectoriesAndFiles (rename a child), ChangePermissions,
       TakeOwnership, GENERIC_ALL. Create-only rights are harmless here (Authenticated Users may create folders in C:\ and
       still cannot touch C:\Program Files). Inherit-only rules do not apply to the folder itself. Trusted: SYSTEM,
       Administrators, TrustedInstaller, CREATOR OWNER. #>
    [CmdletBinding()] param($Rules)
    # by SID (account names are localized on non-English Windows); a name that cannot be looked up (test doubles) is compared as text
    $trustedSid = '^(S-1-5-18|S-1-5-32-544|S-1-3-0|S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)$'
    $trustedName = '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\TrustedInstaller|CREATOR OWNER)$'
    [uint32]$danger = 0x10000 -bor 0x40 -bor 0x40000 -bor 0x80000 -bor 0x10000000     # Delete, DeleteChild, WriteDAC, WriteOwner, GENERIC_ALL
    foreach ($r in @($Rules | ForEach-Object { $_ } | Where-Object { $_ })) {           # an AuthorizationRuleCollection is enumerated, never taken as one item
        if ([string]$r.AccessControlType -ne 'Allow') { continue }
        $who = [string]$r.IdentityReference
        $sid = try { ([Security.Principal.NTAccount]$who).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $who }
        if ($sid -match $trustedSid -or $who -match $trustedName) { continue }
        if (([int]$r.PropagationFlags -band [int][Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $bits = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$r.FileSystemRights), 0)
        if (($bits -band $danger) -ne 0) { return $false }
    }
    $true
}
function Test-VeroAdminOnlyPath {
    <# The folder $Path will be locked down by the installer; this checks its ANCESTORS: if any of them lets a non-administrator
       rename or replace folders, $Path can be renamed away and a folder of that name planted - and the elevated tasks run
       scripts from $Path. Returns the first weak ancestor, $null when all are administrators-only. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $dir = [IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    while ($dir) {
        if ((Test-Path -LiteralPath $dir.FullName) -and -not (Test-VeroAdminOnlyRules @((Get-Acl -LiteralPath $dir.FullName).Access | ForEach-Object { $_ }))) { return $dir.FullName }
        $dir = $dir.Parent
    }
    $null
}
# exactly the spelling of 1.2.1 (C:\WINDOWS\System32\svchost.exe), which is live-verified - only the root comes from the OS now
$script:Svchost      = ((Get-VeroSystemDir System) -replace '\\[^\\]+$', '') + '\System32\svchost.exe'
$script:Rasdial      = (Get-VeroSystemDir System) + '\rasdial.exe'            # elevated callers: never resolved by name
$script:Schtasks     = (Get-VeroSystemDir System) + '\schtasks.exe'
$script:HomeOverride = $null                                            # tests only (Set-VeroHome); never read from the environment
$script:UserOverride = $null                                            # tests only (Set-VeroHome -UserDir)
$script:ReleasePrefix = 'https://github.com/GomelHawk/VeroScudo/releases/'
$script:Types        = @('ras', 'openvpn', 'wireguard')
$script:WgStaleSeconds = 180                                            # WireGuard re-handshakes every 2 min on a live link
$script:WgGraceSeconds = 30                                             # a just-started tunnel has not handshaken yet
