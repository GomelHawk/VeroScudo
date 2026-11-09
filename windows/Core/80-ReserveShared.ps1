# VeroScudo core, part 80: reserve types: shared helpers.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- reserve types: shared helpers
function Test-VeroNeedsPassword($Config) {
    (Get-VeroTypeHandler (Get-VeroConfigType $Config)).PasswordCapable -and [bool]$Config.Auth   # ras: false = certificate sign-in
}

function Test-VeroTunnelAdapter($Nic) {
    <# A virtual tunnel adapter (TAP, Wintun, OpenVPN DCO, WireGuard, RAS) - never a physical NIC. #>
    if (-not $Nic) { return $false }
    if ([string]$Nic.Description -match 'Teredo|ISATAP|6to4|IP-HTTPS|IPHTTPS|Microsoft Kernel Debug') { return $false }   # Windows' own tunnels
    if ([string]$Nic.NetworkInterfaceType -in 'Ppp', 'Tunnel') { return $true }
    [string]$Nic.Description -match 'TAP-Windows|Wintun|WireGuard|OpenVPN|Data Channel Offload|ovpn-dco|TAP-|sing-box|sing-tun|Hiddify|NordLynx|PrivateVPN'   # sing-tun: Hiddify's VPN mode (seen live)
}

function Write-VeroSecretFile {
    <# A file only Administrators and SYSTEM can read (the state folder lets users read). Created empty, locked down, then filled. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    Set-Content -Path $Path -Value '' -Encoding ASCII
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Protect-VeroOpenVpnDir {
    <# %ProgramData%\VeroScudo\openvpn holds imported configs (often with private keys): Administrators and SYSTEM only. #>
    $d = (Get-VeroPath).OpenVpnDir
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $d -AclObject $acl
    $d
}
