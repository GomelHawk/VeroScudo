<#
  Stores the VPN password for the automatic redial, DPAPI-encrypted for THIS Windows account only, one per VPN profile.
  Run as the normal user (no admin):  powershell -ExecutionPolicy Bypass -File Set-VpnCredential.ps1 [-VpnProfile <name>]
  Why: rasdial does not use the password saved by the Windows Settings app, so unattended redials need their own copy.
  The redial hands it to the RasDial API directly (OpenVPN: over its local management connection) - it never appears on a
  command line. -KeyPassphrase stores the passphrase of an OpenVPN profile's encrypted private key instead.
  WireGuard profiles need nothing here (their keys live in the WireGuard app).
#>
param([string]$VpnProfile, [string]$UserName, [switch]$KeyPassphrase)
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force
$cfg = Get-VeroConfig
if ($VpnProfile) { $cfg = Get-VeroConfig -Active $VpnProfile }
elseif (@($cfg.Profiles).Count -gt 1) {
    Write-Host "Configured VPN profiles: $(@($cfg.Profiles | ForEach-Object Profile) -join ', ')"
    $answer = Read-Host "Profile [$($cfg.Profile)]"
    if ($answer) { $cfg = Get-VeroConfig -Active $answer }
}
if (-not $UserName) { $UserName = $cfg.Username }
$p = Get-VeroPath -VpnProfile $cfg.Profile
New-Item -ItemType Directory -Path $p.UserDir -Force | Out-Null
if ($cfg.Type -eq 'wireguard') { Write-Host "'$($cfg.Profile)' is a WireGuard profile: nothing to store (the WireGuard app keeps its keys)."; return }
if ($KeyPassphrase) {
    $pw = Read-Host -AsSecureString "Private-key passphrase ($($cfg.Profile))"
    New-Object System.Management.Automation.PSCredential('key', $pw) | Export-Clixml $p.KeyPass
    Write-Host "stored: $($p.KeyPass)  (readable only by $env:USERDOMAIN\$env:USERNAME on this machine)"
    return
}
if (-not $UserName) { $UserName = Read-Host "VPN username ($($cfg.Profile))" }
$pw = Read-Host -AsSecureString "VPN password for $UserName ($($cfg.Profile))"
New-Object System.Management.Automation.PSCredential($UserName, $pw) | Export-Clixml $p.Cred
Write-Host "stored: $($p.Cred)  (readable only by $env:USERDOMAIN\$env:USERNAME on this machine)"
