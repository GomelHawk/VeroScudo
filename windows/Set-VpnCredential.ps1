<#
  Stores the VPN password for the automatic redial, DPAPI-encrypted for THIS Windows account only, one per VPN profile.
  Run as the normal user (no admin):  powershell -ExecutionPolicy Bypass -File Set-VpnCredential.ps1 [-VpnProfile <name>]
  Why: rasdial does not use the password saved by the Windows Settings app, so unattended redials need their own copy.
  The redial hands it to the RasDial API directly - it never appears on a command line.
#>
param([string]$VpnProfile, [string]$UserName)
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
$pw = Read-Host -AsSecureString "VPN password for $UserName ($($cfg.Profile))"
New-Object System.Management.Automation.PSCredential($UserName, $pw) | Export-Clixml $p.Cred
Write-Host "stored: $($p.Cred)  (readable only by $env:USERDOMAIN\$env:USERNAME on this machine)"
