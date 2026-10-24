<#
  Stores the VPN password for the automatic redial, DPAPI-encrypted for THIS Windows account only.
  Run as the normal user (no admin):  powershell -ExecutionPolicy Bypass -File Set-VpnCredential.ps1
  Why: rasdial does not use the password saved by the Windows Settings app, so unattended redials need their own copy.
#>
param([string]$UserName)
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force
$p = Get-VeroPath
if (-not $UserName) { try { $UserName = (Get-VeroConfig).Username } catch { $UserName = Read-Host 'VPN username' } }
$dir = Split-Path $p.Cred -Parent
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$pw = Read-Host -AsSecureString "VPN password for $UserName"
New-Object System.Management.Automation.PSCredential($UserName, $pw) | Export-Clixml $p.Cred
Write-Host "stored: $($p.Cred)  (readable only by $env:USERDOMAIN\$env:USERNAME on this machine)"
