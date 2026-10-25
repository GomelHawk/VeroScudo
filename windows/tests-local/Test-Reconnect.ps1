#Requires -RunAsAdministrator
# Test-Offline, then a 60 s watch of the fresh tunnel (Windows + WSL traffic): catches the Wi-Fi reset problem
# (docs/ARCHITECTURE.md, wifiRecoveryFix). Through the real tasks; ends protected. ~2 min.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'WslUser', Justification = 'used inside nested function')]
param([string]$WslUser = $env:USERNAME)
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-reconnect.log'
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile }
function Tcp($ip, $port, $ms = 3000) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function Wsl { if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return 'n/a' }; (wsl.exe -u $WslUser -e curl -s -m 4 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>$null) -join '' }
$t0 = Get-Date; '' | Set-Content $Out
& "$PSScriptRoot\Test-Offline.ps1"
if (-not (Up)) { L 'tunnel not up after Test-Offline - no watch'; return }
L '3. fresh tunnel under kill-switch, 60 s watch'; $t1 = Get-Date; $bad = 0
for ($i = 0; $i -lt 12; $i++) {
    $win = Tcp 1.1.1.1 443; $w = Wsl
    if (-not $win -or $w -notin '200', '301', 'n/a') { $bad++ }
    L ("   t+{0,2}s vpn={1} win-tcp={2} wsl={3}" -f [int]((Get-Date) - $t1).TotalSeconds, (Up), $win, $w); Start-Sleep 3
}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=$t0} -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4003 } | ForEach-Object { L ('   WLAN 4003 (Wi-Fi reset) at {0:HH:mm:ss}  <-- enable wifiRecoveryFix' -f $_.TimeCreated) }
L ("=== fresh tunnel stable: {0}" -f $(if ($bad -eq 0) { 'PASS' } else { "FAIL ($bad bad probes)" }))
L 'DONE'
