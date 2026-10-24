#Requires -RunAsAdministrator
# arm -> hang up -> redial under the kill-switch -> watch the fresh tunnel 60 s (Windows + WSL traffic) -> disarm. ~2 min.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'WslUser', Justification = 'used inside nested function')]
param([string]$WslUser = $env:USERNAME)
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-reconnect.log'; '' | Set-Content $Out
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile }
function Tcp($ip, $port, $ms = 3000) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function Wsl { if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return 'n/a' }; (wsl.exe -u $WslUser -e curl -s -m 4 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>$null) -join '' }
$t0 = Get-Date; Remove-Item $p.ArmedFlag, $p.Lock -Force -ErrorAction SilentlyContinue
try {
    L '1. arm'; Invoke-VeroAction arm $cfg | Out-Null; L "   vpn=$(Up) win-tcp=$(Tcp 1.1.1.1 443) wsl=$(Wsl)"
    L '2. hang up + redial under kill-switch'; rasdial.exe $cfg.Profile /disconnect | Out-Null; Start-Sleep 3
    L "   blocked while down: win-tcp=$(Tcp 1.1.1.1 443) wsl=$(Wsl)"
    $sw = [Diagnostics.Stopwatch]::StartNew(); Invoke-VeroAction on $cfg | Out-Null; $sw.Stop(); L ("   vpn={0} in {1:N0}s" -f (Up), $sw.Elapsed.TotalSeconds)
    L '3. fresh tunnel under kill-switch, 60 s watch'; $t1 = Get-Date
    for ($i = 0; $i -lt 12; $i++) { L ("   t+{0,2}s vpn={1} win-tcp={2} wsl={3}" -f [int]((Get-Date) - $t1).TotalSeconds, (Up), (Tcp 1.1.1.1 443), (Wsl)); Start-Sleep 3 }
} finally {
    L '4. restore: disarm'; Invoke-VeroAction disarm $cfg | Out-Null
    if (-not (Up)) { L '   VPN down -> redial (unblocked)'; Invoke-VeroAction on $cfg | Out-Null; Invoke-VeroAction disarm $cfg | Out-Null }
    Start-Sleep 3
    L "   FINAL vpn=$(Up) outbound=$((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',') rules=$(@(Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue).Count) win-tcp=$(Tcp 1.1.1.1 443) wsl=$(Wsl)"
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=$t0} -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4003 } | ForEach-Object { L ('   WLAN 4003 (Wi-Fi reset) at {0:HH:mm:ss}  <-- enable wifiRecoveryFix' -f $_.TimeCreated) }
    L 'DONE'
}
