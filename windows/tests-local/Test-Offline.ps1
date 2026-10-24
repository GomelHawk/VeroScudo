#Requires -RunAsAdministrator
# arm -> hang up -> redial under the kill-switch (stored credential) -> disarm. Restores in `finally`. ~1 min.
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-offline.log'; '' | Set-Content $Out
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile }
function Tcp($ip, $port, $ms = 2500) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
Remove-Item $p.ArmedFlag, $p.Lock -Force -ErrorAction SilentlyContinue
try {
    L '1. arm (VPN up)'; Invoke-VeroAction arm $cfg | Out-Null
    L "   outbound=$((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',') rules=$(@(Get-NetFirewallRule -Group VeroScudo).Count) win-tcp=$(Tcp 1.1.1.1 443)"
    L '2. hang up (expect RAS 631)'; rasdial.exe $cfg.Profile /disconnect | Out-Null; Start-Sleep 3
    L "   vpn=$(Up) 20226=$(Get-VeroRasCode 20226 $cfg.Profile) blocked: win-tcp=$(Tcp 1.1.1.1 443)"
    L '3. redial under kill-switch'; $sw = [Diagnostics.Stopwatch]::StartNew(); Invoke-VeroAction on $cfg | Out-Null; $sw.Stop()
    L ("   vpn={0} after {1:N0}s" -f (Up), $sw.Elapsed.TotalSeconds)
    if (Up) { Start-Sleep 3; L "4. traffic under kill-switch: win-tcp=$(Tcp 1.1.1.1 443)" } else { L "   FAILED (20227=$(Get-VeroRasCode 20227 $cfg.Profile))" }
} finally {
    L '5. restore: disarm'; Invoke-VeroAction disarm $cfg | Out-Null
    if (-not (Up)) { Invoke-VeroAction on $cfg | Out-Null; Invoke-VeroAction disarm $cfg | Out-Null }
    L "   FINAL vpn=$(Up) outbound=$((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',') rules=$(@(Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue).Count) win-tcp=$(Tcp 1.1.1.1 443)"
    L 'DONE'
}
