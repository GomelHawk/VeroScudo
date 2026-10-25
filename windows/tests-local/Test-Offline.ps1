#Requires -RunAsAdministrator
# Through the REAL guard (scheduled tasks), never next to it: manual hang-up (RAS 631) must disarm; the On task must then
# redial UNDER the kill-switch - nothing gets out until the tunnel is up. Ends protected. Network off ~10-30 s.
# Touches no state files itself: the running watchdog and event tasks would race a test that drives the module directly.
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-offline.log'; '' | Set-Content $Out
$Folder = '\VeroScudo\'
function L($m) { $l = '{0:HH:mm:ss.f} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile }
function Armed { Test-Path $p.ArmedFlag }
function Tcp($ip, $port, $ms = 1500) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) { $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt $sec) { if (& $cond) { L ("   {0} after {1:N1}s" -f $what, ((Get-Date) - $t).TotalSeconds); return $true }; Start-Sleep -Milliseconds 500 }; L "   TIMEOUT: $what ($sec s)"; $false }
$verdict = [ordered]@{}
try {
    L "0. precondition: VPN up + armed"
    if (-not ((Up) -and (Armed))) { schtasks /run /tn "$Folder`On" | Out-Null; $null = WaitFor { (Up) -and (Armed) } 90 'protected' }
    if (-not ((Up) -and (Armed))) { L 'ABORT: could not reach the protected state'; return }
    L "   filters=$(Get-VeroWfpCount) win-tcp=$(Tcp 1.1.1.1 443)"

    L '1. manual hang-up (rasdial = Settings UI, RAS 631) -> the guard must disarm'
    rasdial.exe $cfg.Profile /disconnect | Out-Null
    $dis = WaitFor { -not (Armed) -and (Get-VeroWfpCount) -eq 0 } 20 'disarmed, filters removed'
    $verdict['1 hang-up disarms'] = $dis

    L '2. On task -> must stay blocked until the tunnel is up, then protected'
    schtasks /run /tn "$Folder`On" | Out-Null
    $null = WaitFor { (Armed) -and (Get-VeroWfpCount) -gt 0 } 20 'armed, filters applied'
    $leak = $false; $probes = 0; $t = Get-Date
    while (-not (Up) -and ((Get-Date) - $t).TotalSeconds -lt 90) {
        $probes++
        if ((Tcp 1.1.1.1 443 800) -or (Tcp 1.1.1.1 80 800)) { if (-not (Up)) { $leak = $true; L '   LEAK: traffic got out while the tunnel was down' } }
    }
    $up = Up
    L ("   tunnel up={0} after {1:N1}s, {2} leak probes while down, leak={3}" -f $up, ((Get-Date) - $t).TotalSeconds, $probes, $leak)
    $prot = WaitFor { (Tcp 1.1.1.1 443) } 30 'traffic flows through the tunnel'
    $verdict['2 redial under kill-switch'] = ($up -and -not $leak -and $prot -and (Armed))
} finally {
    if (-not (Up) -and (Armed)) { L 'cleanup: not up yet - giving the guard 60 s'; $null = WaitFor { Up } 60 'tunnel back' }
    if (-not (Up)) { L 'cleanup: still down -> Off task (raw internet for the user)'; schtasks /run /tn "$Folder`Off" | Out-Null; Start-Sleep 5 }
    L ("   FINAL vpn={0} armed={1} filters={2} win-tcp={3}" -f (Up), (Armed), (Get-VeroWfpCount), (Tcp 1.1.1.1 443))
    L '=== VERDICT'; foreach ($k in $verdict.Keys) { L ('   {0,-28} {1}' -f $k, $(if ($verdict[$k]) { 'PASS' } else { 'FAIL' })) }
    L 'DONE'
}
