#Requires -RunAsAdministrator
# Through the REAL guard (scheduled tasks), for the ACTIVE profile of any type (Windows VPN, OpenVPN, WireGuard):
#   1. Reconnect (your action): traffic blocked while the tunnel is renewed, nothing leaks, protected again by itself;
#   2. OpenVPN: openvpn.exe killed / WireGuard: its service stopped -> a FAILURE: stays blocked, redials, protected again;
#   3. WireGuard only: tunnel deactivated as the WireGuard app does it -> read as YOUR Off: disarmed; On -> protected.
# Network interrupted for up to ~3 min in total. Touches no state files itself. Paste the VERDICT block into your PR.
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-types.log'; '' | Set-Content $Out
$Folder = '\VeroScudo\'; $type = $cfg.Type
function L($m) { $l = '{0:HH:mm:ss.f} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile -Type $type }
function Armed { Test-Path $p.ArmedFlag }
function Tcp($ip, $port, $ms = 1500) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) { $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt $sec) { if (& $cond) { L ("   {0} after {1:N1}s" -f $what, ((Get-Date) - $t).TotalSeconds); return $true }; Start-Sleep -Milliseconds 500 }; L "   TIMEOUT: $what ($sec s)"; $false }
function Watch-Outage([int]$sec) {
    # probes while the tunnel is not up: any TCP that gets out is a leak; ends when the tunnel is back (or after $sec)
    $r = @{ Leak = $false; Probes = 0; WentDown = $false; Disarmed = $false }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt $sec) {
        if (-not (Up)) {
            $r.WentDown = $true; $r.Probes++
            if ((Tcp 1.1.1.1 443 800) -or (Tcp 1.1.1.1 80 800)) { if (-not (Up)) { $r.Leak = $true; L '   LEAK: traffic got out while the tunnel was down' } }
        } elseif ($r.WentDown) { break }
        if (-not (Armed)) { $r.Disarmed = $true }
        Start-Sleep -Milliseconds 300
    }
    L ("   went down={0}, {1} leak probes while down, leak={2}, disarmed meanwhile={3}, up now={4}" -f $r.WentDown, $r.Probes, $r.Leak, $r.Disarmed, (Up))
    $r
}
$verdict = [ordered]@{}
try {
    L "0. precondition: '$($cfg.Profile)' ($(Get-VeroTypeLabel $type)) up + armed"
    if (-not ((Up) -and (Armed))) { schtasks /run /tn "$Folder`On" | Out-Null; $null = WaitFor { (Up) -and (Armed) } 120 'protected' }
    if (-not ((Up) -and (Armed))) { L 'ABORT: could not reach the protected state'; return }

    L '1. Reconnect task -> blocked while renewing, no leak, protected again'
    schtasks /run /tn "$Folder`Reconnect" | Out-Null
    $r = Watch-Outage 150
    $back = WaitFor { (Up) -and (Tcp 1.1.1.1 443) } 60 'traffic flows through the new tunnel'
    $verdict['1 reconnect'] = ($r.WentDown -and -not $r.Leak -and -not $r.Disarmed -and $back -and (Armed))

    if ($type -eq 'openvpn') {
        L '2. openvpn.exe killed -> a failure: stays blocked, the runner starts it again'
        $s = Get-VeroOpenVpnStatus $cfg.Profile
        if ($s -and $s.OvpnPid) { Stop-Process -Id ([int]$s.OvpnPid) -Force -ErrorAction SilentlyContinue; L "   killed openvpn.exe PID $($s.OvpnPid)" }
        $r = Watch-Outage 150
        $back = WaitFor { (Up) -and (Tcp 1.1.1.1 443) } 60 'traffic flows again'
        $verdict['2 openvpn killed = failure'] = ($r.WentDown -and -not $r.Leak -and -not $r.Disarmed -and $back)
    }
    if ($type -eq 'wireguard') {
        $svc = 'WireGuardTunnel$' + $cfg.Profile
        L '2. WireGuard service stopped (stays installed) -> a failure: stays blocked, redials'
        Stop-Service -Name $svc -Force; L "   stopped $svc"
        $r = Watch-Outage 150
        $back = WaitFor { (Up) -and (Tcp 1.1.1.1 443) } 60 'traffic flows again'
        $verdict['2 wireguard stopped = failure'] = ($r.WentDown -and -not $r.Leak -and -not $r.Disarmed -and $back)

        L '3. tunnel deactivated like the WireGuard app does it -> your Off: disarmed within 30 s; then On'
        L '   waiting 20 s: the watchdog must have seen the tunnel running before it is removed'; Start-Sleep 20
        Start-Process -FilePath (Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe') -ArgumentList "/uninstalltunnelservice $($cfg.Profile)" -Wait -WindowStyle Hidden
        $off = WaitFor { -not (Armed) -and (Get-VeroWfpCount) -eq 0 } 45 'disarmed, filters removed'
        schtasks /run /tn "$Folder`On" | Out-Null
        $on = WaitFor { (Up) -and (Armed) -and (Tcp 1.1.1.1 443) } 120 'protected again'
        $verdict['3 wireguard deactivated = off'] = ($off -and $on)
    }
    if ($type -eq 'ras') { L '2./3. Windows VPN: covered by Test-Offline.ps1 and Test-Live.ps1' }
} finally {
    if (-not (Up) -and (Armed)) { L 'cleanup: not up yet - giving the guard 90 s'; $null = WaitFor { Up } 90 'tunnel back' }
    if (-not (Up)) { L 'cleanup: still down -> Off task (raw internet for the user)'; schtasks /run /tn "$Folder`Off" | Out-Null; Start-Sleep 5 }
    L ("   FINAL vpn={0} armed={1} filters={2} win-tcp={3}" -f (Up), (Armed), (Get-VeroWfpCount), (Tcp 1.1.1.1 443))
    L '=== VERDICT'; foreach ($k in $verdict.Keys) { L ('   {0,-32} {1}' -f $k, $(if ($verdict[$k]) { 'PASS' } else { 'FAIL' })) }
    L 'DONE'
}
