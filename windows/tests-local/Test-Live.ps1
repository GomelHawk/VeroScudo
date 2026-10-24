#Requires -RunAsAdministrator
# LIVE end-to-end verification through the real scheduled tasks. The harness only breaks the link / runs tasks and observes. ~7 min.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'WslUser', Justification = 'used inside nested function')]
param([string]$WslUser = $env:USERNAME)
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-live.log'; '' | Set-Content $Out
$ServerIps = Resolve-VeroServerIp $cfg.Server; $BlockRule = 'VeroScudo - TEST block server'; $Folder = '\VeroScudo\'
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected $cfg.Profile }
function Armed { Test-Path $p.ArmedFlag }
function Outb { ((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction | Select-Object -Unique) -join ',') }
function Tcp($ip, $port, $ms = 2500) { try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function Wsl { if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }; $r = (wsl.exe -u $WslUser -e curl -s -m 3 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>$null) -join ''; $r -in '200','301' }
function Dns { try { $null = Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction Stop; $true } catch { $false } }
function Ping8 { Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue }
function Wifi { Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' } | Select-Object -First 1 }
function Probe($tag) { L ("   {0} vpn={1} armed={2} outbound={3} | leaks: tcp443={4} tcp80={5} ping={6} wsl={7} | dns={8}" -f $tag, (Up), (Armed), (Outb), (Tcp 1.1.1.1 443), (Tcp 1.1.1.1 80), (Ping8), (Wsl), (Dns)) }
function BounceWifi { $w = Wifi; if (-not $w) { L '   no Wi-Fi adapter up - skipping bounce'; return }
    $ssid = ((netsh wlan show interfaces | Select-String '^\s*SSID\s*:') -split ':\s*', 2)[1].Trim()
    netsh wlan disconnect interface="$($w.Name)" | Out-Null; Start-Sleep 5; netsh wlan connect name="$ssid" interface="$($w.Name)" | Out-Null; L "   wifi bounced ($ssid)" }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) { $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt $sec) { if (& $cond) { L ("   {0} after {1:N0}s" -f $what, ((Get-Date) - $t).TotalSeconds); return $true }; Start-Sleep 2 }; L "   TIMEOUT: $what ($sec s)"; $false }
$verdict = [ordered]@{}; $t0 = Get-Date
try {
    L '=== PRECONDITION'; Probe 'base'
    if (-not (Up) -or -not (Armed)) { L 'ABORT: need VPN up + armed (run the On task first)'; return }
    L '=== PHASE 1: STRICT - server unreachable + link bounce; must stay blocked 3 min (incl. a watchdog run)'
    New-NetFirewallRule -DisplayName $BlockRule -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $ServerIps -RemotePort $cfg.Port -Profile Any | Out-Null
    BounceWifi; $dropped = WaitFor { -not (Up) } 60 'tunnel dropped'
    $leak = $false; $unblocked = $false; $t = Get-Date; $i = 0
    while (((Get-Date) - $t).TotalSeconds -lt 180) {
        $i++; Probe ("STRICT t+{0:N0}s" -f ((Get-Date) - $t).TotalSeconds)
        if ((Tcp 1.1.1.1 443) -or (Tcp 1.1.1.1 80) -or (Wsl)) { $leak = $true }
        if ((Outb) -ne 'Block' -or -not (Armed)) { $unblocked = $true }
        if ($i -eq 6) { schtasks /run /tn "$Folder`Watchdog" | Out-Null; L '   (watchdog triggered)' }
        Start-Sleep 12
    }
    L "   leak=$leak unblocked=$unblocked vpnUp=$(Up) (all must be False)"
    $verdict['1 strict outage'] = ($dropped -and -not $leak -and -not $unblocked -and -not (Up))
    Remove-NetFirewallRule -DisplayName $BlockRule; L '   server unblocked -> guard must reconnect by itself'
    $back = WaitFor { Up } 120 'tunnel back'; Start-Sleep 8; Probe 'UP'
    $verdict['1 auto-recover'] = ($back -and (Tcp 1.1.1.1 443) -and (Armed) -and (Outb) -eq 'Block')
    L '=== PHASE 2: Off task -> raw internet; On task -> protected'
    schtasks /run /tn "$Folder`Off" | Out-Null; $off = WaitFor { -not (Up) -and -not (Armed) -and (Outb) -ne 'Block' } 40 'off+disarmed'; Start-Sleep 3; Probe 'OFF'
    $verdict['2 off'] = ($off -and (Tcp 1.1.1.1 443))
    schtasks /run /tn "$Folder`On" | Out-Null; $on = WaitFor { (Up) -and (Armed) -and (Outb) -eq 'Block' } 90 'on+armed'; Start-Sleep 8; Probe 'ON'
    $verdict['2 on'] = ($on -and (Tcp 1.1.1.1 443))
    L '=== PHASE 3: manual disconnect (rasdial = Settings UI, RAS 631) -> guard disarms; then On'
    rasdial.exe $cfg.Profile /disconnect | Out-Null; $dis = WaitFor { -not (Armed) -and (Outb) -ne 'Block' } 40 'disarmed by 631'; Start-Sleep 3; Probe 'MANUAL-OFF'
    $verdict['3 manual disconnect'] = ($dis -and (Tcp 1.1.1.1 443))
    schtasks /run /tn "$Folder`On" | Out-Null; $on = WaitFor { (Up) -and (Armed) -and (Outb) -eq 'Block' } 90 'on+armed'; Start-Sleep 5; Probe 'ON'
    $verdict['3 on'] = $on
} finally {
    Get-NetFirewallRule -DisplayName $BlockRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (-not (Up) -and (Armed)) { L 'cleanup: VPN down & armed -> giving the guard 90 s'; WaitFor { Up } 90 'tunnel back' | Out-Null }
    if (-not (Up)) { L 'cleanup: still down -> Off task (raw internet for the user)'; schtasks /run /tn "$Folder`Off" | Out-Null; Start-Sleep 10 }
    L '=== VERDICT'; foreach ($k in $verdict.Keys) { L ('   {0,-22} {1}' -f $k, $(if ($verdict[$k]) { 'PASS' } else { 'FAIL' })) }
    Probe 'FINAL'
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=$t0} -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4003 } | ForEach-Object { L ('   WLAN 4003 at {0:HH:mm:ss}' -f $_.TimeCreated) }
    L 'DONE'
}
