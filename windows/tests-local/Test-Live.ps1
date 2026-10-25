#Requires -RunAsAdministrator
# LIVE end-to-end verification through the real scheduled tasks. The harness only breaks the link / runs tasks and observes. ~10 min.
# Restores the machine in `finally`. Paste the VERDICT block into your PR.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'WslUser', Justification = 'used inside nested function')]
param([string]$WslUser = $env:USERNAME)
$ErrorActionPreference = 'Continue'
Import-Module "$PSScriptRoot\..\VeroScudo.Core.psm1" -Force
$cfg = Get-VeroConfig; $p = Get-VeroPath; $Out = Join-Path $p.State 'test-live.log'; '' | Set-Content $Out
$ServerIps = Resolve-VeroServerIp -Config $cfg; $BlockRule = 'VeroScudo - TEST block server'; $AllowRule = 'VeroScudo - TEST allow powershell'; $Folder = '\VeroScudo\'
$PsExe = (Get-Process -Id $PID).Path
$LanDns = @(Get-VeroDnsServer -ProfileName $cfg.Profile | Where-Object { $_ -notmatch ':' } | Select-Object -First 1)
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
function Up { Test-VeroVpnConnected (Get-VeroConfig).Profile }
function Armed { Test-Path $p.ArmedFlag }
function Filters { Get-VeroWfpCount }
function Tcp($ip, $port, $ms = 2500) { try { $c = New-Object Net.Sockets.TcpClient($(if ($ip -match ':') { 'InterNetworkV6' } else { 'InterNetwork' })); $ok = $c.ConnectAsync($ip, $port).Wait($ms) -and $c.Connected; $c.Close(); $ok } catch { $false } }
function Wsl { if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }; $r = (wsl.exe -u $WslUser -e curl -s -m 3 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>$null) -join ''; $r -in '200','301' }
function Dns { try { $null = Resolve-DnsName example.com -Type A -DnsOnly -QuickTimeout -ErrorAction Stop; $true } catch { $false } }
function LanDnsQuery { if (-not $LanDns) { return $false }; try { $null = Resolve-DnsName www.example.com -Server $LanDns[0] -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop; $true } catch { $false } }
function Ping8 { Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue }
function Leaks {
    # everything that must be False while blocked; the allow-rule probe runs from this PowerShell, which has its own firewall allow rule
    [ordered]@{ tcp443 = (Tcp 1.1.1.1 443); tcp80 = (Tcp 1.1.1.1 80); tcp53 = (Tcp 1.1.1.1 53); ipv6 = (Tcp '2606:4700:4700::1111' 443); ping = (Ping8); wsl = (Wsl) }
}
function Probe($tag) { $k = Leaks; L ("   {0} vpn={1} armed={2} filters={3} | leaks: {4} | dns={5}" -f $tag, (Up), (Armed), (Filters), (($k.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '), (Dns)); $k }
function Wifi { Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' } | Select-Object -First 1 }
function BounceWifi { $w = Wifi; if (-not $w) { L '   no Wi-Fi adapter up - skipping bounce'; return }
    $ssid = ((netsh wlan show interfaces | Select-String '^\s*SSID\s*:') -split ':\s*', 2)[1].Trim()
    netsh wlan disconnect interface="$($w.Name)" | Out-Null; Start-Sleep 5; netsh wlan connect name="$ssid" interface="$($w.Name)" | Out-Null; L "   wifi bounced ($ssid)" }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) { $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt $sec) { if (& $cond) { L ("   {0} after {1:N0}s" -f $what, ((Get-Date) - $t).TotalSeconds); return $true }; Start-Sleep 2 }; L "   TIMEOUT: $what ($sec s)"; $false }
$verdict = [ordered]@{}; $t0 = Get-Date
$fwBefore = Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction
try {
    L '=== PRECONDITION'; $null = Probe 'base'
    if (-not (Up) -or -not (Armed)) { L 'ABORT: need VPN up + armed (run the On task first)'; return }
    L "   watchdog task: $((Get-ScheduledTask -TaskPath $Folder -TaskName Watchdog).State) ; LAN resolver: $($LanDns -join ',')"
    New-NetFirewallRule -DisplayName $AllowRule -Direction Outbound -Action Allow -Program $PsExe -Profile Any | Out-Null
    L "   test allow rule for $PsExe created (1.0 leaked through rules like this)"

    L '=== PHASE 0: PROTECTED - no DNS leak to the local network, forged 631 ignored'
    $leakDns = LanDnsQuery; L "   query to LAN resolver $($LanDns -join ',') while protected answered=$leakDns (must be False)"
    $verdict['0 no DNS leak while protected'] = (-not $leakDns)
    $coid = [string](Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267 } -MaxEvents 1).Properties[0].Value
    [Diagnostics.EventLog]::WriteEvent('RasClient', (New-Object Diagnostics.EventInstance(20226, 0, 'Information')), @($coid, "$env:USERDOMAIN\$env:USERNAME", $cfg.Profile, '631'))
    L "   forged RasClient 20226 code 631 for $coid"; Start-Sleep 20
    $verdict['0 forged 631 ignored'] = ((Armed) -and (Up) -and (Filters) -gt 0)
    L "   armed=$(Armed) vpn=$(Up) filters=$(Filters)"

    L '=== PHASE 1: STRICT - server unreachable + link bounce; must stay blocked 3 min (incl. a firewall-default reset)'
    New-NetFirewallRule -DisplayName $BlockRule -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $ServerIps -RemotePort $cfg.Port -Profile Any | Out-Null
    BounceWifi; $dropped = WaitFor { -not (Up) } 60 'tunnel dropped'
    $leak = $false; $unblocked = $false; $t = Get-Date; $i = 0
    while (((Get-Date) - $t).TotalSeconds -lt 180) {
        $i++; $k = Probe ("STRICT t+{0:N0}s" -f ((Get-Date) - $t).TotalSeconds)
        if ($k.Values -contains $true) { $leak = $true }
        if ((Filters) -eq 0 -or -not (Armed)) { $unblocked = $true }
        if ($i -eq 4) { Set-NetFirewallProfile -All -DefaultOutboundAction Allow; L '   (firewall default outbound forced to Allow - as a GPO refresh would)' }
        if ($i -eq 6) { schtasks /run /tn "$Folder`Watchdog" | Out-Null; L '   (watchdog triggered)' }
        Start-Sleep 12
    }
    L "   leak=$leak unblocked=$unblocked vpnUp=$(Up) (all must be False)"
    $verdict['1 strict outage'] = ($dropped -and -not $leak -and -not $unblocked -and -not (Up))

    L '=== PHASE 2: SELF-HEAL - filters deleted while blocked must be restored by the watchdog within 30 s'
    Clear-VeroWfpFilter; L '   all VeroScudo filters deleted'
    $healed = WaitFor { (Filters) -gt 0 } 30 'filters restored'
    Start-Sleep 2; $k = Probe 'HEALED'
    $verdict['2 self-heal'] = ($healed -and -not ($k.Values -contains $true))

    Remove-NetFirewallRule -DisplayName $BlockRule; L '   server unblocked -> guard must reconnect by itself'
    $back = WaitFor { Up } 120 'tunnel back'; Start-Sleep 8; $null = Probe 'UP'
    $verdict['1 auto-recover'] = ($back -and (Tcp 1.1.1.1 443) -and (Armed) -and (Filters) -gt 0)

    if (@($cfg.Profiles).Count -ge 2) {
        $other = @($cfg.Profiles | Where-Object Profile -ne $cfg.Profile)[0].Profile
        L "=== PHASE 3: PROFILE SWITCH '$($cfg.Profile)' -> '$other' -> back; blocked in between"
        foreach ($target in $other, $cfg.Profile) {
            Set-Content (Get-VeroPath).SwitchRequest $target; schtasks /run /tn "$Folder`Switch" | Out-Null
            $sw = Get-Date; $swLeak = $false
            while (((Get-Date) - $sw).TotalSeconds -lt 90 -and -not ((Get-VeroConfig).Profile -eq $target -and (Up))) {
                if (-not (Up) -and ((Tcp 1.1.1.1 443) -or (Tcp 1.1.1.1 80))) { $swLeak = $true }
                Start-Sleep 1
            }
            $ok = ((Get-VeroConfig).Profile -eq $target) -and (Up) -and (Armed)
            L "   -> '$target' connected=$ok leak-while-switching=$swLeak"
            $verdict["3 switch to $target"] = ($ok -and -not $swLeak)
        }
    } else { L '=== PHASE 3: profile switch skipped (only one profile configured)' }

    L '=== PHASE 4: Off task -> raw internet; On task -> protected'
    schtasks /run /tn "$Folder`Off" | Out-Null; $off = WaitFor { -not (Up) -and -not (Armed) -and (Filters) -eq 0 } 40 'off+disarmed'; Start-Sleep 3; $null = Probe 'OFF'
    $verdict['4 off'] = ($off -and (Tcp 1.1.1.1 443))
    schtasks /run /tn "$Folder`On" | Out-Null; $on = WaitFor { (Up) -and (Armed) -and (Filters) -gt 0 } 90 'on+armed'; Start-Sleep 8; $null = Probe 'ON'
    $verdict['4 on'] = ($on -and (Tcp 1.1.1.1 443))
    L '=== PHASE 5: manual disconnect (rasdial = Settings UI, RAS 631) -> guard disarms; then On'
    rasdial.exe $cfg.Profile /disconnect | Out-Null; $dis = WaitFor { -not (Armed) -and (Filters) -eq 0 } 40 'disarmed by 631'; Start-Sleep 3; $null = Probe 'MANUAL-OFF'
    $verdict['5 manual disconnect'] = ($dis -and (Tcp 1.1.1.1 443))
    schtasks /run /tn "$Folder`On" | Out-Null; $on = WaitFor { (Up) -and (Armed) -and (Filters) -gt 0 } 90 'on+armed'; Start-Sleep 5; $null = Probe 'ON'
    $verdict['5 on'] = $on
} finally {
    Get-NetFirewallRule -DisplayName $BlockRule, $AllowRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($pr in $fwBefore) { Set-NetFirewallProfile -Name $pr.Name -DefaultOutboundAction ([string]$pr.DefaultOutboundAction) }
    if (-not (Up) -and (Armed)) { L 'cleanup: VPN down & armed -> giving the guard 90 s'; WaitFor { Up } 90 'tunnel back' | Out-Null }
    if (-not (Up)) { L 'cleanup: still down -> Off task (raw internet for the user)'; schtasks /run /tn "$Folder`Off" | Out-Null; Start-Sleep 10 }
    L '=== VERDICT'; foreach ($k in $verdict.Keys) { L ('   {0,-30} {1}' -f $k, $(if ($verdict[$k]) { 'PASS' } else { 'FAIL' })) }
    $null = Probe 'FINAL'
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=$t0} -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4003 } | ForEach-Object { L ('   WLAN 4003 at {0:HH:mm:ss}' -f $_.TimeCreated) }
    L 'DONE'
}
