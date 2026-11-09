# Live test of the kill-switch with a Hiddify profile (VPN/TUN mode). Guided: it tells you what to do in Hiddify at each
# step and watches, every 2 s, which address your traffic leaves from. Changes nothing itself: it never touches Hiddify,
# VeroScudo or the network - it only asks https://api.ipify.org (your exit address) and reads VeroScudo's state.
# Writes one log file: %TEMP%\VeroScudo-claude\hiddify-test-<time>.log (named at the end).
#
# 1. Once, with Hiddify DISCONNECTED and VeroScudo OFF - learn your real (ISP) address, so a leak can be recognised:
#      powershell -ExecutionPolicy Bypass -File <repo>\windows\tests-local\Test-Hiddify.ps1 -LearnRealIp
# 2. Hiddify connected (VPN mode), VeroScudo ON with the Hiddify profile:
#      powershell -ExecutionPolicy Bypass -File <repo>\windows\tests-local\Test-Hiddify.ps1
#
# Each sample is one of: VPN <ip> (through Hiddify), BLOCKED (no answer - the kill-switch), LEAK <ip> (your real address -
# must never appear while VeroScudo is on). PASS = no LEAK at all, and Hiddify reconnected while VeroScudo stayed on.
param([switch]$LearnRealIp, [int]$StepSeconds = 30)
$ErrorActionPreference = 'Stop'
$script:Step = $StepSeconds                                             # each step's watch time (most steps)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$dir = Join-Path $env:TEMP 'VeroScudo-claude'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$realFile = Join-Path $dir 'hiddify-test-real-ip.txt'

function Get-ExitIp {
    try { ([string](Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 4)).Trim() } catch { $null }
}

if ($LearnRealIp) {
    $ip = Get-ExitIp
    if (-not $ip) { Write-Host 'No answer - is the network up, Hiddify disconnected and VeroScudo off?' -ForegroundColor Red; exit 1 }
    Set-Content -LiteralPath $realFile -Value $ip -Encoding ASCII
    Write-Host "Your real address: $ip (saved to $realFile). Now connect Hiddify, turn VeroScudo on and run the test without -LearnRealIp."
    exit 0
}

$real = if (Test-Path -LiteralPath $realFile) { (Get-Content -LiteralPath $realFile -Raw).Trim() } else { '' }
if (-not $real) { Write-Host 'Run once with -LearnRealIp first (Hiddify disconnected, VeroScudo off) - otherwise a leak cannot be told apart.' -ForegroundColor Yellow; exit 1 }

$log = Join-Path $dir ('hiddify-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
function Write-TestLog([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color; Add-Content -LiteralPath $log -Value $text }

function Get-State {
    $armed = Test-Path -LiteralPath (Join-Path $env:ProgramData 'VeroScudo\state\armed.flag')
    $active = try { (Get-Content -LiteralPath (Join-Path $env:ProgramData 'VeroScudo\state\active-profile') -Raw).Trim() } catch { '?' }
    $tun = [bool](Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like 'sing-tun*' -and $_.Status -eq 'Up' })
    $app = [bool](Get-Process -Name 'Hiddify', 'HiddifyCli' -ErrorAction SilentlyContinue)
    [pscustomobject]@{ Armed = $armed; Active = $active; Tun = $tun; App = $app }
}

$results = [ordered]@{}
function Watch-Step([string]$name, [string]$todo, [string]$expect, [int]$seconds = $script:Step, [switch]$UntilVpn) {
    Write-TestLog ''
    Write-TestLog "=== $name" 'Cyan'
    Write-TestLog "Do now: $todo" 'White'
    Write-TestLog "Expected: $expect" 'White'
    Read-Host 'Press Enter when you are ready to start watching' | Out-Null
    $r = @{ VPN = 0; BLOCKED = 0; LEAK = 0; FirstVpnAfter = $null }
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $seconds) {
        $ip = Get-ExitIp; $s = Get-State
        $kind = if (-not $ip) { 'BLOCKED' } elseif ($ip -eq $real) { 'LEAK' } else { 'VPN' }
        $r[$kind]++
        if ($kind -eq 'VPN' -and $null -eq $r.FirstVpnAfter) { $r.FirstVpnAfter = [int]((Get-Date) - $start).TotalSeconds }
        $color = switch ($kind) { 'LEAK' { 'Red' } 'BLOCKED' { 'Yellow' } default { 'Green' } }
        Write-TestLog ('{0:HH:mm:ss}  {1,-7} {2,-16} VeroScudo {3,-3} profile {4,-10} Hiddify {5,-3} tunnel {6}' -f (Get-Date), $kind, $(if ($ip) { $ip } else { '-' }),
                   $(if ($s.Armed) { 'on' } else { 'off' }), $s.Active, $(if ($s.App) { 'run' } else { '-' }), $(if ($s.Tun) { 'up' } else { 'down' })) $color
        if ($UntilVpn -and $kind -eq 'VPN') { break }
        Start-Sleep -Seconds 2
    }
    $results[$name] = $r
    Write-TestLog ('-> VPN {0}, BLOCKED {1}, LEAK {2}{3}' -f $r.VPN, $r.BLOCKED, $r.LEAK, $(if ($null -ne $r.FirstVpnAfter) { ", first VPN answer after $($r.FirstVpnAfter) s" } else { '' }))
}

$s = Get-State
Write-TestLog "Hiddify kill-switch test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - real address $real" 'Cyan'
Write-TestLog ('Start: VeroScudo {0}, active profile {1}, Hiddify {2}, tunnel {3}' -f $(if ($s.Armed) { 'ON' } else { 'OFF' }), $s.Active, $(if ($s.App) { 'running' } else { 'not running' }), $(if ($s.Tun) { 'up' } else { 'down' }))
if (-not $s.Armed -or -not $s.Tun) { Write-TestLog 'Before starting: connect Hiddify (VPN mode) and turn VeroScudo on with the Hiddify profile.' 'Yellow' }

Watch-Step '1 baseline' 'nothing - Hiddify connected, VeroScudo on' 'VPN only' 20
Watch-Step '2 disconnect in Hiddify' 'press Disconnect in Hiddify (leave the app open)' 'BLOCKED only - never LEAK'
Watch-Step '3 reconnect in Hiddify' 'press Connect in Hiddify (VeroScudo stays on)' 'BLOCKED, then VPN within ~30 s - Hiddify must be able to connect while VeroScudo is on' 90 -UntilVpn
Watch-Step '4 change server in Hiddify' 'pick another server or group in Hiddify' 'VPN (maybe a short BLOCKED), never LEAK'
Watch-Step '5 quit Hiddify' 'quit Hiddify completely (tray icon > Exit)' 'BLOCKED only - never LEAK'
Watch-Step '6 start Hiddify again' 'start Hiddify and connect it (VPN mode)' 'BLOCKED, then VPN' 120 -UntilVpn
Watch-Step '7 VeroScudo off' 'Turn VPN off in VeroScudo (Hiddify stays connected)' 'VPN (Hiddify still works, VeroScudo off) - not your real address' 20

$leaks = 0; foreach ($r in $results.Values) { $leaks += [int]$r['LEAK'] }            # hashtables: no properties for Measure-Object
$recon = $results['3 reconnect in Hiddify'].FirstVpnAfter
$restart = $results['6 start Hiddify again'].FirstVpnAfter
Write-TestLog ''
Write-TestLog '=== Result' 'Cyan'
Write-TestLog ("leaks: $leaks; reconnect while on: " + $(if ($null -ne $recon) { "$recon s" } else { 'NO' }) + '; restart while on: ' + $(if ($null -ne $restart) { "$restart s" } else { 'NO' }))
if ($leaks -eq 0 -and $null -ne $recon -and $null -ne $restart) { Write-TestLog 'PASS' 'Green' } else { Write-TestLog 'FAIL - send me the log' 'Red' }
Write-TestLog "Log: $log"
