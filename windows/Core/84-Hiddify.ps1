# VeroScudo core, part 84: Hiddify in VPN (TUN) mode - kill-switch only.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.
#
# Hiddify (a GUI around hiddify-core, a sing-box fork) runs its proxies inside Hiddify.exe and, in VPN mode, a Wintun
# adapter described "sing-tun Tunnel" that carries the default route and DNS (seen live, Hiddify 4.1.1). Its servers are
# many (selector/balancer groups), change with each subscription update and use TCP and UDP (VLESS, Hysteria, QUIC) - so
# the permit is not "these servers" but "this program": Hiddify.exe and HiddifyCli.exe from the Hiddify folder may reach
# anything, everything else only goes through the tunnel. The folder must be administrators-only (Program Files): a
# writable folder would let any program be planted there under that name. VeroScudo never starts or stops Hiddify:
# connect, disconnect and reconnect in Hiddify; while its tunnel is down everything else stays blocked.

$script:HiddifyExes = @('Hiddify.exe', 'HiddifyCli.exe')
$script:HiddifyTunPattern = '^sing-tun'                                  # the Wintun adapter's description in VPN mode
$script:HiddifyWaitLogged = $false

function Get-VeroHiddifyDir {
    <# Where Hiddify is installed: its uninstall entry (HKLM - written by its installer as administrator), else the default
       Program Files folder. $null when there is no Hiddify.exe. #>
    $cands = @()
    foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        foreach ($e in @(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and [string]$_.DisplayName -match '^Hiddify' -and $_.PSObject.Properties['InstallLocation'] -and $_.InstallLocation })) {
            $cands += [string]$e.InstallLocation
        }
    }
    $cands += Join-Path (Get-VeroSystemDir ProgramFiles) 'Hiddify'
    foreach ($d in $cands) { if ($d -and (Test-Path -LiteralPath (Join-Path $d 'Hiddify.exe'))) { return ([IO.Path]::GetFullPath($d)).TrimEnd('\') } }
    $null
}

function Get-VeroHiddifyApps {
    <# The programs the kill-switch lets out for a Hiddify profile: Hiddify.exe and HiddifyCli.exe - only when their folder
       and its parents are administrators-only. Empty = nothing is let out but the tunnel (logged once by the caller). #>
    $dir = Get-VeroHiddifyDir
    if (-not $dir) { return @() }
    if (Test-VeroAdminOnlyPath -Path (Join-Path $dir 'Hiddify.exe')) { return @() }
    if (-not (Test-VeroAdminOnlyRules @((Get-Acl -LiteralPath $dir).Access | ForEach-Object { $_ }))) { return @() }
    @(foreach ($n in $script:HiddifyExes) { $p = Join-Path $dir $n; if (Test-Path -LiteralPath $p) { $p } })
}

function Get-VeroHiddifyNic {
    <# Hiddify's tunnel adapter while it is up, else $null. #>
    Get-VeroNic | Where-Object { [string]$_.Description -match $script:HiddifyTunPattern -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
}

function Test-VeroHiddifyRunning {
    [bool](Get-Process -Name 'Hiddify', 'HiddifyCli' -ErrorAction SilentlyContinue)
}

function Test-VeroHiddifyConnected {
    <# Connected = Hiddify runs and its tunnel adapter is up (VPN mode). #>
    [bool]((Get-VeroHiddifyNic) -and (Test-VeroHiddifyRunning))
}

function Get-VeroHiddifyTunnelLuid {
    if (-not (Test-VeroHiddifyRunning)) { return [uint64]0 }
    $nic = Get-VeroHiddifyNic
    if ($nic) { [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) } else { [uint64]0 }
}

function Get-VeroHiddifyPermit {
    <# The filters' permit for a Hiddify profile: its programs, to any address (see the top of this file). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $apps = @(Get-VeroHiddifyApps)
    if ($apps.Count -eq 0 -and -not $script:HiddifyAppsMissingLogged) {
        Write-VeroLog "WARNING: '$($Config.Profile)': Hiddify.exe not found in an administrators-only folder (Program Files) - nothing but its tunnel is allowed, so Hiddify cannot connect while VeroScudo is on" $Action
    }
    $script:HiddifyAppsMissingLogged = ($apps.Count -eq 0)
    @{ Kind = 'program'; Ips = @(); Endpoints = $null; App = ''; Apps = $apps }
}

function Invoke-VeroHiddifyDial {
    <# VeroScudo never connects Hiddify: it waits a few seconds for you to connect it in Hiddify (logged once per drop). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if (-not $script:HiddifyWaitLogged) {
        Write-VeroLog "'$($Config.Profile)': Hiddify is not connected - connect it in Hiddify (VPN mode); traffic stays blocked meanwhile" $Action
        $script:HiddifyWaitLogged = $true
    }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 5) {
        if (Test-VeroHiddifyConnected) { $script:HiddifyWaitLogged = $false; return }
        if (Get-VeroPendingSwitch) { return }
        Start-Sleep -Seconds 1
    }
}

function Get-VeroHiddifyMode {
    <# 'vpn' / 'proxy' / ... from Hiddify's settings of the user running this (the tray), $null when not found. Only VPN mode
       (a tunnel adapter) can be protected. #>
    [CmdletBinding()] param([string]$AppData = $env:APPDATA)
    foreach ($p in (Join-Path $AppData 'Hiddify\hiddify\shared_preferences.json'), (Join-Path $AppData 'Hiddify\shared_preferences.json')) {
        try { $j = [IO.File]::ReadAllText($p) | ConvertFrom-Json } catch { continue }
        if ($j -and $j.PSObject.Properties['flutter.service-mode']) { return [string]$j.'flutter.service-mode' }
    }
    $null
}

function Get-VeroHiddifyOffer {
    <# Import (tray): Hiddify as one more profile to offer, or $null when it is not installed. @{ Name; Mode; Ok; Note } #>
    if (-not (Get-VeroHiddifyDir)) { return $null }
    $mode = Get-VeroHiddifyMode
    $ok = ($null -eq $mode) -or ($mode -eq 'vpn')
    [pscustomobject]@{ Name = 'Hiddify'; Mode = $mode; Ok = $ok
                       Note = $(if ($ok) { 'VPN mode - connect and reconnect it in Hiddify' } else { "Hiddify is in $mode mode - switch it to VPN mode (only VPN mode is supported)" }) }
}

$script:HiddifySeen = $null
function Update-VeroHiddifyWatch {
    <# Watchdog: Hiddify's tunnel BECAME connected since the last pass while a Hiddify profile is configured and not the armed,
       active one - VeroScudo turns on for it, like a Windows VPN or WireGuard tunnel you connect yourself. Edges only: the
       first look after start changes nothing; never right after your Off, never during our own redial or switch. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $pr = @($Config.Profiles | Where-Object Type -eq 'hiddify') | Select-Object -First 1
    if (-not $pr) { $script:HiddifySeen = $null; return $false }
    $cur = Test-VeroHiddifyConnected
    $prev = $script:HiddifySeen
    $script:HiddifySeen = $cur
    if ($null -eq $prev -or $prev -or -not $cur) { return $false }
    if ((Test-VeroArmed) -and $Config.Profile -eq $pr.Profile) { return $false }   # already protected by it
    if (Test-VeroRecentOff) { return $false }
    if (Test-VeroLockAlive) { return $false }
    Write-VeroLog "Hiddify connected (VPN mode) - kill-switch on for '$($pr.Profile)' (decision source: watchdog saw its tunnel come up)" $Action
    if ($pr.Profile -ne $Config.Profile) { Set-VeroActiveProfile -Name $pr.Profile -Action $Action }
    Invoke-VeroArmConnected -Config (Get-VeroConfig) -Action $Action
    $true
}
