# VeroScudo core, part 85: conflicts: other VPNs and kill-switches next to VeroScudo.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- conflicts: other VPNs and kill-switches next to VeroScudo
$script:KillSwitchWords = 'WireGuard|OpenVPN|PrivateVPN|Hiddify|sing-box|sing-tun|NordVPN|ExpressVPN|Mullvad|Proton|Surfshark|Private Internet Access|CyberGhost|Windscribe|IVPN|Astrill|Cloudflare WARP'
function Get-VeroConflict {
    <# Read-only: what else is tunnelling or filtering next to VeroScudo. Each item is one human-readable line. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $type = Get-VeroConfigType $Config
    $items = New-Object System.Collections.Generic.List[string]
    # 1. every other connected VPN (Windows VPN, WireGuard, openvpn.exe, vendor apps' adapters)
    foreach ($f in @(Get-VeroForeignVpn -Config $Config)) { $items.Add((Format-VeroForeignVpn $f) + ' - VeroScudo blocks its traffic while it is on') }
    # 2. our OpenVPN configs also present in OpenVPN GUI / the OpenVPN service folders (same servers)
    $ovpnProfiles = @($Config.Profiles | Where-Object Type -eq 'openvpn')
    if ($ovpnProfiles.Count -gt 0) {
        $dirs = @()
        try { $u = Get-ItemProperty 'HKCU:\Software\OpenVPN-GUI' -ErrorAction Stop; if ($u.PSObject.Properties['config_dir']) { $dirs += [Environment]::ExpandEnvironmentVariables([string]$u.config_dir) } } catch { Write-Verbose 'no OpenVPN-GUI key' }
        $dirs += (Join-Path $env:USERPROFILE 'OpenVPN\config')
        $auto = Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\config-auto'
        try { $k = Get-ItemProperty 'HKLM:\SOFTWARE\OpenVPN' -ErrorAction Stop; if ($k.PSObject.Properties['config_dir']) { $dirs += [string]$k.config_dir }; if ($k.PSObject.Properties['autostart_config_dir']) { $auto = [string]$k.autostart_config_dir } } catch { Write-Verbose 'no OpenVPN key' }
        $dirs += (Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\config')
        foreach ($pr in $ovpnProfiles) {
            $mine = @(Get-VeroOpenVpnRemote -ProfileName $pr.Profile | ForEach-Object { '{0}:{1}' -f $_.Host, $_.Port }) | Sort-Object
            if ($mine.Count -eq 0) { continue }
            foreach ($d in @($dirs + $auto | Select-Object -Unique)) {
                if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
                # the folder and its direct subfolders only, never through junctions/links: these folders belong to the user,
                # and a junction to C:\ must not turn this admin-run check into a disk scan every minute
                $where = @($d) + @(Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Select-Object -First 20 | ForEach-Object FullName)
                $files = @(foreach ($w in $where) { Get-ChildItem -LiteralPath $w -Filter '*.ovpn' -File -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } })
                foreach ($f in @($files | Select-Object -First 50)) {
                    $theirs = @((Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($f.FullName)) -ReadFile { param($x) $null = $x; [byte[]]@() }).Remotes | ForEach-Object { '{0}:{1}' -f $_.Host, $_.Port }) | Sort-Object
                    if ($theirs.Count -gt 0 -and (@($theirs | Where-Object { $mine -contains $_ }).Count -gt 0)) {
                        $where = if ($d -eq $auto) { 'the OpenVPN service starts it by itself' } else { "OpenVPN GUI lists it - don't connect it there" }
                        $items.Add("'$($f.Name)' has the same server as '$($pr.Profile)': $where")
                    }
                }
            }
        }
    }
    # 5. other apps' kill-switch filter layers (WFP providers)
    try {
        Import-VeroNative
        foreach ($i in @(Select-VeroForeignWfp -Type $type -Providers @([VeroScudo.Wfp]::Providers()) -SubLayers @([VeroScudo.Wfp]::SubLayers()))) { $items.Add($i) }
    } catch { Write-Verbose "WFP providers: $($_.Exception.Message)" }
    @($items | Select-Object -Unique)
}

function Select-VeroForeignWfp {
    <# Pure. Other apps' WFP kill-switch layers worth a warning. Providers: names; SubLayers: "weight|name". The active
       profile's own client (WireGuard app, OpenVPN) is not "another app" - its layer is expected while its tunnel runs. #>
    [CmdletBinding()] param([string]$Type, [string[]]$Providers = @(), [string[]]$SubLayers = @())
    $own = (Get-VeroTypeHandler $Type).OwnLayer
    foreach ($n in $Providers) {
        if ($n -notmatch $script:KillSwitchWords) { continue }
        if ($own -and $n -match $own) { continue }
        "another app's filter layer is installed: '$n'"
    }
    # a sublayer with the same top weight as ours: WFP evaluates equal weights in no defined order, so its hard permits
    # could be seen before our block
    foreach ($sl in $SubLayers) {
        $parts = $sl -split '\|', 2
        if ($parts.Count -lt 2 -or [int]$parts[0] -lt 0xFFFF) { continue }
        if ($own -and $parts[1] -match $own) { continue }
        "another filter layer has the same top priority as VeroScudo's: '$($parts[1])' - its rules may win"
    }
}

function Get-VeroForeignVpn {
    <# Every VPN that is connected right now and is NOT the active profile's tunnel: another Windows VPN, a WireGuard tunnel,
       an openvpn.exe VeroScudo did not start, or a vendor app's tunnel adapter. Read-only, works without admin rights (the
       tray asks before Turn on). @{ Name; Kind ('ras'|'wireguard'|'openvpn'|'app'); Configured; CanDisconnect; Id }. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $type = Get-VeroConfigType $Config
    $names = @($Config.Profiles | ForEach-Object Profile)
    $out = New-Object System.Collections.Generic.List[object]
    $rasUp = @(Get-VeroWindowsVpn | Where-Object { $_.Connected })
    foreach ($v in $rasUp) {
        if ($type -eq 'ras' -and $v.Name -eq $Config.Profile) { continue }
        $out.Add([pscustomobject]@{ Name = $v.Name; Kind = 'ras'; Configured = ($names -contains $v.Name); CanDisconnect = $true; Id = $v.Name })
    }
    $wgUp = @(Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Status -eq 'Running' } | ForEach-Object { $_.Name.Substring(16) })
    foreach ($n in $wgUp) {
        if ($type -eq 'wireguard' -and $n -eq $Config.Profile) { continue }
        $out.Add([pscustomobject]@{ Name = $n; Kind = 'wireguard'; Configured = ($names -contains $n); CanDisconnect = $true; Id = $n })
    }
    $ours = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'openvpn')) { $st = Get-VeroOpenVpnStatus $pr.Profile; if ($st -and $st.OvpnPid) { [int]$st.OvpnPid } })
    $ovpnForeign = @(Get-Process -Name openvpn -ErrorAction SilentlyContinue | Where-Object { $ours -notcontains $_.Id })
    foreach ($proc in $ovpnForeign) { $out.Add([pscustomobject]@{ Name = "OpenVPN (PID $($proc.Id))"; Kind = 'openvpn'; Configured = $false; CanDisconnect = $true; Id = [string]$proc.Id }) }
    # vendor apps: a tunnel adapter that is up and belongs to none of the above (and is not ours)
    $ownRunner = ($type -eq 'openvpn') -and (Test-VeroOpenVpnRunnerAlive)
    # VeroScudo's own OpenVPN tunnels, by the adapter that holds the address OpenVPN reported: the runner's lock above is
    # per session and invisible to the tray (it would list VeroScudo's own TAP adapter as "a VPN app")
    $ownNics = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'openvpn')) { $n = Get-VeroOpenVpnNic $pr.Profile; if ($n) { [string]$n.Id } })
    foreach ($nic in @(Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and (Test-VeroTunnelAdapter $_) })) {
        if ([string]$nic.NetworkInterfaceType -eq 'Ppp') { continue }                                       # Windows VPN: listed by name above
        if ($ownNics -contains [string]$nic.Id) { continue }
        if ([string]$nic.Description -like 'WireGuard*' -and ($wgUp -contains $nic.Name -or ($type -eq 'wireguard' -and $nic.Name -eq $Config.Profile))) { continue }
        if ([string]$nic.Description -match $script:HiddifyTunPattern) {          # Hiddify in VPN mode: named, never "an app's tunnel"
            if ($type -ne 'hiddify') {
                $out.Add([pscustomobject]@{ Name = 'Hiddify (VPN mode)'; Kind = 'hiddify'; Configured = [bool]@($Config.Profiles | Where-Object Type -eq 'hiddify'); CanDisconnect = $false; Id = 'hiddify' })
            }
            continue
        }
        $isOvpnAdapter = [string]$nic.Description -match 'TAP-Windows|Wintun|OpenVPN|Data Channel Offload|ovpn-dco'
        if ($isOvpnAdapter -and ($ownRunner -or $ovpnForeign.Count -gt 0)) { continue }
        $out.Add([pscustomobject]@{ Name = "$($nic.Name) ($($nic.Description))"; Kind = 'app'; Configured = $false; CanDisconnect = $false; Id = [string]$nic.Name })
    }
    $out.ToArray()                                                          # callers wrap it in @()
}

function Format-VeroForeignVpn($F) {
    <# One line for the log, the tray and the status window. Pure. #>
    if ($script:Types -contains [string]$F.Kind) { return (& (Get-VeroTypeHandler $F.Kind).ForeignText $F) }
    "a VPN app's tunnel is up: $($F.Name) - VeroScudo cannot disconnect it, close that app"
}

function Stop-VeroForeignOpenVpn($F) {
    <# An openvpn.exe VeroScudo did not start: through OpenVPN GUI when it runs, else the process itself. #>
    $gui = Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\bin\openvpn-gui.exe'
    if ((Get-Process -Name 'openvpn-gui' -ErrorAction SilentlyContinue) -and (Test-Path $gui)) { Start-Process -FilePath $gui -ArgumentList '--command disconnect_all' -WindowStyle Hidden; Start-Sleep -Seconds 3 }
    $proc = Get-Process -Id ([int]$f.Id) -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -eq 'openvpn') { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

function Disconnect-VeroForeignVpn {
    <# Only on your choice (tray "Disconnect ... and turn on", -DisconnectOthers): ends every other connected VPN it can,
       each the way its own client does. Returns the ones it could not end (vendor apps). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'on')
    $left = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-VeroForeignVpn -Config $Config)) {
        if (-not $f.CanDisconnect) { $left.Add($f); continue }             # a VPN app's own tunnel (NB: not inside the switch)
        & (Get-VeroTypeHandler $f.Kind).ForeignHangUp $f
        Write-VeroLog "disconnected: $(Format-VeroForeignVpn $f) - you chose it (Disconnect and turn on)" $Action
    }
    $left.ToArray()
}

function Update-VeroConflict {
    <# Watchdog: refreshes state\conflicts.json (the tray shows it) and logs when the list changes. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $items = @(Get-VeroConflict -Config $Config)
    $p = Get-VeroPath
    $old = @(Get-VeroConflictList)
    if (($old -join "`n") -ne ($items -join "`n")) {
        if ($items.Count -gt 0) { Write-VeroLog ("ATTENTION: {0}" -f ($items -join ' | ')) $Action } else { Write-VeroLog 'no other VPN or kill-switch next to VeroScudo any more' $Action }
    }
    @{ Time = (Get-Date).ToString('o'); Items = $items } | ConvertTo-Json -Depth 3 | Set-Content $p.Conflicts
}

function Get-VeroConflictList {
    $f = (Get-VeroPath).Conflicts
    if (Test-Path $f) { try { return @((Get-Content $f -Raw | ConvertFrom-Json).Items | Where-Object { $_ }) } catch { Write-Verbose 'conflicts unreadable' } }
    @()
}
