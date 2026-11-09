# VeroScudo core, part 95: profile types: one handler per type, and the permits each type's client gets.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- profile types: one handler per type
# Everything that differs between the built-in client ('ras'), OpenVPN and WireGuard, in one place. The scriptblocks call
# module functions by name (tests mock those) and are invoked as `& $h.Op args`. Built last: every function exists by now.
# Keys: Label, DefaultPort, PasswordCapable (asks for / stores a password), HasDco (OpenVPN kernel data channel option),
# OwnLayer (the client's own WFP layer name, expected while its tunnel runs), HangUpOnOffAlways (Off ends the client even
# mid-connect); config rules NamePattern/NameHint, ServerRequired, UsernameRequired; on-disk form OnDiskType, OnDiskPort,
# OnDiskAuth (the type's own keys); SwitchNotice, IsConnected, TunnelLuid, ServerPermit (@{ Kind; Ips; Endpoints; App }
# for the filters), ResolveIps, RasTunnelType, CrlWindow, Dial, HangUp, DialFailure, StatusDetail, ServerText (what the
# profile names, for status), ForeignText, ForeignHangUp.
$script:TypeHandler = @{
    ras = @{
        Label = 'Windows VPN'; DefaultPort = 443; PasswordCapable = $true; HasDco = $false; OwnLayer = $null; HangUpOnOffAlways = $false
        NamePattern = $null; NameHint = ''; ServerRequired = $true; UsernameRequired = $true; OnDiskType = $false; OnDiskPort = $true
        OnDiskAuth    = { param($Entry, $o) if ($Entry.PSObject.Properties['Auth'] -and -not $Entry.Auth) { $o.auth = $false } }   # certificate sign-in
        ServerText    = { param($Config) $Config.Server }
        SwitchNotice  = { $null }
        IsConnected   = { param($ProfileName) Test-VeroRasConnected $ProfileName }
        TunnelLuid    = { param($ProfileName) Get-VeroRasTunnelLuid $ProfileName }
        ServerPermit  = { param($Config, $Action) Get-VeroRasServerPermit -Config $Config -Action $Action }
        ResolveIps    = { param($Config) Resolve-VeroServerIp -Config $Config }
        RasTunnelType = { param($ProfileName) Get-VeroTunnelType $ProfileName }
        CrlWindow     = { Test-VeroCrlWindow }
        Dial          = { param($Config, $Action) Invoke-VeroRasDial -Config $Config -Action $Action }
        HangUp        = { param($ProfileName) & $script:Rasdial $ProfileName /disconnect 2>&1 | Out-Null }
        DialFailure   = { param($Config) $ev = Get-VeroRasCode -EventId 20227 -Profile $Config.Profile; "RasDial $($script:LastDialCode)$(if ($ev -ne -1) { ', RAS ' + $ev })" }
        StatusDetail  = { '-' }
        ForeignText   = { param($F) "Windows VPN '$($F.Name)' is connected$(if ($F.Configured) { ' (another VeroScudo profile)' } else { ' (not a VeroScudo profile)' })" }
        ForeignHangUp = { param($F) & $script:Rasdial $F.Id /disconnect 2>&1 | Out-Null }
    }
    openvpn = @{
        Label = 'OpenVPN'; DefaultPort = 1194; PasswordCapable = $true; HasDco = $true; OwnLayer = 'OpenVPN'; HangUpOnOffAlways = $true
        NamePattern = $null; NameHint = ''; ServerRequired = $false; UsernameRequired = $false; OnDiskType = $true; OnDiskPort = $false   # server/port: the .ovpn's remote lines
        OnDiskAuth    = { param($Entry, $o) $o.auth = if ($Entry.PSObject.Properties['Auth']) { [bool]$Entry.Auth } else { $true }; if ($Entry.PSObject.Properties['Dco'] -and $Entry.Dco) { $o.dco = $true } }
        ServerText    = { param($Config) (@(try { Get-VeroOpenVpnRemote -ProfileName $Config.Profile } catch { @() }) | ForEach-Object { '{0}:{1}/{2}' -f $_.Host, $_.Port, $_.Proto }) -join ' ' }
        SwitchNotice  = { param($ProfileName) "'$ProfileName' is an OpenVPN profile. VeroScudo controls this connection: don't connect or disconnect it from OpenVPN GUI - use VeroScudo's On, Off and Reconnect." }
        IsConnected   = { param($ProfileName) [bool](Get-VeroOpenVpnNic $ProfileName) }
        # only the adapter that holds the address OpenVPN reported - never a physical NIC
        TunnelLuid    = { param($ProfileName) $nic = Get-VeroOpenVpnNic $ProfileName; if ($nic) { [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) } else { [uint64]0 } }
        ServerPermit  = { param($Config, $Action) Get-VeroEndpointPermit -Config $Config -Action $Action -Program:(-not $Config.Dco) }
        ResolveIps    = { param($Config) Resolve-VeroEndpoint -Config $Config | ForEach-Object { [string]$_.Ip } | Select-Object -Unique }
        RasTunnelType = { 'Automatic' }
        CrlWindow     = { $false }
        Dial          = { param($Config, $Action) Invoke-VeroOpenVpnDial -Config $Config -Action $Action }
        HangUp        = { param($ProfileName) Stop-VeroOpenVpn -ProfileName $ProfileName }
        DialFailure   = { param($Config) $s = Get-VeroOpenVpnStatus $Config.Profile; if ($s) { "OpenVPN $($s.State)$(if ($s.Reason) { ': ' + $s.Reason })" } else { 'OpenVPN not started' } }
        StatusDetail  = { param($Config) $s = Get-VeroOpenVpnStatus $Config.Profile; if ($s) { "$($s.State)$(if ($s.Reason) { ' (' + $s.Reason + ')' })" } else { 'not started' } }
        ForeignText   = { param($F) "$($F.Name) runs outside VeroScudo (OpenVPN GUI or the OpenVPN service)" }
        ForeignHangUp = { param($F) Stop-VeroForeignOpenVpn $F }
    }
    wireguard = @{
        Label = 'WireGuard'; DefaultPort = 51820; PasswordCapable = $false; HasDco = $false; OwnLayer = 'WireGuard'; HangUpOnOffAlways = $false
        # WireGuard names its tunnel service after the tunnel: the same rule as the WireGuard app (and safe on a command line)
        NamePattern = '^[A-Za-z0-9_=+.-]{1,32}$'; NameHint = 'a WireGuard tunnel name is 1-32 of A-Z a-z 0-9 _ = + . -'
        ServerRequired = $true; UsernameRequired = $false; OnDiskType = $true; OnDiskPort = $true
        OnDiskAuth    = { }                                                   # no password, no DCO: nothing of its own on disk
        ServerText    = { param($Config) $Config.Server }
        SwitchNotice  = { param($ProfileName) "'$ProfileName' is a WireGuard profile. A dead WireGuard link is noticed after 1-3 minutes, not seconds; you stay blocked until it reconnects. Prefer a Windows VPN profile when you can." }
        IsConnected   = { param($ProfileName) (Get-VeroWgHealthNow $ProfileName) -eq 'up' }
        # allowed while its service runs, even before the first handshake - app traffic is what starts a handshake when no
        # keepalive is set; a dead tunnel only loses that traffic (its routes point into it), it never leaks
        TunnelLuid    = { param($ProfileName) $nic = if ((Get-VeroWgState $ProfileName) -eq 'running') { Get-VeroWgNic $ProfileName }; if ($nic) { [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) } else { [uint64]0 } }
        ServerPermit  = { param($Config, $Action) Get-VeroEndpointPermit -Config $Config -Action $Action }
        ResolveIps    = { param($Config) Resolve-VeroEndpoint -Config $Config | ForEach-Object { [string]$_.Ip } | Select-Object -Unique }
        RasTunnelType = { 'Automatic' }
        CrlWindow     = { $false }
        Dial          = { param($Config, $Action) Invoke-VeroWgDial -Config $Config -Action $Action }
        HangUp        = { param($ProfileName) Invoke-VeroWgHangUp -ProfileName $ProfileName }
        DialFailure   = { param($Config) "WireGuard $(Get-VeroWgState $Config.Profile), handshake $(Get-VeroWgHealthNow $Config.Profile)" }
        StatusDetail  = { param($Config) "service $(Get-VeroWgState $Config.Profile), handshake $(Get-VeroWgHealthNow $Config.Profile)" }
        ForeignText   = { param($F) "WireGuard tunnel '$($F.Name)' is active$(if ($F.Configured) { ' (another VeroScudo profile)' } else { ' (not a VeroScudo profile)' })" }
        ForeignHangUp = { param($F) Invoke-VeroWgHangUp -ProfileName $F.Id }
    }
    hiddify = @{
        # kill-switch only (84-Hiddify.ps1): Hiddify connects, disconnects and reconnects itself - VeroScudo only blocks
        Label = 'Hiddify'; DefaultPort = 443; PasswordCapable = $false; HasDco = $false; OwnLayer = 'sing-box|sing-tun|Hiddify'; HangUpOnOffAlways = $false
        NamePattern = $null; NameHint = ''; ServerRequired = $false; UsernameRequired = $false; OnDiskType = $true; OnDiskPort = $false
        OnDiskAuth    = { }
        ServerText    = { 'servers of the Hiddify app' }
        SwitchNotice  = { param($ProfileName) "'$ProfileName' is a Hiddify profile: connect, disconnect and reconnect it in Hiddify (VPN mode). While its tunnel is down, nothing else leaves this PC." }
        IsConnected   = { Test-VeroHiddifyConnected }                         # one Hiddify per PC: the profile name does not matter
        TunnelLuid    = { Get-VeroHiddifyTunnelLuid }
        ServerPermit  = { param($Config, $Action) Get-VeroHiddifyPermit -Config $Config -Action $Action }
        ResolveIps    = { @() }
        RasTunnelType = { 'Automatic' }
        CrlWindow     = { $false }
        Dial          = { param($Config, $Action) Invoke-VeroHiddifyDial -Config $Config -Action $Action }
        HangUp        = { }                                                   # never: Hiddify is yours to disconnect
        DialFailure   = { "Hiddify $(if (Test-VeroHiddifyRunning) { 'runs, its tunnel is down (VPN mode off or not connected)' } else { 'is not running' })" }
        StatusDetail  = { "Hiddify $(if (Test-VeroHiddifyRunning) { 'running' } else { 'not running' }), tunnel $(if (Get-VeroHiddifyNic) { 'up' } else { 'down' })" }
        ForeignText   = { param($F) "Hiddify is connected in VPN mode$(if ($F.Configured) { ' (another VeroScudo profile)' } else { ' (not a VeroScudo profile)' }) - VeroScudo cannot disconnect it, use Hiddify" }
        ForeignHangUp = { }
    }
}
function Get-VeroTypeHandler {
    <# The handler table of a profile type ('' = the built-in client, like Get-VeroConfigType). Unknown: throw - config
       validation only lets the three through, so this is a programming error, never a user error. #>
    [CmdletBinding()] param([string]$Type)
    if (-not $Type) { $Type = 'ras' }
    $h = $script:TypeHandler[$Type]
    if (-not $h) { throw "unknown profile type '$Type'" }
    $h
}
function Get-VeroRasServerPermit {
    <# The addresses the filters may let the built-in client reach: cached first, one lookup when nothing is cached. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $ips = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
    if ($ips.Count -eq 0) { $ips = @(Resolve-VeroServerIp -Config $Config) }                   # first run: nothing cached yet
    if ($ips.Count -eq 0) { Write-VeroLog "WARNING: cannot resolve $($Config.Server) and no cached IP - redial cannot reach it" $Action }
    @{ Kind = 'server'; Ips = $ips; Endpoints = $null; App = '' }
}
function Get-VeroEndpointPermit {
    <# OpenVPN / WireGuard: the endpoints @{ Ip; Proto; Port } the filters may let the client reach. -Program: only from the
       client's executable (OpenVPN without DCO) - and never a program-less permit by accident: no program known, nothing allowed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Program)
    $eps = @(Resolve-VeroEndpoint -Config $Config -CacheOnly)
    if ($eps.Count -eq 0) { $eps = @(Resolve-VeroEndpoint -Config $Config) }
    if ($eps.Count -eq 0) { Write-VeroLog "WARNING: no address known for the $(Get-VeroTypeLabel (Get-VeroConfigType $Config)) server of '$($Config.Profile)' - redial cannot reach it" $Action }
    $ips = @($eps | ForEach-Object { [string]$_.Ip } | Select-Object -Unique)
    $app = ''
    if ($Program) {
        $app = Get-VeroOpenVpnExe
        if (-not $app) { $eps = @() }
    }
    @{ Kind = 'endpoints'; Ips = $ips; Endpoints = $eps; App = [string]$app }
}
