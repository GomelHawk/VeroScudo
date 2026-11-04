# VeroScudo core, part 95: profile types: one handler per type, and the permits each type's client gets.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- profile types: one handler per type
# Everything that differs between the built-in client ('ras'), OpenVPN and WireGuard, in one place. The scriptblocks call
# module functions by name (tests mock those) and are invoked as `& $h.Op args`. Built last: every function exists by now.
# Keys: Label, DefaultPort, PasswordCapable (asks for / stores a password), HasDco (OpenVPN kernel data channel option),
# OwnLayer (the client's own WFP layer name, expected while its tunnel runs), HangUpOnOffAlways (Off ends the client even
# mid-connect), SwitchNotice, IsConnected, TunnelLuid, ServerPermit (@{ Ips; Endpoints; App } for the filters),
# ResolveIps, RasTunnelType, CrlWindow, Dial, HangUp, DialFailure, StatusDetail, ForeignText, ForeignHangUp.
$script:TypeHandler = @{
    ras = @{
        Label = 'Windows VPN'; DefaultPort = 443; PasswordCapable = $true; HasDco = $false; OwnLayer = $null; HangUpOnOffAlways = $false
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
    @{ Ips = $ips; Endpoints = $null; App = '' }
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
    @{ Ips = $ips; Endpoints = $eps; App = [string]$app }
}
