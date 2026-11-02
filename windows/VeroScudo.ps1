#Requires -Version 5.1
<# VeroScudo entry point. Usage: VeroScudo.ps1 -Action arm|disarm|on|off|on-event|reconnect|watchdog|check|switch|status|openvpn [-VpnProfile <name>]
   on refuses while another VPN is connected: add -DisconnectOthers (end it first) or -Force (turn on anyway).
   reconnect = your Reconnect: block, hang up, redial, traffic again once the tunnel is back. openvpn = the OpenVPN runner task. #>
param(
    [Parameter(Mandatory)]
    [ValidateSet('arm', 'disarm', 'on', 'on-disconnect', 'on-force', 'off', 'on-event', 'reconnect', 'watchdog', 'check', 'switch', 'status', 'openvpn')]
    [string]$Action,
    [string]$VpnProfile,
    [switch]$DisconnectOthers,       # with -Action on: end every other connected VPN first (your choice)
    [switch]$Force                   # with -Action on: turn on even though another VPN is connected (its traffic is blocked)
)
if ($Action -eq 'on' -and $DisconnectOthers) { $Action = 'on-disconnect' } elseif ($Action -eq 'on' -and $Force) { $Action = 'on-force' }
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force
try {
    Invoke-VeroAction -Action $Action -VpnProfile $VpnProfile
} catch {
    # the scheduled tasks run hidden: without this line a failure would be invisible
    Write-VeroLog ("ERROR: {0} | at {1}" -f $_.Exception.Message, ($_.InvocationInfo.PositionMessage -replace '\s+', ' ')) $Action
    # the native helper was refused by Windows: record it for the tray (the On/Off/... tasks are separate processes)
    if (& (Get-Module VeroScudo.Core) { $script:NativeLoadFailed }) { try { Set-VeroNativeBlocked -Message $_.Exception.Message -Action $Action -FromTask } catch { Write-Verbose 'not recorded' } }
    exit 1
}
