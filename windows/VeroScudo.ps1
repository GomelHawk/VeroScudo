#Requires -Version 5.1
<# VeroScudo entry point. Usage: VeroScudo.ps1 -Action arm|disarm|on|off|on-event|reconnect|watchdog|check|switch|status [-VpnProfile <name>] #>
param(
    [Parameter(Mandatory)]
    [ValidateSet('arm', 'disarm', 'on', 'off', 'on-event', 'reconnect', 'watchdog', 'check', 'switch', 'status')]
    [string]$Action,
    [string]$VpnProfile
)
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force
try {
    Invoke-VeroAction -Action $Action -VpnProfile $VpnProfile
} catch {
    # the scheduled tasks run hidden: without this line a failure would be invisible
    Write-VeroLog ("ERROR: {0} | at {1}" -f $_.Exception.Message, ($_.InvocationInfo.PositionMessage -replace '\s+', ' ')) $Action
    exit 1
}
