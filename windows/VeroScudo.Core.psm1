#Requires -Version 5.1
<#
  VeroScudo - Master the switch.          https://github.com/GomelHawk/VeroScudo
  Windows core module. See docs/ARCHITECTURE.md for the contract this implements and docs/SECURITY.md for the threat model.
  The code lives in Core\NN-<topic>.ps1, dot-sourced below in order into this one module (one scope, many files).

  Pure functions (unit-tested): Get-VeroConfig, Get-VeroDecision, Get-VeroFilterSpec, Get-VeroPath, Test-VeroCidr,
  Test-VeroReleaseUrl, Test-VeroNewerVersion, Get-VeroRasVerdict, the profile-type checks (Test-VeroOpenVpnConf,
  Test-VeroWireGuardConf), the OpenVPN management parser and the WireGuard health / transition rules.
  Everything else talks to Windows (WFP, RAS, OpenVPN, WireGuard, event log, Hyper-V firewall) and is exercised by tests-local/.

  Profile types (docs/ARCHITECTURE.md, "Profile types"): 'ras' = the Windows built-in VPN client (default, stable),
  'openvpn' = an openvpn.exe that VeroScudo starts and owns through its management interface, 'wireguard' = a tunnel
  service of the WireGuard for Windows app.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The parts, in order - an explicit list: a file left behind by an older version is never picked up. Everything they define
# lives in this module's scope; Export-ModuleMember at the end decides what callers see.
$script:ModuleRoot = $PSScriptRoot                                       # the parts refer to the folder of this file, not their own
foreach ($part in '10-Settings.ps1', '20-Native.ps1', '30-Config.ps1', '40-State.ps1', '50-VpnStatus.ps1', '60-KillSwitch.ps1', '62-HyperVAcl.ps1', '66-Quality.ps1', '67-Stats.ps1', '70-Dial.ps1', '80-ReserveShared.ps1', '81-OpenVpn.ps1', '82-WireGuard.ps1', '84-Hiddify.ps1', '85-Conflicts.ps1', '90-Actions.ps1', '95-TypeHandlers.ps1') {
    . (Join-Path $PSScriptRoot "Core\$part")
}

Export-ModuleMember -Function ConvertTo-VeroNetworkPrefix, Get-VeroVmAclRule, Set-VeroVmBlock, ConvertFrom-VeroCheckConfig, ConvertTo-VeroCheckObject, Split-VeroCheckAddress, ConvertFrom-VeroCheckForm, Get-VeroCheckWindow, Measure-VeroQuality, Format-VeroQuality, Get-VeroCheckLabel, Get-VeroQualityPerTarget, Invoke-VeroProbeRound, Update-VeroQuality, Read-VeroQuality, Update-VeroStats, Add-VeroStatsChecks, Save-VeroStatsMinute, Remove-VeroOldStats, ConvertFrom-VeroStatsText, Read-VeroStatsDay, Get-VeroStatsState, ConvertTo-VeroStatsDay, Format-VeroStatsBar, Format-VeroStatsTotal, Format-VeroStatsLine, Get-VeroStatsChoices, Get-VeroPendingSwitch, Initialize-VeroOpenVpnAdapter, Remove-VeroOpenVpnAdapter, Test-VeroOpenVpnAdapter, Get-VeroTapctl, Select-VeroForeignWfp, Get-VeroRasConnected, Save-VeroRasCoId, Test-VeroRecentOff, Update-VeroServerIpBeforeArm, Invoke-VeroArmConnected, Update-VeroRasWatch, Get-VeroRasClientConnect, Get-VeroRasConnectedRecord, Get-VeroExpectedCoId, Open-VeroCrlWindow, Test-VeroCrlWindow, Get-VeroSystemDir, Get-VeroTypeHandler, Resolve-VeroTerminationCode, Get-VeroStatusServer, Enter-VeroSingleton, Test-VeroSingletonHeld, Get-VeroLockDir, Test-VeroLockDirAcl, Import-VeroSavePayload, Import-VeroOpenVpnText, Select-VeroStaleOpenVpnFile, Remove-VeroStaleOpenVpnFile, Test-VeroAdminOnlyRules, Test-VeroAdminOnlyPath, Get-VeroNativeRetrySeconds, Get-VeroNativeBlocked, Set-VeroNativeBlocked, Clear-VeroNativeBlocked, Test-VeroNativeRetryDue, Get-VeroForeignVpn, Format-VeroForeignVpn, Disconnect-VeroForeignVpn, Split-VeroServerAddress, ConvertTo-VeroRasEntry, Get-VeroRasSavedUser, Get-VeroWindowsVpn, Test-VeroRasPassword, Get-VeroRasDescription, ConvertTo-VeroProfileObject, Get-VeroTypeLabel, Get-VeroSwitchNotice, Get-VeroProfileType, Test-VeroElevated,
    Test-VeroNeedsPassword, Test-VeroTunnelAdapter, Protect-VeroOpenVpnDir, Test-VeroOpenVpnConf, Import-VeroOpenVpnProfile, Get-VeroOpenVpnRemote,
    Get-VeroOpenVpnExe, Get-VeroOpenVpnArgs, ConvertFrom-VeroMgmtLine, Format-VeroMgmtValue, New-VeroMgmtQueue, Add-VeroMgmtCommand, Update-VeroMgmtQueue, Get-VeroStaticChallengeResponse, Get-VeroOpenVpnStatus,
    Get-VeroOpenVpnNic, Test-VeroOpenVpnRunnerAlive, Invoke-VeroOpenVpnDial, Stop-VeroOpenVpn, Invoke-VeroOpenVpnSession, Invoke-VeroOpenVpnRunner,
    Get-VeroHiddifyDir, Get-VeroHiddifyApps, Get-VeroHiddifyNic, Test-VeroHiddifyConnected, Get-VeroHiddifyMode, Get-VeroHiddifyOffer, Update-VeroHiddifyWatch, Get-VeroWgState, Get-VeroWgHealth, Get-VeroWgTransition, Update-VeroWgWatch, Get-VeroWgHealthNow, Invoke-VeroWgDial, Invoke-VeroWgHangUp,
    Test-VeroWireGuardConf, Get-VeroConflict, Update-VeroConflict, Get-VeroConflictList, Get-VeroKeyPassphrase, Set-VeroAuthFailed, Clear-VeroAuthFailed,
    Test-VeroAuthBlocked, Set-VeroRenewMarker, Test-VeroRenewHangUp, Get-VeroRenewMarker, Resolve-VeroEndpoint, Invoke-VeroHangUp,
    Get-VeroVersion, Test-VeroNewerVersion, Test-VeroReleaseUrl, Get-VeroLatestRelease, Set-VeroHome, Get-VeroPath,
    Get-VeroConfig, Get-VeroProfileId, Set-VeroProfileIds, ConvertTo-VeroConfigJson, Save-VeroConfig, Test-VeroCidr, Write-VeroLog, Test-VeroArmed, Set-VeroArmed, Set-VeroActiveProfile,
    Test-VeroVpnConnected, Get-VeroRasCode, Get-VeroRasVerdict, Get-VeroRasTermination, Get-VeroDecision, Resolve-VeroServerIp,
    Get-VeroFilterSpec, Get-VeroTunnelLuid, Get-VeroDnsServer, Get-VeroWslLuid, Get-VeroSwitchLuid, Test-VeroVmWanted, Sync-VeroKillSwitch, Disable-VeroKillSwitch,
    Remove-VeroLegacyFirewall, Test-VeroKillSwitchPresent, Test-VeroNative, Import-VeroNative, Set-VeroVmAccess, Restore-VeroVmAccess,
    Get-VeroCredential, Invoke-VeroDial, Enter-VeroLock, Set-VeroWfpFilter, Get-VeroWfpCount, Clear-VeroWfpFilter, Invoke-VeroReconnect, Invoke-VeroCheck, Invoke-VeroSwitch, Get-VeroStatus, Invoke-VeroAction
