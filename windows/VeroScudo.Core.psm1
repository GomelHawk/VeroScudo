#Requires -Version 5.1
<#
  VeroScudo - Master the switch.          https://github.com/GomelHawk/VeroScudo
  Windows core module. See docs/ARCHITECTURE.md for the contract this implements.

  Pure functions (unit-tested): Get-VeroConfig, Get-VeroDecision, Get-VeroRuleSpec, Get-VeroPath
  Everything else talks to Windows (firewall, RAS, event log) and is exercised by tests-local/.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Version    = '1.0.0'
$script:Group      = 'VeroScudo'
$script:VmRule     = 'VeroScudo-WSL'
$script:WslCreator = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'   # Hyper-V firewall VM creator id of WSL
$script:Svchost    = "$env:SystemRoot\System32\svchost.exe"

# ---------------------------------------------------------------- paths & config
function Get-VeroPath {
    [CmdletBinding()] param()
    $home_ = if ($env:VEROSCUDO_HOME) { $env:VEROSCUDO_HOME } else { Join-Path $env:ProgramData 'VeroScudo' }
    $state = Join-Path $home_ 'state'
    [pscustomobject]@{
        Home      = $home_
        Config    = Join-Path $home_ 'config.json'
        State     = $state
        ArmedFlag = Join-Path $state 'armed.flag'
        Lock      = Join-Path $state 'reconnect.lock'
        FwBackup  = Join-Path $state 'fw-original.json'
        ServerIp  = Join-Path $state 'server.ip'
        Log       = Join-Path $state 'veroscudo.log'
        Cred      = Join-Path $env:LOCALAPPDATA 'VeroScudo\cred.xml'
    }
}

function Get-VeroConfig {
    <# Reads config.json, applies defaults, validates. -Raw accepts JSON text (tests). #>
    [CmdletBinding()] param([string]$Path, [string]$Raw)
    if (-not $Raw) {
        if (-not $Path) { $Path = (Get-VeroPath).Config }
        if (-not (Test-Path $Path)) { throw "VeroScudo config not found: $Path (run Install.ps1)" }
        $Raw = Get-Content $Path -Raw
    }
    $j = $Raw | ConvertFrom-Json
    $vpn = if ($j.PSObject.Properties['vpn']) { $j.vpn } else { $null }
    function Get-Prop($o, $n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if (-not (Get-Prop $vpn 'profile'))  { throw 'config.json: vpn.profile is required' }
    if (-not (Get-Prop $vpn 'server'))   { throw 'config.json: vpn.server is required' }
    if (-not (Get-Prop $vpn 'username')) { throw 'config.json: vpn.username is required' }
    $vm = if ($null -ne $j.PSObject.Properties['vm']) { $j.vm } else { 'auto' }
    if ($vm -is [string] -and $vm -ne 'auto') { throw "config.json: vm must be 'auto', true or false" }
    [pscustomobject]@{
        Profile         = [string]$vpn.profile
        Server          = [string]$vpn.server
        Port            = if ($vpn.PSObject.Properties['port']) { [int]$vpn.port } else { 443 }
        Username        = [string]$vpn.username
        RetrySeconds    = if ($j.PSObject.Properties['retrySeconds']) { [int]$j.retrySeconds } else { 10 }
        Vm              = $vm
        WifiRecoveryFix = if ($j.PSObject.Properties['wifiRecoveryFix']) { [bool]$j.wifiRecoveryFix } else { $true }
        LanAllow        = @(if ($j.PSObject.Properties['lanAllow']) { $j.lanAllow } else { @() })
        UpdateCheck     = if ($j.PSObject.Properties['updateCheck']) { [bool]$j.updateCheck } else { $true }
    }
}

# ---------------------------------------------------------------- logging & state
function Write-VeroLog {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Message, [string]$Action = 'core')
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    if ((Test-Path $p.Log) -and (Get-Item $p.Log).Length -gt 2MB) { Move-Item $p.Log "$($p.Log).1" -Force }
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Action, $Message
    Add-Content -Path $p.Log -Value $line -Encoding UTF8
    Write-Host $line
}
function Test-VeroArmed { Test-Path (Get-VeroPath).ArmedFlag }
function Set-VeroArmed {
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Value, [string]$Action = 'core')
    $p = Get-VeroPath
    if ($Value -and -not (Test-Path $p.ArmedFlag)) { New-Item -ItemType File -Path $p.ArmedFlag -Force | Out-Null; Write-VeroLog 'ARMED' $Action }
    if (-not $Value -and (Test-Path $p.ArmedFlag)) { Remove-Item $p.ArmedFlag -Force; Write-VeroLog 'DISARMED' $Action }
}

# ---------------------------------------------------------------- VPN status & events
function Test-VeroVpnConnected {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
    if ($c) { return $c.ConnectionStatus -eq 'Connected' }
    return ((rasdial.exe) -join ' ') -match ('\b' + [regex]::Escape($ProfileName) + '\b')
}

function Get-VeroRasCode {
    <# Reason code of the newest RasClient event (20226 terminated / 20227 dial failed) for this profile. -1 if none. #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$EventId, [Parameter(Mandatory)][string]$ProfileName, [int]$WithinMinutes = 5)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = $EventId
                                           StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -ge 4 -and $_.Properties[2].Value -eq $ProfileName } |
          Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($ev) { return [int64]$ev.Properties[3].Value }
    return -1
}

function Get-VeroDecision {
    <# The one judgement the guard makes. 631 = "the user disconnected" (Windows RAS). #>
    [CmdletBinding()] param([Parameter(Mandatory)][int64]$ReasonCode, [Parameter(Mandatory)][bool]$Armed)
    if ($ReasonCode -eq 631) { return 'disarm' }
    if ($Armed) { return 'reconnect' }
    return 'none'
}

# ---------------------------------------------------------------- firewall
function Resolve-VeroServerIp {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Server)
    $p = Get-VeroPath
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($Server) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
        if ($ips) { Set-Content -Path $p.ServerIp -Value $ips; return @($ips) }
    } catch { Write-Verbose "DNS lookup of $Server failed: $($_.Exception.Message)" }
    if (Test-Path $p.ServerIp) { return @(Get-Content $p.ServerIp | Where-Object { $_ }) }
    return @()
}

function Get-VeroWslInterface {
    [CmdletBinding()] param()
    $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'vEthernet (WSL*' } | Select-Object -First 1
    if ($a) { $a.Name } else { $null }
}

function Test-VeroVmWanted {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    if ($Config.Vm -eq 'auto') { return [bool](Get-NetFirewallHyperVVMCreator -ErrorAction SilentlyContinue | Where-Object VMCreatorId -eq $script:WslCreator) }
    return [bool]$Config.Vm
}

function Get-VeroRuleSpec {
    <# The allow-list (see ARCHITECTURE.md). Pure: returns @{Name; Params} entries for New-NetFirewallRule. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string[]]$ServerIps = @(), [string]$WslInterface)
    $specs = @(
        @{ Name = 'VPN tunnel';  Params = @{ InterfaceType = 'RemoteAccess' } }
        @{ Name = 'DHCP';        Params = @{ Protocol = 'UDP'; LocalPort = 68; RemotePort = 67 } }
        @{ Name = 'DNS UDP';     Params = @{ Protocol = 'UDP'; RemotePort = 53 } }
        @{ Name = 'DNS TCP';     Params = @{ Protocol = 'TCP'; RemotePort = 53 } }
        @{ Name = 'CRL SstpSvc'; Params = @{ Protocol = 'TCP'; RemotePort = 80; Program = $script:Svchost; Service = 'SstpSvc' } }
        @{ Name = 'CRL CryptSvc';Params = @{ Protocol = 'TCP'; RemotePort = 80; Program = $script:Svchost; Service = 'CryptSvc' } }
    )
    if ($WslInterface) { $specs += @{ Name = 'WSL switch'; Params = @{ InterfaceAlias = $WslInterface } } }
    if ($ServerIps.Count -gt 0) { $specs += @{ Name = 'VPN server'; Params = @{ Protocol = 'TCP'; RemotePort = $Config.Port; RemoteAddress = $ServerIps } } }
    foreach ($cidr in $Config.LanAllow) { $specs += @{ Name = "LAN $cidr"; Params = @{ RemoteAddress = $cidr } } }
    return ,$specs
}

function Confirm-VeroRule {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Params, [string]$Action = 'core')
    $full = "$script:Group - $Name"
    $rule = Get-NetFirewallRule -DisplayName $full -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule -DisplayName $full -Group $script:Group -Direction Outbound -Action Allow -Profile Any -Enabled True @Params | Out-Null
        Write-VeroLog "firewall rule created: $full" $Action
    } elseif ($Params.ContainsKey('RemoteAddress')) {
        $current = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
        if (Compare-Object $current @($Params.RemoteAddress)) {
            $rule | Set-NetFirewallRule -RemoteAddress $Params.RemoteAddress
            Write-VeroLog "$full -> $($Params.RemoteAddress -join ',')" $Action
        }
    }
}

function Save-VeroFirewallDefault {
    $p = Get-VeroPath
    if (Test-Path $p.FwBackup) { return }
    Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction | ConvertTo-Json | Set-Content -Path $p.FwBackup
}
function Restore-VeroFirewallDefault {
    $p = Get-VeroPath
    if (-not (Test-Path $p.FwBackup)) { Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured; return }
    foreach ($pr in (Get-Content $p.FwBackup -Raw | ConvertFrom-Json)) {
        Set-NetFirewallProfile -Name $pr.Name -DefaultOutboundAction ([string]$pr.DefaultOutboundAction)
    }
}

function Set-VeroVmAccess {
    <# WSL/Docker traffic is filtered at the Hyper-V vSwitch where the host default-drop is merged in;
       an explicit Hyper-V allow rule lets it through while the tunnel is up and is disabled while down. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Allow, [string]$Action = 'core')
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    if (-not $r) {
        New-NetFirewallHyperVRule -Name $script:VmRule -DisplayName "$script:Group - WSL outbound" -Direction Outbound -Action Allow -VMCreatorId $script:WslCreator | Out-Null
        $r = Get-NetFirewallHyperVRule -Name $script:VmRule
        Write-VeroLog 'Hyper-V rule created: WSL outbound' $Action
    }
    $want = if ($Allow) { 'True' } else { 'False' }
    if ([string]$r.Enabled -ne $want) {
        Set-NetFirewallHyperVRule -Name $script:VmRule -Enabled $want
        Write-VeroLog "WSL outbound -> $(if ($Allow) { 'allowed' } else { 'blocked' })" $Action
    }
}
function Remove-VeroVmAccess { Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule }

function Enable-VeroKillSwitch {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    Save-VeroFirewallDefault
    $ips = @(Resolve-VeroServerIp -Server $Config.Server)
    if ($ips.Count -eq 0) { Write-VeroLog "WARNING: cannot resolve $($Config.Server) and no cached IP" $Action }
    $wsl = if (Test-VeroVmWanted $Config) { Get-VeroWslInterface } else { $null }
    foreach ($s in (Get-VeroRuleSpec -Config $Config -ServerIps $ips -WslInterface $wsl)) { Confirm-VeroRule -Name $s.Name -Params $s.Params -Action $Action }
    if (Get-NetFirewallProfile | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }) {
        Set-NetFirewallProfile -All -DefaultOutboundAction Block
        Write-VeroLog 'kill-switch ON (default outbound = Block)' $Action
    }
    if (Test-VeroVmWanted $Config) { Set-VeroVmAccess -Allow (Test-VeroVpnConnected $Config.Profile) -Action $Action }
}
function Disable-VeroKillSwitch {
    [CmdletBinding()] param([string]$Action = 'core')
    Restore-VeroFirewallDefault
    Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-VeroVmAccess
    Write-VeroLog 'kill-switch OFF (firewall restored)' $Action
}

# ---------------------------------------------------------------- dialing
function Get-VeroCredential {
    $p = Get-VeroPath
    if (-not (Test-Path $p.Cred)) { return $null }
    try { Import-Clixml $p.Cred } catch { $null }
}
function Invoke-VeroDial {
    <# rasdial ignores the password saved by the Settings app -> dial with the DPAPI-stored credential. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $cred = Get-VeroCredential
    if ($cred) { rasdial.exe $Config.Profile $cred.UserName $cred.GetNetworkCredential().Password 2>&1 | Out-Null }
    else {
        Write-VeroLog 'WARNING: no stored credential (run Set-VpnCredential.ps1) - dialing without password' $Action
        rasdial.exe $Config.Profile 2>&1 | Out-Null
    }
}

function Test-VeroLockAlive {
    $p = Get-VeroPath
    if (-not (Test-Path $p.Lock)) { return $false }
    $lockPid = Get-Content $p.Lock -ErrorAction SilentlyContinue | Select-Object -First 1
    # the lock survives a crash or reboot and Windows reuses PIDs: alive only if that PID is still a PowerShell
    # process that was already running when the lock was written
    $proc = if ($lockPid) { Get-Process -Id $lockPid -ErrorAction SilentlyContinue }
    $started = try { $proc.StartTime } catch { $null }
    if ($proc -and $proc.ProcessName -in 'powershell', 'pwsh' -and $started -and $started -le (Get-Item $p.Lock).LastWriteTime) { return $true }
    Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    return $false
}

function Invoke-VeroReconnect {
    <# Blocked + redial forever, until the tunnel is up or the user turns the VPN off. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if (Test-VeroLockAlive) { Write-VeroLog 'reconnect loop already running' $Action; return }
    $p = Get-VeroPath
    Set-Content -Path $p.Lock -Value $PID
    $attempt = 0
    try {
        while ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
            $attempt++
            if (Test-VeroVmWanted $Config) { Set-VeroVmAccess -Allow $false -Action $Action }
            Enable-VeroKillSwitch -Config $Config -Action $Action
            Invoke-VeroDial -Config $Config -Action $Action
            if (Test-VeroVpnConnected $Config.Profile) { Write-VeroLog "reconnected after $attempt attempt(s)" $Action; break }
            Write-VeroLog "attempt $attempt failed (RAS $(Get-VeroRasCode -EventId 20227 -Profile $Config.Profile))" $Action
            Start-Sleep -Seconds $Config.RetrySeconds
        }
        if (-not (Test-VeroArmed)) { Write-VeroLog 'disarmed during reconnect - stopping' $Action }
    } finally {
        Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    }
    if ((Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) { Enable-VeroKillSwitch -Config $Config -Action $Action }
}

# ---------------------------------------------------------------- actions & status
function Get-VeroStatus {
    [CmdletBinding()] param($Config)
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $Config.Profile
    $outbound = @(Get-NetFirewallProfile | ForEach-Object { [string]$_.DefaultOutboundAction } | Select-Object -Unique) -join ','
    [pscustomobject]@{
        Version    = $script:Version
        Profile    = $Config.Profile
        Armed      = $armed
        Connected  = $up
        State      = if (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
        Credential = Test-Path $p.Cred
        Outbound   = $outbound
        Rules      = @(Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue).Count
        Vm         = if (-not $r) { 'host policy' } elseif ([string]$r.Enabled -eq 'True') { 'allowed' } else { 'blocked' }
        Reconnect  = Test-VeroLockAlive
        Log        = $p.Log
    }
}

function Invoke-VeroAction {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][ValidateSet('arm', 'disarm', 'on', 'off', 'on-event', 'reconnect', 'watchdog', 'status')][string]$Action,
        $Config
    )
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    switch ($Action) {
        'arm'    { Set-VeroArmed $true $Action; Enable-VeroKillSwitch -Config $Config -Action $Action }
        'disarm' { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
        'on'     { Set-VeroArmed $true $Action; Enable-VeroKillSwitch -Config $Config -Action $Action
                   if (-not (Test-VeroVpnConnected $Config.Profile)) { Invoke-VeroReconnect -Config $Config -Action $Action } }
        'off'    { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action
                   if (Test-VeroVpnConnected $Config.Profile) { rasdial.exe $Config.Profile /disconnect | Out-Null; Write-VeroLog 'disconnected by user (off)' $Action } }
        'on-event' {
            $code = Get-VeroRasCode -EventId 20226 -Profile $Config.Profile
            Write-VeroLog "VPN terminated, RAS code $code" $Action
            switch (Get-VeroDecision -ReasonCode $code -Armed (Test-VeroArmed)) {
                'disarm'    { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
                'reconnect' { Invoke-VeroReconnect -Config $Config -Action $Action }
            }
        }
        'reconnect' { if (Test-VeroArmed) { Invoke-VeroReconnect -Config $Config -Action $Action } }
        'watchdog' {
            if (Test-VeroArmed) {
                Enable-VeroKillSwitch -Config $Config -Action $Action
                if (-not (Test-VeroVpnConnected $Config.Profile)) { Invoke-VeroReconnect -Config $Config -Action $Action }
            } elseif (Get-NetFirewallProfile | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' }) {
                Write-VeroLog 'disarmed but outbound still blocked - restoring' $Action
                Disable-VeroKillSwitch -Action $Action
            }
        }
        'status' {
            $s = Get-VeroStatus -Config $Config
            $s.PSObject.Properties | ForEach-Object { '{0,-11}: {1}' -f $_.Name, $_.Value }
            if (Test-Path $p.Log) { '--- last log lines'; Get-Content $p.Log -Tail 8 }
        }
    }
}

function Get-VeroVersion { $script:Version }

function Test-VeroNewerVersion {
    <# True when a release tag (v1.2.3) is newer than the running version. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Tag, [string]$Current = $script:Version)
    $t = $Tag.Trim() -replace '^[vV]', ''
    if ($t -notmatch '^\d+(\.\d+){1,3}$') { return $false }
    return ([version]$t -gt [version]$Current)
}

function Get-VeroLatestRelease {
    <# GitHub "latest release" lookup; $null on any failure. Only call while traffic is allowed (never while blocked). #>
    [CmdletBinding()] param([string]$Repo = 'GomelHawk/VeroScudo', [int]$TimeoutSec = 10)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec $TimeoutSec -UseBasicParsing `
                -Headers @{ 'User-Agent' = "VeroScudo/$script:Version"; Accept = 'application/vnd.github+json' }
        if ($r.tag_name) { return [pscustomobject]@{ Tag = [string]$r.tag_name; Url = [string]$r.html_url; Name = [string]$r.name } }
    } catch { Write-Verbose "update check failed: $($_.Exception.Message)" }
    return $null
}

Export-ModuleMember -Function Get-VeroVersion, Test-VeroNewerVersion, Get-VeroLatestRelease, Get-VeroPath, Get-VeroConfig, Write-VeroLog, Test-VeroArmed, Set-VeroArmed,
    Test-VeroVpnConnected, Get-VeroRasCode, Get-VeroDecision, Resolve-VeroServerIp, Get-VeroWslInterface,
    Test-VeroVmWanted, Get-VeroRuleSpec, Enable-VeroKillSwitch, Disable-VeroKillSwitch, Set-VeroVmAccess,
    Invoke-VeroDial, Invoke-VeroReconnect, Get-VeroStatus, Invoke-VeroAction
