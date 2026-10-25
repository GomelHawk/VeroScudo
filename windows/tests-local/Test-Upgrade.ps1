#Requires -RunAsAdministrator
<#
  Upgrade test: install the previous release, then this checkout over it (twice), and check what a user would see.
  Uses the real install ($InstallDir) and keeps config.json; ends with this checkout installed. ~1 min, no network
  interruption (only the tray restarts). Run before every release:
    .\Test-Upgrade.ps1                      # previous = newest GitHub release older than this checkout
    .\Test-Upgrade.ps1 -OldTag v1.0.0       # a specific release
    .\Test-Upgrade.ps1 -OldDir C:\x\VeroScudo-windows   # an unpacked release folder (offline)
#>
param([string]$OldTag, [string]$OldDir, [string]$InstallDir = "$env:ProgramFiles\VeroScudo")
$ErrorActionPreference = 'Stop'
$Repo = 'GomelHawk/VeroScudo'
$NewSrc = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $NewSrc 'VeroScudo.Core.psm1') -Force
$NewVer = Get-VeroVersion
$p = Get-VeroPath; New-Item $p.State -ItemType Directory -Force | Out-Null
$Out = Join-Path $p.State 'test-upgrade.log'; '' | Set-Content $Out
function L($m) { $l = '{0:HH:mm:ss} {1}' -f (Get-Date), $m; Add-Content $Out $l; Write-Host $l }
$fails = New-Object System.Collections.Generic.List[string]
function Check([string]$name, [bool]$ok, [string]$detail = '') { L ("   {0} {1} {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail); if (-not $ok) { $fails.Add($name) } }
function Get-Tray { @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudoTray\.ps1' }) }
function Install-From([string]$dir) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'Install.ps1') -InstallDir $InstallDir *>&1 | ForEach-Object { L "     | $_" }
    if ($LASTEXITCODE) { throw "Install.ps1 from $dir exited with $LASTEXITCODE" }
}

# --- previous release
$tmp = Join-Path $env:TEMP "veroscudo-upgrade-$PID"
if (-not $OldDir) {
    $rels = @(Invoke-RestMethod "https://api.github.com/repos/$Repo/releases" -Headers @{ 'User-Agent' = 'VeroScudo-test' })
    $rel = if ($OldTag) { $rels | Where-Object tag_name -eq $OldTag | Select-Object -First 1 } else { $rels | Where-Object { $_.tag_name.TrimStart('v') -ne $NewVer } | Select-Object -First 1 }
    if (-not $rel) { throw "no previous release on GitHub$(if ($OldTag) { " named $OldTag" }) - pass -OldDir <an older checkout or unpacked release>" }
    $asset = $rel.assets | Where-Object name -like '*-windows.zip' | Select-Object -First 1
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path $tmp $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing
    Expand-Archive $zip $tmp -Force
    $OldDir = Join-Path $tmp 'VeroScudo-windows'
    $OldTag = $rel.tag_name
} elseif (-not $OldTag) {
    $m = Select-String -Path (Join-Path $OldDir 'VeroScudo.Core.psm1') -Pattern "^\`$script:Version\s*=\s*'(.+)'" -ErrorAction SilentlyContinue
    $OldTag = if ($m) { "local $($m.Matches.Groups[1].Value)" } else { 'local' }
}
L "=== upgrade test: $OldTag ($OldDir) -> $NewVer ($NewSrc)"

$armedBefore = Test-VeroArmed
# a 1.0 installer only reads the 1.0 single-profile config: save the current file, hand the old installer what a real 1.0
# user has, and put the saved file back at the end (overwritten in `finally`, never deleted)
$cfgSaved = Join-Path $p.State 'config-before-upgrade-test.json'
Copy-Item -LiteralPath $p.Config -Destination $cfgSaved -Force
try {
    if ((Get-Content $p.Config -Raw | ConvertFrom-Json).PSObject.Properties['profiles']) {
        $c = Get-VeroConfig
        [ordered]@{ vpn = [ordered]@{ profile = $c.Profile; server = $c.Server; port = $c.Port; username = $c.Username }
                    retrySeconds = $c.RetrySeconds; vm = $c.Vm; wifiRecoveryFix = $c.WifiRecoveryFix; updateCheck = $c.UpdateCheck
                    lanAllow = @($c.LanAllow) } | ConvertTo-Json -Depth 5 | Set-Content $p.Config -Encoding UTF8
        L "   config written in the 1.0 format for the old installer (current one saved: $cfgSaved)"
    }
    L '1. install the previous release'; Install-From $OldDir; Start-Sleep 3
    L "   trays running after old install: $(@(Get-Tray).Count)"

    foreach ($round in 1, 2) {
        L "$($round + 1). install this checkout over it$(if ($round -eq 2) { ' again (rerun)' })"
        $t0 = Get-Date; Install-From $NewSrc; Start-Sleep 5
        $trays = @(Get-Tray)   # a single result would otherwise unroll to a bare object without .Count
        Check 'one tray running' ($trays.Count -eq 1) "($($trays.Count))"
        Check 'tray is the new one' (@($trays | Where-Object { $_.CreationDate -ge $t0 }).Count -eq $trays.Count -and $trays.Count -gt 0)
        $ver = (Select-String -Path (Join-Path $InstallDir 'VeroScudo.Core.psm1') -Pattern "^\`$script:Version\s*=\s*'(.+)'").Matches.Groups[1].Value
        Check 'installed version' ($ver -eq $NewVer) "($ver)"
        foreach ($f in 'VeroScudo.Core.psm1', 'VeroScudo.Native.cs', 'VeroScudo.ps1', 'VeroScudoTray.ps1', 'run.vbs', 'Set-VpnCredential.ps1', 'Uninstall.ps1') {
            Check "file $f up to date" ((Get-FileHash (Join-Path $InstallDir $f)).Hash -eq (Get-FileHash (Join-Path $NewSrc $f)).Hash)
        }
        Check 'native helper compiled' (Test-Path (Join-Path $InstallDir 'VeroScudo.Native.dll'))
        Check 'kill-switch matches the on/off state' (((Get-VeroWfpCount) -gt 0) -eq $armedBefore) "(filters $(Get-VeroWfpCount))"
        Check 'no 1.0 firewall rules left' (-not (Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue))
        Check 'tray runs without admin rights' ((Get-ScheduledTask -TaskPath '\VeroScudo\' -TaskName Tray).Principal.RunLevel -eq 'Limited')
        $acl = (Get-Acl $p.Home).Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0' -and $_.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles' }
        Check 'state folder not writable by users' (-not $acl)
        $icons = Join-Path $InstallDir 'icons'
        Check 'no nested icons\icons' (-not (Test-Path (Join-Path $icons 'icons')))
        foreach ($i in 'app\app.ico', 'app\app-128.png', 'png\protected.ico', 'badge\protected.ico', 'png\protected-64.png') {
            Check "icon $i" (Test-Path (Join-Path $icons $i))
        }
        $tasks = @(@(Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue).TaskName)
        Check 'scheduled tasks' (-not (Compare-Object $tasks @('Connected', 'Off', 'On', 'Switch', 'Terminated', 'Tray', 'Watchdog'))) "($($tasks -join ','))"
        Check 'VPN on/off state unchanged' ((Test-VeroArmed) -eq $armedBefore)
        Check 'config is in the profiles format' ([bool](Get-Content $p.Config -Raw | ConvertFrom-Json).PSObject.Properties['profiles'])
    }
    $missing = Select-String -Path $p.Log -Pattern 'WARNING: missing' -SimpleMatch -ErrorAction SilentlyContinue | Where-Object { [datetime]::ParseExact($_.Line.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $t0 }
    Check 'tray logged no missing assets' (-not $missing) "$(@($missing).Count) warning(s)"
} catch {
    $fails.Add("exception: $($_.Exception.Message)"); L "   ERROR $($_.Exception.Message)"
} finally {
    Copy-Item -LiteralPath $cfgSaved -Destination $p.Config -Force; L "   config restored from $cfgSaved"
    if ($tmp -like "$env:TEMP\veroscudo-upgrade-*") { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    L ''
    L '=== VERDICT'
    L "upgrade $OldTag -> $NewVer : $(if ($fails.Count) { "FAIL ($($fails -join '; '))" } else { 'PASS' })"
    L "log: $Out"
}
if ($fails.Count) { exit 1 }
