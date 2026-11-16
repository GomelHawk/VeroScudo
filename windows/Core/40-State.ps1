# VeroScudo core, part 40: logging and the armed state.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- logging & state
function Write-VeroLog {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Message, [string]$Action = 'core')
    $p = Get-VeroPath
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Action, $Message
    # nothing in here may throw: a log line sits between the steps of an arm, a sync and an Off. The folder and the
    # rotation too - a log file somebody holds open cannot be moved
    try {
        if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
        if ((Test-Path $p.Log) -and (Get-Item $p.Log).Length -gt 2MB) { Move-Item $p.Log "$($p.Log).1" -Force }
    } catch { Write-Verbose "log rotation skipped: $($_.Exception.Message)" }
    # several processes write this file (watchdog, event tasks, On/Off, the OpenVPN runner): a line that cannot be written
    # because another one is writing is tried once more and then dropped - a log line must never stop an arm or a sync halfway
    try { Add-Content -Path $p.Log -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch {
        Start-Sleep -Milliseconds 50
        try { Add-Content -Path $p.Log -Value $line -Encoding UTF8 -ErrorAction Stop } catch { Write-Verbose "log line not written: $($_.Exception.Message)" }
    }
    Write-Host $line
}
function Write-VeroStateFile {
    <# A state file other processes read (the tray, the watchdog, the event tasks): written whole - to a
       temporary file of this process beside it, then put in the old one's place in one step (only when a reader holds the
       old file open for the whole of four tries is it written over in place, where a reader can meet it empty for an instant) (File.Replace: the name never
       points at nothing, and two writers never share a temporary file). UTF-8 with its mark: Get-Content and ReadAllText
       both read it back exactly, whatever letters a profile name has - the system's ANSI code page would turn the ones
       it lacks into "?", and a name that no longer compares equal is a marker that no longer counts. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $tmp = '{0}.{1}.new' -f $Path, $PID
    $enc = New-Object Text.UTF8Encoding($true)
    try {
        [IO.File]::WriteAllText($tmp, $Text + "`r`n", $enc)
        # a reader that has the old file open at this instant (the tray looks every 3 s) keeps it from being replaced:
        # tried again a few times, and as the last way the old file is written over in place - a reader that shares it
        # for writing allows that, and a file written late is better than one not written
        for ($i = 0; $i -lt 4; $i++) {
            try {
                if ([IO.File]::Exists($Path)) { [IO.File]::Replace($tmp, $Path, $null) } else { [IO.File]::Move($tmp, $Path) }
                return
            } catch { Start-Sleep -Milliseconds 30 }
        }
        [IO.File]::WriteAllText($Path, $Text + "`r`n", $enc)
    } finally {
        # this process's own temporary file never stays behind (every task is a new process: nothing would remove it later)
        if ([IO.File]::Exists($tmp)) { try { [IO.File]::Delete($tmp) } catch { Write-Verbose "temporary file kept: $tmp" } }
    }
}
function Start-VeroTask {
    <# Starts one of VeroScudo's own scheduled tasks. $false when it could not be started (an install from before the task
       existed, until Install.ps1 has run again) - and always with a redirected home: tests never start an installed task. #>
    [CmdletBinding()] param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z]+\z')][string]$Name)
    if ($script:HomeOverride) { return $false }
    # (local) Windows PowerShell turns what a program writes to its error stream into an error under 'Stop' - and a task
    # that is not there is exactly what this function answers with $false
    $ErrorActionPreference = 'Continue'
    try { & $script:Schtasks /run /tn "\VeroScudo\$Name" 2>&1 | Out-Null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}
function Get-VeroMachineVariable {
    <# The machine's environment variables as they are stored (HKLM), %NAME% left as written: read through the .NET
       environment API they would arrive already filled in from this process's environment - the user's variables. #>
    $h = @{}
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
    if ($k) {
        try { foreach ($n in $k.GetValueNames()) { $h[$n] = [string]$k.GetValue($n, '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } }
        finally { $k.Close() }
    }
    $h
}
function Get-VeroCleanEnvironment {
    <# The environment for a program the elevated guard starts (openvpn.exe): the machine's own variables, the Windows
       folders from the system itself, a PATH of system folders, and a temp folder only administrators can use. Nothing
       of the signed-in user's environment, which any program of that user can add to (HKCU\Environment) - a variable such
       as OPENSSL_CONF or OPENSSL_MODULES makes OpenSSL load a library of the user's choosing, as administrator.
       Returns a hashtable name -> value. Pure apart from reading the machine's variables (-Machine: tests pass their own). #>
    [CmdletBinding()] param($Machine = (Get-VeroMachineVariable))
    $sys = Get-VeroSystemDir System; $win = Split-Path -Parent $sys
    $env_ = @{}
    foreach ($k in @($Machine.Keys)) {
        $n = [string]$k
        # the machine's variables are for every program, but these name code to load or a place to load it from
        if ($n -match '^(OPENSSL_|COR_|CORECLR_|COMPLUS_|DOTNET_|APPDOMAIN_MANAGER_|__COMPAT_LAYER\z|PATH\z|PATHEXT\z|TEMP\z|TMP\z|PSModulePath\z)') { continue }
        # %...% in a machine value is filled in from the system's own folders only - not from this process's environment,
        # which holds the user's variables too; a value that still has one afterwards is left out
        $v = [string]$Machine[$k]
        foreach ($pair in @(@('SystemRoot', $win), @('windir', $win), @('SystemDrive', [IO.Path]::GetPathRoot($win).TrimEnd('\')),
                            @('ProgramFiles', (Get-VeroSystemDir ProgramFiles)), @('ProgramData', (Get-VeroSystemDir ProgramData)))) {
            $v = $v -replace ('%' + [regex]::Escape($pair[0]) + '%'), ([string]$pair[1]).Replace('$', '$$')   # -replace: any letter case
        }
        if ($v -match '%[^%]+%') { continue }
        $env_[$n] = $v
    }
    $env_['SystemRoot'] = $win; $env_['windir'] = $win; $env_['SystemDrive'] = [IO.Path]::GetPathRoot($win).TrimEnd('\')
    $env_['ComSpec'] = Join-Path $sys 'cmd.exe'
    $env_['PATH'] = "$sys;$win;$sys\Wbem;$sys\WindowsPowerShell\v1.0"
    $env_['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $env_['ProgramData'] = Get-VeroSystemDir ProgramData
    $env_['ProgramFiles'] = Get-VeroSystemDir ProgramFiles
    $env_['TEMP'] = Join-Path $win 'Temp'; $env_['TMP'] = $env_['TEMP']
    $env_
}
function Start-VeroCleanProcess {
    <# Starts a program hidden, with Get-VeroCleanEnvironment as its whole environment. Returns the Process. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$FilePath, [string]$ArgumentList = '', [hashtable]$Environment)
    if (-not $Environment) { $Environment = Get-VeroCleanEnvironment }
    $si = New-Object System.Diagnostics.ProcessStartInfo $FilePath
    $si.Arguments = $ArgumentList; $si.UseShellExecute = $false; $si.CreateNoWindow = $true
    $si.WorkingDirectory = Get-VeroSystemDir System
    $si.EnvironmentVariables.Clear()
    foreach ($k in $Environment.Keys) { $si.EnvironmentVariables[[string]$k] = [string]$Environment[$k] }
    [System.Diagnostics.Process]::Start($si)
}
function Write-VeroHeartbeat {
    <# The watchdog is alive and working (the tray's "Guard not running" reads this file's content). #>
    try { Write-VeroStateFile -Path (Get-VeroPath).Heartbeat -Text ([string][int64](Get-VeroEpoch)) } catch { Write-Verbose 'heartbeat not written' }
}
function Test-VeroArmed { Test-Path (Get-VeroPath).ArmedFlag }
function Set-VeroArmed {
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Value, [string]$Action = 'core')
    $p = Get-VeroPath
    if ($Value -and -not (Test-Path $p.ArmedFlag)) { New-Item -ItemType File -Path $p.ArmedFlag -Force | Out-Null; Write-VeroLog 'ARMED' $Action }
    if (-not $Value -and (Test-Path $p.ArmedFlag)) { Remove-Item $p.ArmedFlag -Force; Write-VeroLog 'DISARMED' $Action }
}
function Enter-VeroArmed {
    <# The one way into ARMED, for every caller (On, a VPN connected by hand, the WireGuard and Hiddify watches): the
       server name is looked up while nothing is blocked yet, the flag is set, the filters are applied for the state the
       tunnel is in. The flag comes first: if applying fails, the machine is armed and the sync falls back to its
       emergency block - never the other way round. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    # the lookup only improves the first rules: whatever goes wrong in it, the flag and the filters still follow
    try { Update-VeroServerIpBeforeArm -Config $Config -Action $Action } catch { Write-VeroLog "server lookup before arming failed ($($_.Exception.Message)) - arming with the cached addresses" $Action }
    Set-VeroArmed $true $Action
    Sync-VeroKillSwitch -Config $Config -Action $Action
}
function Read-VeroUserInput {
    <# A small text the unelevated tray left for the guard in the user's own folder (a profile to switch to, a one-time
       code). The elevated guard only ever READS there - it never deletes or writes in a folder the user controls, where a
       link could point the delete at any file. "Taken" is noted in the state folder instead, by the file's time and
       size: each text is handed out once. A link in place of the file or of its folder, or more than 1 KB: nothing.
       -Peek: look without taking. Returns the trimmed text or $null. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+\z')][string]$Name, [switch]$Peek, [double]$MinAgeSeconds = 0)
    try {
        $fi = New-Object IO.FileInfo $Path
        if (-not $fi.Exists -or $fi.Length -gt 1024) { return $null }
        if (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($fi.Directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $null }
        if ($MinAgeSeconds -gt 0 -and ([datetime]::UtcNow - $fi.LastWriteTimeUtc).TotalSeconds -lt $MinAgeSeconds) { return $null }
        $stamp = '{0}:{1}' -f $fi.LastWriteTimeUtc.Ticks, $fi.Length
        $done = Join-Path (Get-VeroPath).State "taken-$Name.txt"
        if ((Test-Path -LiteralPath $done) -and ([IO.File]::ReadAllText($done)).Trim() -eq $stamp) { return $null }
        # one open file, at most 1 KB of it, and one line: whatever this path leads to at the moment it is opened, no more
        # than a short single line is ever taken from it
        $fs = New-Object System.IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            if ($fs.Length -gt 1024) { return $null }
            $buf = New-Object byte[] 1024; $n = $fs.Read($buf, 0, $buf.Length)
        } finally { $fs.Dispose() }
        $text = ((New-Object Text.UTF8Encoding($false)).GetString($buf, 0, $n)).TrimStart([char]0xFEFF).Trim()
        if (-not $Peek) { Write-VeroStateFile -Path $done -Text $stamp }
        if ($text -and $text -notmatch '[\x00-\x1f]') { $text } else { $null }
    } catch { Write-Verbose "user input ${Name}: $($_.Exception.Message)"; $null }
}
function Set-VeroOffStamp {
    <# Your Off, just now: for 30 s nothing arms by itself (Test-VeroRecentOff). Off never fails over this note: if it
       cannot be written, Off goes on without it. #>
    try { Write-VeroStateFile -Path (Get-VeroPath).OffAt -Text (Get-Date).ToString('o') }
    catch { Write-VeroLog "the note that Off just ran could not be written ($($_.Exception.Message)) - turning off all the same" 'off' }
}
function Exit-VeroArmed {
    <# The one way out of ARMED (your Off, your hang-up, deactivating a WireGuard tunnel in its app): the flag goes, then
       every filter. Disable-VeroKillSwitch keeps the filters if something armed again meanwhile. #>
    [CmdletBinding()] param([string]$Action = 'core')
    Set-VeroArmed $false $Action
    Disable-VeroKillSwitch -Action $Action
}
function Stop-VeroGuardState {
    <# The part of Off that needs nothing but the state folder - also the whole of Off when config.json does not load:
       the note that Off just ran (-Stamp: your Off, not a plain disarm), out of ARMED, and no Reconnect marker left. #>
    [CmdletBinding()] param([switch]$Stamp, [string]$Action = 'off')
    if ($Stamp) { Set-VeroOffStamp }
    try { Exit-VeroArmed -Action $Action }
    finally {
        $renew = (Get-VeroPath).Renew
        if (Test-Path -LiteralPath $renew) { Remove-Item -LiteralPath $renew -Force -ErrorAction SilentlyContinue }
    }
}
function Set-VeroActiveProfile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [string]$Action = 'core')
    $p = Get-VeroPath
    $null = Get-VeroConfig -Active $Name                                  # validates the name against config.json
    $cur = if (Test-Path $p.ActiveProfile) { (Get-Content $p.ActiveProfile -Raw).Trim() } else { '' }
    if ($cur -ne $Name) {
        Write-VeroStateFile -Path $p.ActiveProfile -Text $Name               # whole or not at all (read by every task and the tray)
        Write-VeroLog "active profile -> '$Name'" $Action }
}

# ---------------------------------------------------------------- one holder per lock, across every process
function Test-VeroLockDirAcl {
    <# Pure: $true when these access rules (identities as SIDs) let only SYSTEM and Administrators in, and none is inherited.
       Inherited rules are the state folder's - Users may read there, and read is enough to open a lock file with no sharing
       and hold it. Deny rules take nothing away from the guard and are ignored. #>
    [CmdletBinding()] param($Rules)
    foreach ($r in @($Rules | ForEach-Object { $_ } | Where-Object { $_ })) {
        if ($r.IsInherited) { return $false }
        if ([string]$r.AccessControlType -ne 'Allow') { continue }
        if ([string]$r.IdentityReference -notmatch '^(S-1-5-18|S-1-5-32-544)$') { return $false }
    }
    $true
}
function Set-VeroLockDirAcl([string]$Path) {
    <# Elevated: exactly SYSTEM and Administrators, full control, inherited by the lock files; nothing from the parent. The
       DACL is written whole, so a rule someone added by hand goes too (icacls /grant:r would keep it). #>
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    [IO.Directory]::SetAccessControl($Path, $acl)
}
function Get-VeroLockDir {
    <# The lock files' folder: administrators and SYSTEM only. A named mutex in the session namespace could be created first by
       any process of the account (a planted "watchdog" would stall the real one for good); a file nobody else may open cannot.
       Checked on every call by an elevated caller, not only when created: the installer's reset of the state folder once gave
       it back the inherited "Users: read" - enough for any program of the account to open watchdog.lock first and hold it. #>
    $d = Join-Path (Get-VeroPath).State 'locks'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    if ((Test-VeroElevated) -and -not (Test-VeroLockDirAcl (Get-Acl -LiteralPath $d).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        Set-VeroLockDirAcl $d
        Write-VeroLog 'locks folder: access set to Administrators and SYSTEM only' 'lock'
    }
    $d
}
function Enter-VeroSingleton {
    <# Returns a handle that makes this process the one holder of $Name (Dispose releases it), or $null when another process
       holds it after waiting up to $WaitMs. The handle is an exclusive open of a file in the locks folder. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [int]$WaitMs = 0)
    $f = Join-Path (Get-VeroLockDir) "$Name.lock"
    $deadline = (Get-Date).AddMilliseconds($WaitMs)
    while ($true) {
        try { return (New-Object IO.FileStream($f, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)) }
        catch [IO.IOException] { if ((Get-Date) -ge $deadline) { return $null }; Start-Sleep -Milliseconds 200 }
    }
}
function Test-VeroSingletonHeld {
    <# True when some process holds $Name right now. Needs the rights of the locks folder: for a non-administrator (the tray) the
       answer is always $false - it cannot see the guard's locks, and never could. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    $f = Join-Path (Get-VeroPath).State "locks\$Name.lock"
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    try { $h = New-Object IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None); $h.Dispose(); return $false }
    catch [IO.IOException] { return $true }
    catch { return $false }
}
