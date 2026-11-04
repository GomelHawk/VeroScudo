# VeroScudo core, part 81: OpenVPN: config check and import, runner status, the runner.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- OpenVPN: config check and import
# ALLOW-list of client options. VeroScudo runs openvpn.exe as administrator, so an imported config may only use options
# known not to run programs, load modules (plugin, pkcs11-providers, providers, engine), write files or redirect control
# (management, config, log, proxies). Anything else - also an option spelled with quotes or escapes - is refused.
$script:OvpnAllowed = @('client', 'tls-client', 'pull', 'dev', 'dev-type', 'proto', 'remote', 'remote-random', 'remote-random-hostname',
    'resolv-retry', 'nobind', 'persist-key', 'persist-tun', 'persist-remote-ip', 'port', 'rport', 'lport', 'float',
    'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'key-direction', 'extra-certs', 'crl-verify', 'secret', 'dh', 'pkcs12',
    'peer-fingerprint', 'cipher', 'data-ciphers', 'data-ciphers-fallback', 'ncp-ciphers', 'ncp-disable', 'auth', 'tls-version-min',
    'tls-version-max', 'tls-cipher', 'tls-ciphersuites', 'tls-cert-profile', 'tls-groups', 'ecdh-curve', 'remote-cert-tls', 'ns-cert-type',
    'remote-cert-ku', 'remote-cert-eku', 'verify-x509-name', 'x509-username-field', 'tls-timeout', 'hand-window', 'tran-window', 'reneg-sec',
    'reneg-bytes', 'reneg-pkts', 'comp-lzo', 'compress', 'allow-compression', 'comp-noadapt', 'verb', 'mute', 'mute-replay-warnings',
    'replay-window', 'auth-user-pass', 'auth-nocache', 'auth-retry', 'auth-token-user', 'static-challenge', 'redirect-gateway',
    'redirect-private', 'route', 'route-ipv6', 'route-nopull', 'route-delay', 'route-method', 'route-metric', 'route-gateway',
    'route-ipv6-gateway', 'max-routes', 'pull-filter', 'dhcp-option', 'block-outside-dns', 'register-dns', 'ip-win32', 'tap-sleep',
    'dhcp-renew', 'dhcp-release', 'windows-driver', 'disable-dco', 'topology', 'tun-ipv6', 'ifconfig', 'ifconfig-ipv6', 'ifconfig-nowarn',
    'ping', 'ping-restart', 'ping-exit', 'ping-timer-rem', 'keepalive', 'inactive', 'explicit-exit-notify', 'connect-retry',
    'connect-retry-max', 'connect-timeout', 'server-poll-timeout', 'sndbuf', 'rcvbuf', 'fragment', 'mssfix', 'tun-mtu', 'tun-mtu-extra',
    'link-mtu', 'mtu-disc', 'push-peer-info', 'setenv', 'key-method', 'auth-nocache', 'socket-flags', 'bind', 'script-security',
    'remap-usr1', 'single-session', 'tls-exit', 'nice', 'fast-io', 'txqueuelen', 'mark', 'opt-verify', 'auth-token')
$script:OvpnInline = @('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'extra-certs', 'crl-verify', 'secret', 'dh', 'pkcs12', 'peer-fingerprint')

function Test-VeroOpenVpnConf {
    <# Checks an .ovpn and returns @{ Errors; Warnings; Remotes; Auth; StaticChallenge; Text }. Text is the config with every
       referenced key/cert file inlined (what the import stores). Pure apart from -ReadFile (reads those files; tests pass a fake).
       Reads blocks the way OpenVPN does: an inline block ends at the first line that STARTS with </tag>. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$BaseDir = '', [scriptblock]$ReadFile)
    if (-not $ReadFile) { $ReadFile = { param($f) [IO.File]::ReadAllBytes($f) } }
    $errors = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $remotes = New-Object System.Collections.Generic.List[object]
    $out = New-Object System.Text.StringBuilder
    $g = @{ Proto = 'udp'; Port = 1194 }                                    # global defaults
    $c = $null                                                              # the current <connection> block's own proto/port
    $auth = $false; $sc = $false; $redirect = $false; $dns = $false; $pull = $false
    $inBlock = $null
    $toPort = { param($v) if ($v -match '^\d{1,5}$' -and [int]$v -ge 1 -and [int]$v -le 65535) { [int]$v } else { -1 } }
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = $raw.Trim()
        if ($inBlock) {                                                     # inline <ca>...</ca> etc: copied as is
            if ($line.StartsWith("</$inBlock>")) {
                if ($line -ne "</$inBlock>") { $errors.Add("text after </$inBlock> on the same line") }
                $inBlock = $null
            } elseif ($line.StartsWith('<')) { $errors.Add("a tag line inside <$inBlock>: '$line'") }
            [void]$out.AppendLine($raw)
            continue
        }
        if ($line -eq '<connection>') { if ($c) { $errors.Add('nested <connection>') }; $c = @{ Proto = $null; Port = $null }; [void]$out.AppendLine($raw); continue }
        if ($line -eq '</connection>') { $c = $null; [void]$out.AppendLine($raw); continue }
        if ($line -match '^<([a-z0-9-]+)>$') {
            if ($script:OvpnInline -notcontains $Matches[1]) { $errors.Add("inline <$($Matches[1])> is not allowed"); continue }
            $inBlock = $Matches[1]; [void]$out.AppendLine($raw); continue
        }
        if ($line.StartsWith('<')) { $errors.Add("unexpected tag line '$line'"); continue }
        if (-not $line -or $line -match '^[#;]') { [void]$out.AppendLine($raw); continue }
        $tok = @($line -split '\s+' | Where-Object { $_ })
        $first = $tok[0]
        if ($first.StartsWith('--')) { $first = $first.Substring(2) }
        if ($first -cnotmatch '^[a-z0-9-]+$') { $errors.Add("'$($tok[0])' is not allowed: option names must be plain (no quotes, escapes or capitals)"); continue }
        $d = $first
        $arg = @($tok | Select-Object -Skip 1)
        if ($script:OvpnAllowed -notcontains $d) { $errors.Add("'$d' is not allowed: VeroScudo runs OpenVPN as administrator and accepts only known client options (remove the line)"); continue }
        if ($d -eq 'script-security' -and -not ($arg.Count -gt 0 -and $arg[0] -in '0', '1')) { $errors.Add("'script-security $($arg -join ' ')' would let the config run programs as administrator (remove the line)"); continue }
        if ($d -eq 'setenv' -and $arg.Count -gt 0 -and $arg[0] -eq 'opt') { $errors.Add("'setenv opt' would hide unknown options (remove the line)"); continue }
        $skip = $false                                                      # NB: 'continue' inside a switch would not skip this line
        switch ($d) {
            'proto' { if ($arg.Count) { $v = if ($arg[0] -like 'tcp*') { 'tcp' } else { 'udp' }; if ($c) { $c.Proto = $v } else { $g.Proto = $v } } }
            { $_ -in 'port', 'rport' } {
                $v = if ($arg.Count) { & $toPort $arg[0] } else { -1 }
                if ($v -lt 0) { $errors.Add("'$d' needs a port 1-65535"); break }
                if ($c) { $c.Port = $v } else { $g.Port = $v }
            }
            'remote' {
                if ($arg.Count -lt 1) { $errors.Add("'remote' without a server"); break }
                $pt = 0
                if ($arg.Count -ge 2) { $pt = & $toPort $arg[1]; if ($pt -lt 0) { $errors.Add("remote '$($arg[0])': port must be 1-65535"); break } }
                $r = [pscustomobject]@{ Host = $arg[0]; Port = $pt; Proto = $(if ($arg.Count -ge 3) { if ($arg[2] -like 'tcp*') { 'tcp' } else { 'udp' } } else { '' }); Block = $c }
                if (-not (Test-VeroHost $r.Host)) { $errors.Add("invalid remote '$($r.Host)'") } else { $remotes.Add($r) }
            }
            'auth-user-pass' {
                $auth = $true
                if ($arg.Count -gt 0) { $warn.Add("'auth-user-pass $($arg[0])' keeps the password in a plain file. VeroScudo ignores that file and uses the password stored in VeroScudo (tray Settings) - delete the file.") }
                [void]$out.AppendLine('auth-user-pass'); $skip = $true
            }
            'static-challenge' { $sc = $true; $warn.Add('This config asks for a one-time code (static-challenge). Every connect, also an automatic redial, waits for you to type the code in the tray.') }
            'redirect-gateway' { $redirect = $true }
            'pull' { $pull = $true }
            'client' { $pull = $true }
            'dhcp-option' { if ($arg.Count -ge 2 -and $arg[0] -eq 'DNS') { $dns = $true } }
        }
        if ($skip) { continue }
        if ($script:OvpnInline -contains $d -and $arg.Count -ge 1 -and $arg[0] -ne '[inline]') {
            if ($d -eq 'crl-verify' -and $arg.Count -ge 2 -and $arg[1] -eq 'dir') { $errors.Add("'crl-verify ... dir' cannot be imported - use a CRL file"); continue }
            $file = $arg[0]
            $full = if ([IO.Path]::IsPathRooted($file) -or -not $BaseDir) { $file } else { [IO.Path]::Combine($BaseDir, $file) }   # no drive check: pure
            try { $bytes = & $ReadFile $full } catch { $errors.Add("'$d $file': file not found or unreadable"); continue }
            $body = if ($d -eq 'pkcs12') { [Convert]::ToBase64String($bytes) } else { ([Text.Encoding]::UTF8.GetString($bytes)).Trim() }
            # a key file must not be able to close its block early and smuggle options in
            if (@($body -split "`r?`n" | Where-Object { $_.Trim().StartsWith('<') }).Count -gt 0) { $errors.Add("'$d $file' contains a tag line ('<...>') - not a plain key/cert file"); continue }
            [void]$out.AppendLine("<$d>"); [void]$out.AppendLine($body); [void]$out.AppendLine("</$d>")
            if ($d -eq 'tls-auth' -and $arg.Count -ge 2) { [void]$out.AppendLine("key-direction $($arg[1])") }
            continue
        }
        [void]$out.AppendLine($raw)
    }
    if ($inBlock) { $errors.Add("inline block <$inBlock> is not closed") }
    if ($c) { $errors.Add('<connection> is not closed') }
    # a remote's own proto/port, else its <connection> block's, else the global one
    $resolved = @(foreach ($r in $remotes) {
        $bp = if ($r.Block) { $r.Block.Port } else { $null }; $bq = if ($r.Block) { $r.Block.Proto } else { $null }
        [pscustomobject]@{ Host = $r.Host; Port = $(if ($r.Port) { $r.Port } elseif ($bp) { $bp } else { $g.Port }); Proto = $(if ($r.Proto) { $r.Proto } elseif ($bq) { $bq } else { $g.Proto }) } })
    if ($resolved.Count -eq 0) { $errors.Add("no 'remote' line - VeroScudo needs the server to allow it through the kill-switch") }
    if ($resolved.Count -gt 16) { $errors.Add('more than 16 remote servers - keep the ones you use') }
    if (-not $redirect) {
        if ($pull) { $warn.Add("No 'redirect-gateway' in the file: fine if the server pushes it. If it does not (split tunnel), everything outside the tunnel stays blocked while VeroScudo is on.") }
        else { $warn.Add("No 'redirect-gateway': only the tunnel's own routes work; everything else stays blocked while VeroScudo is on.") }
    }
    if (-not $dns -and -not $pull) { $warn.Add("No DNS server for the tunnel ('dhcp-option DNS'): names may not resolve while VeroScudo blocks the local network's DNS.") }
    [pscustomobject]@{ Errors = @($errors); Warnings = @($warn); Remotes = $resolved; Auth = $auth; StaticChallenge = $sc; Text = $out.ToString() }
}

function Import-VeroOpenVpnProfile {
    <# Elevated: checks the user's .ovpn once more, inlines its key files and stores the result as the admin-only copy that
       openvpn.exe will run. Returns the check result (warnings). Throws on any error - nothing is written then. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [Parameter(Mandatory)][string]$Source)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "OpenVPN config not found: $Source" }
    $text = [IO.File]::ReadAllText($Source)                                # read once: what is checked is what is stored
    $r = Test-VeroOpenVpnConf -Text $text -BaseDir (Split-Path -Parent $Source)
    if ($r.Errors.Count -gt 0) { throw ("OpenVPN config '{0}' refused: {1}" -f $Source, ($r.Errors -join '; ')) }
    # what is stored is checked once more as a whole (inlined key files included)
    $again = Test-VeroOpenVpnConf -Text $r.Text -ReadFile { param($x) throw "unexpected file reference $x" }
    if ($again.Errors.Count -gt 0) { throw ("OpenVPN config '{0}' refused after inlining: {1}" -f $Source, ($again.Errors -join '; ')) }
    $null = Protect-VeroOpenVpnDir
    $dst = (Get-VeroPath -VpnProfile $ProfileName).OvpnConfig
    [IO.File]::WriteAllText($dst, $r.Text, (New-Object Text.UTF8Encoding($false)))
    Write-VeroLog "OpenVPN profile '$ProfileName' imported from $Source ($($r.Remotes.Count) server(s); password: $($r.Auth))" 'import'
    $r
}

function Get-VeroOpenVpnRemote {
    <# The 'remote' servers of an imported profile (admin copy). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $f = (Get-VeroPath -VpnProfile $ProfileName).OvpnConfig
    if (-not (Test-Path $f)) { return @() }
    @((Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($f)) -ReadFile { param($x) $null = $x; [byte[]]@() }).Remotes)
}

$script:OvpnExe = $null
# VeroScudo's own TAP adapter for OpenVPN profiles (without DCO OpenVPN otherwise takes ANY free TAP adapter - seen live:
# the one the PrivateVPN app installed and named "PrivateVPN", which also clashes when that app runs at the same time).
$script:OvpnAdapter = 'VeroScudo OpenVPN'
$script:OvpnAdapterNoted = $false
function Get-VeroTapctl {
    <# tapctl.exe, shipped next to openvpn.exe by the OpenVPN community installer. #>
    $exe = Get-VeroOpenVpnExe
    if (-not $exe) { return '' }
    $t = Join-Path (Split-Path $exe -Parent) 'tapctl.exe'
    if (Test-Path -LiteralPath $t -PathType Leaf) { $t } else { '' }
}
function Test-VeroOpenVpnAdapter { [bool](Get-VeroNic | Where-Object { [string]$_.Name -eq $script:OvpnAdapter } | Select-Object -First 1) }
function Initialize-VeroOpenVpnAdapter {
    <# Makes sure the 'VeroScudo OpenVPN' adapter exists (elevated: installer, OpenVPN runner). True when OpenVPN can be
       pinned to it; false = OpenVPN keeps choosing a free TAP adapter itself (said once per process, in the log). #>
    [CmdletBinding()] param([string]$Action = 'core')
    if (Test-VeroOpenVpnAdapter) { return $true }
    $t = Get-VeroTapctl
    $why = ''
    if (-not $t) { $why = 'tapctl.exe not found next to openvpn.exe' }
    else {
        $out = & $t create --hwid 'root\tap0901' --name $script:OvpnAdapter 2>&1
        $code = $LASTEXITCODE
        $deadline = (Get-Date).AddSeconds(5)
        while (-not (Test-VeroOpenVpnAdapter) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
        if (Test-VeroOpenVpnAdapter) { Write-VeroLog "created network adapter '$($script:OvpnAdapter)' for VeroScudo's OpenVPN profiles" $Action; return $true }
        $why = "tapctl create failed (exit $code): $((@($out) | ForEach-Object { [string]$_ }) -join ' ') - is the TAP-Windows driver installed?"
    }
    if (-not $script:OvpnAdapterNoted) { Write-VeroLog "NOTE: no '$($script:OvpnAdapter)' adapter ($why) - OpenVPN uses any free TAP adapter" $Action; $script:OvpnAdapterNoted = $true }
    $false
}
function Remove-VeroOpenVpnAdapter {
    <# Uninstall: removes the adapter VeroScudo created (only that one, by its exact name). #>
    [CmdletBinding()] param([string]$Action = 'uninstall')
    if (-not (Test-VeroOpenVpnAdapter)) { return }
    $t = Get-VeroTapctl
    if (-not $t) { Write-VeroLog "WARNING: '$($script:OvpnAdapter)' adapter left in place - tapctl.exe not found (remove it in Device Manager)" $Action; return }
    $out = & $t delete $script:OvpnAdapter 2>&1
    if ($LASTEXITCODE -eq 0) { Write-VeroLog "removed network adapter '$($script:OvpnAdapter)'" $Action }
    else { Write-VeroLog "WARNING: could not remove the '$($script:OvpnAdapter)' adapter: $((@($out) | ForEach-Object { [string]$_ }) -join ' ')" $Action }
}

function Get-VeroOpenVpnExe {
    <# openvpn.exe of the OpenVPN community installer (HKLM, administrators only), else its default location. #>
    if ($script:OvpnExe) { return $script:OvpnExe }
    $cand = @()
    try { $k = Get-ItemProperty 'HKLM:\SOFTWARE\OpenVPN' -ErrorAction Stop; if ($k.PSObject.Properties['exe_path']) { $cand += [string]$k.exe_path } } catch { Write-Verbose 'no OpenVPN registry key' }
    $cand += (Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\bin\openvpn.exe')
    foreach ($c in $cand) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $script:OvpnExe = $c; return $c } }
    ''
}

function Get-VeroOpenVpnVersion([string]$Exe) {
    try { $v = (& $Exe --version 2>&1 | Select-Object -First 1) -join ''; if ($v -match 'OpenVPN (\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] } } catch { Write-Verbose 'openvpn --version failed' }
    [version]'0.0'
}

function Get-VeroOpenVpnArgs {
    <# The openvpn.exe command line. Pure. The user's file is used as is; VeroScudo's own options come after it so they win:
       management on localhost with a one-time password, hold until we release, passwords asked over the management
       connection (never a file), no user scripts, our log, and no DCO unless the profile allows it (then the permit can be
       tied to openvpn.exe). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConfigPath, [Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][string]$PwFile,
                            [Parameter(Mandatory)][string]$LogPath, [version]$Version = [version]'2.6', [bool]$Dco = $false, [bool]$Auth = $true,
                            [string]$DevNode = '')
    $q = { param($x) '"' + ($x -replace '"', '') + '"' }
    $a = @('--config', (& $q $ConfigPath), '--management', '127.0.0.1', $Port, (& $q $PwFile), '--management-hold', '--management-query-passwords',
           '--auth-retry', 'interact', '--auth-nocache', '--script-security', '1', '--log', (& $q $LogPath), '--verb', '3')
    if ($Auth) { $a += '--auth-user-pass' }                                 # overrides any file named in the config
    if (-not $Dco -and $Version -ge [version]'2.6') { $a += '--disable-dco' }
    if ($DevNode -and -not $Dco) { $a += @('--dev-node', (& $q $DevNode)) }  # VeroScudo's own TAP adapter, never another app's
    $a -join ' '
}

function ConvertFrom-VeroMgmtLine {
    <# One line of the OpenVPN management interface -> what it means. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    $r = [ordered]@{ Kind = 'other'; State = ''; Reason = ''; LocalIp = ''; Which = ''; Challenge = ''; Dynamic = $false }
    if ($Line -match '^>STATE:\d*,([A-Z_]+),([^,]*),([^,]*)') {
        $r.Kind = 'state'; $r.State = $Matches[1]; $r.Reason = $Matches[2]; $r.LocalIp = $Matches[3]
    } elseif ($Line -match "^>PASSWORD:Need '([^']+)'(.*)$") {
        $r.Kind = 'need'; $r.Which = $Matches[1]
        if ($Matches[2] -match 'SC:\d+,(.*)$') { $r.Challenge = $Matches[1].Trim(); if (-not $r.Challenge) { $r.Challenge = 'one-time code' } }
    } elseif ($Line -match "^>PASSWORD:Verification Failed: '([^']+)'(.*)$") {
        $r.Kind = 'failed'; $r.Which = $Matches[1]; $r.Dynamic = ($Matches[2] -match 'CRV1:')
    } elseif ($Line -match '^>HOLD:') { $r.Kind = 'hold' }
    elseif ($Line -match '^>FATAL:(.*)$') { $r.Kind = 'fatal'; $r.Reason = $Matches[1] }
    elseif ($Line -match '^ERROR:(.*)$') { $r.Kind = 'error'; $r.Reason = $Matches[1].Trim() }
    [pscustomobject]$r
}

function Format-VeroMgmtValue {
    <# A value for a management command: quoted, backslash and double quote escaped. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -match '[\r\n]') { throw 'line breaks are not allowed in a credential' }
    '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

function Get-VeroStaticChallengeResponse {
    <# OpenVPN static-challenge password: SCRV1:<base64 password>:<base64 response>. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Password, [Parameter(Mandatory)][AllowEmptyString()][string]$Response)
    'SCRV1:{0}:{1}' -f [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password)), [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Response))
}

# ---------------------------------------------------------------- OpenVPN: runner status (state folder, written elevated)
function Get-VeroOpenVpnStatus([string]$ProfileName) {
    $f = (Get-VeroPath -VpnProfile $ProfileName).OvpnStatus
    if (Test-Path $f) { try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { Write-Verbose 'openvpn status unreadable' } }
    $null
}
function Set-VeroOpenVpnStatus([string]$ProfileName, [hashtable]$Fields) {
    $p = Get-VeroPath -VpnProfile $ProfileName
    $cur = [ordered]@{ State = ''; Reason = ''; LocalIp = ''; RunnerPid = 0; OvpnPid = 0; Challenge = ''; Time = '' }
    $old = Get-VeroOpenVpnStatus $ProfileName
    if ($old) { foreach ($k in @($cur.Keys)) { if ($old.PSObject.Properties[$k]) { $cur[$k] = $old.$k } } }
    foreach ($k in $Fields.Keys) { $cur[$k] = $Fields[$k] }
    $cur.Time = (Get-Date).ToString('o')
    $tmp = "$($p.OvpnStatus).new"
    $cur | ConvertTo-Json | Set-Content $tmp
    Move-Item $tmp $p.OvpnStatus -Force
}

function Get-VeroOpenVpnNic([string]$ProfileName) {
    <# The tunnel adapter that carries the address OpenVPN reported on CONNECTED - only a tunnel adapter, never a physical NIC. #>
    $s = Get-VeroOpenVpnStatus $ProfileName
    if (-not $s -or [string]$s.State -ne 'CONNECTED' -or -not [string]$s.LocalIp) { return $null }
    $ip = [string]$s.LocalIp
    Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and (Test-VeroTunnelAdapter $_) -and
                                 (@($_.GetIPProperties().UnicastAddresses | ForEach-Object { $_.Address.ToString() }) -contains $ip) } | Select-Object -First 1
}

function Test-VeroOpenVpnRunnerAlive {
    $m = $null
    try { if ([System.Threading.Mutex]::TryOpenExisting('Local\VeroScudo-OpenVPN', [ref]$m)) { $m.Dispose(); return $true } } catch { Write-Verbose 'mutex check failed' }
    $false
}

function Invoke-VeroOpenVpnDial {
    <# Makes sure the OpenVPN runner (a long-running elevated task) is up, then waits up to 30 s for CONNECTED. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $p = Get-VeroPath -VpnProfile $Config.Profile
    if (-not (Test-Path $p.OvpnConfig)) { Write-VeroLog "ERROR: OpenVPN profile '$($Config.Profile)' is not imported (tray Settings, or Install.ps1 -OpenVpnConfig)" $Action; return }
    if (-not (Get-VeroOpenVpnExe)) { Write-VeroLog 'ERROR: openvpn.exe not found - install OpenVPN (community edition, openvpn.net/community)' $Action; return }
    if (-not (Test-VeroOpenVpnRunnerAlive)) {
        Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue
        Set-VeroOpenVpnStatus $Config.Profile @{ State = 'STARTING'; Reason = ''; LocalIp = ''; Challenge = '' }   # not the last run's result
        Write-VeroLog "starting OpenVPN for '$($Config.Profile)'" $Action
        & $script:Schtasks /run /tn '\VeroScudo\OpenVPN' 2>&1 | Out-Null
    }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 30) {
        Start-Sleep -Seconds 1
        if (Test-VeroVpnConnected $Config.Profile -Type 'openvpn') { return }
        if (Get-VeroPendingSwitch) { return }                                # you chose another profile: the loop switches
        $s = Get-VeroOpenVpnStatus $Config.Profile
        if ($s -and [string]$s.State -in 'AUTH_FAILED', 'NO_PASSWORD', 'NEED_OTP') { return }
    }
}

function Stop-VeroOpenVpn {
    <# Asks the runner to stop OpenVPN (it sends SIGTERM over the management connection); kills a leftover process only
       when it really is that openvpn.exe. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    Set-Content -Path $p.OvpnStop -Value (Get-Date).ToString('o')
    $t = Get-Date
    while ((Test-VeroOpenVpnRunnerAlive) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }   # gone, so a redial starts a fresh one
    Stop-VeroOpenVpnOrphan -ProfileName $ProfileName
}

function Stop-VeroOpenVpnOrphan([string]$ProfileName) {
    $s = Get-VeroOpenVpnStatus $ProfileName
    if (-not $s -or -not $s.OvpnPid) { return }
    $proc = Get-Process -Id ([int]$s.OvpnPid) -ErrorAction SilentlyContinue
    $started = try { $proc.StartTime } catch { $null }
    $when = try { [datetime]::Parse([string]$s.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind) } catch { Get-Date }
    if ($proc -and $proc.ProcessName -eq 'openvpn' -and $started -and $started -le $when) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-VeroLog "stopped a leftover openvpn.exe (PID $($proc.Id)) of '$ProfileName'" 'openvpn'
    }
}

# ---------------------------------------------------------------- OpenVPN: the runner (elevated task \VeroScudo\OpenVPN)
function Get-VeroFreePort {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop(); $port
}
function New-VeroSecret {
    $b = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b); $rng.Dispose()
    [Convert]::ToBase64String($b) -replace '[+/=]', 'x'
}

function Send-VeroMgmt($M, [string]$Command) {
    $b = [Text.Encoding]::UTF8.GetBytes($Command + "`n")
    $M.Stream.Write($b, 0, $b.Length); $M.Stream.Flush()
}

function Read-VeroMgmt($M, [int]$TimeoutMs = 1000) {
    <# Complete lines that arrived within the timeout; $null once the connection closed. #>
    $sock = $M.Client.Client
    if ($sock.Poll($TimeoutMs * 1000, [System.Net.Sockets.SelectMode]::SelectRead)) {
        if ($sock.Available -eq 0) { return $null }
        $buf = New-Object byte[] 8192
        $n = $M.Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return $null }
        [void]$M.Pending.Append([Text.Encoding]::UTF8.GetString($buf, 0, $n))
    }
    $text = $M.Pending.ToString()
    $i = $text.LastIndexOf("`n")
    if ($i -lt 0) { return , @() }
    $M.Pending.Length = 0; [void]$M.Pending.Append($text.Substring($i + 1))
    , @($text.Substring(0, $i) -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ })
}

function Connect-VeroMgmt([int]$Port, [string]$Password, $Process) {
    <# Connects to the management port (OpenVPN opens it a moment after start) and logs in with the one-time password. #>
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 15 -and -not $Process.HasExited) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect([System.Net.IPAddress]::Loopback, $Port)
            $m = [pscustomobject]@{ Client = $c; Stream = $c.GetStream(); Pending = (New-Object System.Text.StringBuilder) }
            $t2 = Get-Date
            while (((Get-Date) - $t2).TotalSeconds -lt 5) {
                $null = Read-VeroMgmt $m 500
                if ($m.Pending.ToString() -match 'ENTER PASSWORD:') { $m.Pending.Length = 0; Send-VeroMgmt $m $Password; return $m }
            }
            $c.Close()
        } catch { Start-Sleep -Milliseconds 300 }
    }
    $null
}

function Get-VeroOpenVpnStopReason([string]$ProfileName) {
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (Test-Path $p.OvpnStop) { return 'stop requested' }
    if (-not (Test-VeroArmed)) { return 'VPN turned off' }
    $c = Get-VeroConfig
    if ($c.Profile -ne $ProfileName) { return "profile switched to '$($c.Profile)'" }
    $null
}

function Invoke-VeroOpenVpnSession {
    <# One openvpn.exe run, driven through its management connection. Returns why it ended:
       'stopped' (VeroScudo asked), 'exited' (OpenVPN ended on its own - a failure), 'auth-failed', 'no-password', 'otp' or 'setup'. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'openvpn')
    $name = $Config.Profile
    $p = Get-VeroPath -VpnProfile $name
    $exe = Get-VeroOpenVpnExe
    if (-not $exe -or -not (Test-Path $p.OvpnConfig)) { Write-VeroLog "ERROR: OpenVPN not installed or '$name' not imported" $Action; return 'setup' }
    $cred = if ($Config.Auth) { Get-VeroCredential -Config $Config } else { $null }
    if ($Config.Auth -and -not $cred) { Set-VeroOpenVpnStatus $name @{ State = 'NO_PASSWORD'; Reason = 'no stored password' }; Write-VeroLog "ERROR: no stored password for '$name' (tray Settings)" $Action; return 'no-password' }
    $port = Get-VeroFreePort; $secret = New-VeroSecret
    Write-VeroSecretFile -Path $p.OvpnPw -Text $secret
    $dev = if (-not $Config.Dco -and (Initialize-VeroOpenVpnAdapter -Action $Action)) { $script:OvpnAdapter } else { '' }
    $argLine = Get-VeroOpenVpnArgs -ConfigPath $p.OvpnConfig -Port $port -PwFile $p.OvpnPw -LogPath $p.OvpnLog -Version (Get-VeroOpenVpnVersion $exe) -Dco $Config.Dco -Auth $Config.Auth -DevNode $dev
    # the previous run's log is kept (OpenVPN rewrites its log on every start - a failed start's log was lost that way)
    if (Test-Path $p.OvpnLog) { Move-Item -LiteralPath $p.OvpnLog -Destination ($p.OvpnLog -replace '\.log$', '.prev.log') -Force -ErrorAction SilentlyContinue }
    $proc = Start-Process -FilePath $exe -ArgumentList $argLine -WindowStyle Hidden -PassThru
    Set-VeroOpenVpnStatus $name @{ State = 'STARTING'; Reason = ''; LocalIp = ''; RunnerPid = $PID; OvpnPid = $proc.Id; Challenge = '' }
    $result = 'exited'; $reason = ''; $m = $null; $stopping = $null; $deadline = $null
    # what OpenVPN said last (never what VeroScudo sent - that holds the credentials): logged when a start makes no progress
    $trace = New-Object System.Collections.Generic.Queue[string]
    $progress = Get-Date; $curState = 'STARTING'; $waitingOtp = $false
    try {
        $m = Connect-VeroMgmt -Port $port -Password $secret -Process $proc
        Remove-Item $p.OvpnPw -Force -ErrorAction SilentlyContinue
        if (-not $m) { $reason = 'management interface did not answer' }
        else { Send-VeroMgmt $m 'state on'; Send-VeroMgmt $m 'hold release' }
        while ($m) {
            if (-not $stopping) {
                $stopping = Get-VeroOpenVpnStopReason $name
                if ($stopping) { Write-VeroLog "stopping OpenVPN '$name' ($stopping)" $Action; Send-VeroMgmt $m 'signal SIGTERM'; $deadline = (Get-Date).AddSeconds(10); $result = 'stopped'; $reason = $stopping }
            } elseif ((Get-Date) -gt $deadline) { break }
            $lines = Read-VeroMgmt $m 1000
            if ($null -eq $lines) { break }
            # no progress for 45 s before CONNECTED (no new state, no password asked): restart it instead of waiting for ever
            # (seen live twice: a start sat in STARTING, OpenVPN never asked for the password; the next start took 7 s)
            if (-not $stopping -and -not $waitingOtp -and $curState -ne 'CONNECTED' -and ((Get-Date) - $progress).TotalSeconds -gt 45) {
                Write-VeroLog ("OpenVPN '{0}' made no progress for 45 s (state {1}) - restarting it. Last from OpenVPN: {2}" -f $name, $curState, ((@($trace) | Select-Object -Last 8) -join ' | ')) $Action
                Send-VeroMgmt $m 'signal SIGTERM'; $stopping = 'no progress for 45 s'; $deadline = (Get-Date).AddSeconds(10); $reason = $stopping
            }
            foreach ($line in $lines) {
                if ($line -notmatch '^>PASSWORD:Verification|^>BYTECOUNT') { $trace.Enqueue($line); while ($trace.Count -gt 30) { $null = $trace.Dequeue() } }
                $e = ConvertFrom-VeroMgmtLine $line
                if ($e.Kind -in 'state', 'need', 'hold') { $progress = Get-Date; if ($e.Kind -eq 'state') { $curState = $e.State } }
                switch ($e.Kind) {
                    'hold' { Send-VeroMgmt $m 'hold release' }
                    'state' {
                        Set-VeroOpenVpnStatus $name @{ State = $e.State; Reason = $e.Reason; LocalIp = $(if ($e.State -eq 'CONNECTED') { $e.LocalIp } else { '' }) }
                        if ($e.State -in 'CONNECTED', 'RECONNECTING', 'EXITING') {
                            Write-VeroLog "OpenVPN '$name': $($e.State)$(if ($e.Reason) { ' (' + $e.Reason + ')' })" $Action
                            if ($e.State -eq 'EXITING' -and -not $stopping) { $reason = $e.Reason }
                            if (Test-VeroArmed) { Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action }
                        }
                    }
                    'need' {
                        if ($stopping) { break }                            # never re-send a just-rejected password
                        if ($e.Which -eq 'Auth') {
                            if (-not $cred) { $result = 'no-password'; $reason = 'the server asks for a password - none stored'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                            $pw = $cred.GetNetworkCredential().Password
                            if ($e.Challenge) {
                                $waitingOtp = $true
                                $otp = Wait-VeroOtp -ProfileName $name -Challenge $e.Challenge -Action $Action
                                $waitingOtp = $false; $progress = Get-Date
                                if ($null -eq $otp) { $result = 'otp'; $reason = 'no one-time code entered'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                                $pw = Get-VeroStaticChallengeResponse -Password $pw -Response $otp
                            }
                            Send-VeroMgmt $m ('username "Auth" ' + (Format-VeroMgmtValue $cred.UserName))
                            Send-VeroMgmt $m ('password "Auth" ' + (Format-VeroMgmtValue $pw))
                            $pw = $null
                        } elseif ($e.Which -eq 'Private Key') {
                            $kp = Get-VeroKeyPassphrase -ProfileName $name
                            if (-not $kp) { $result = 'no-password'; $reason = 'the private key needs a passphrase - none stored'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                            Send-VeroMgmt $m ('password "Private Key" ' + (Format-VeroMgmtValue $kp.GetNetworkCredential().Password))
                        } else {
                            $result = 'setup'; $reason = "OpenVPN asks for '$($e.Which)', which VeroScudo cannot answer"; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10)
                        }
                    }
                    'failed' {
                        $result = 'auth-failed'
                        $reason = if ($e.Dynamic) { 'the server asks for a dynamic challenge (CRV1), which VeroScudo cannot answer' } else { "$($e.Which) rejected by the server" }
                        Set-VeroAuthFailed -ProfileName $name -Reason "OpenVPN: $reason" -Action $Action -Which $(if ($e.Which -eq 'Private Key') { 'Key' } else { 'Auth' })
                        Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10)
                    }
                    'fatal' { Write-VeroLog "OpenVPN '$name' FATAL: $($e.Reason)" $Action; $reason = $e.Reason }
                    'error' { Write-VeroLog "OpenVPN '$name' management: $($e.Reason)" $Action }
                }
            }
        }
    } finally {
        if ($m) { try { $m.Client.Close() } catch { Write-Verbose 'close failed' } }
        if (-not $proc.HasExited) { if (-not $proc.WaitForExit(5000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } }
        Remove-Item $p.OvpnPw -Force -ErrorAction SilentlyContinue
        $final = switch ($result) { 'auth-failed' { 'AUTH_FAILED' } 'no-password' { 'NO_PASSWORD' } 'otp' { 'NEED_OTP' } default { 'EXITED' } }
        Set-VeroOpenVpnStatus $name @{ State = $final; Reason = $reason; LocalIp = ''; OvpnPid = 0; Challenge = '' }
        if (Test-VeroArmed) { try { Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action } catch { Write-VeroLog "ERROR: sync after OpenVPN exit: $($_.Exception.Message)" $Action } }
    }
    Write-VeroLog ("OpenVPN '{0}' ended: {1}{2} (decision source: {3})" -f $name, $result, $(if ($reason) { " - $reason" }),
        $(if ($result -eq 'stopped') { "VeroScudo's own stop" } else { 'OpenVPN exited on its own = failure, stays blocked' })) $Action
    $result
}

function Wait-VeroOtp {
    <# Static challenge: the tray shows the question, the user types the code; it arrives as a file in the user's folder.
       Waits up to 2 minutes; $null when no code came (or VeroScudo was turned off meanwhile). #>
    [CmdletBinding()] param([string]$ProfileName, [string]$Challenge, [string]$Action = 'openvpn')
    $p = Get-VeroPath -VpnProfile $ProfileName
    Remove-Item $p.Otp -Force -ErrorAction SilentlyContinue
    Set-VeroOpenVpnStatus $ProfileName @{ State = 'NEED_OTP'; Challenge = $Challenge }
    Write-VeroLog "OpenVPN '$ProfileName' asks for a one-time code - type it in the tray" $Action
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 120) {
        if (Test-Path $p.Otp) {
            $code = (Get-Content $p.Otp -Raw -ErrorAction SilentlyContinue); Remove-Item $p.Otp -Force -ErrorAction SilentlyContinue
            Set-VeroOpenVpnStatus $ProfileName @{ State = 'AUTH'; Challenge = '' }
            if ($code) { return $code.Trim() }
        }
        if (Get-VeroOpenVpnStopReason $ProfileName) { break }
        Start-Sleep -Milliseconds 500
    }
    $null
}

function Invoke-VeroOpenVpnRunner {
    <# The long-running elevated runner (scheduled task \VeroScudo\OpenVPN, one per session). Runs openvpn.exe for the active
       profile while VeroScudo is on; an OpenVPN that ends on its own is a failure: restarted every retrySeconds. Ends when
       VeroScudo is turned off, another profile type becomes active, a password is rejected or VeroScudo asks it to stop. #>
    [CmdletBinding()] param([string]$Action = 'openvpn')
    $mutex = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-OpenVPN')
    $mine = $false
    try { $mine = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $mine = $true }
    if (-not $mine) { $mutex.Dispose(); return }
    try {
        $cfg = Get-VeroConfig
        foreach ($pr in @($cfg.Profiles | Where-Object Type -eq 'openvpn')) { Stop-VeroOpenVpnOrphan -ProfileName $pr.Profile }
        while ($true) {
            $cfg = Get-VeroConfig
            if ((Get-VeroConfigType $cfg) -ne 'openvpn' -or -not (Test-VeroArmed)) { break }
            $p = Get-VeroPath -VpnProfile $cfg.Profile
            if (Test-Path $p.OvpnStop) { Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue; break }
            if (Test-VeroAuthBlocked $cfg.Profile) { break }
            $r = Invoke-VeroOpenVpnSession -Config $cfg -Action $Action
            if ($r -ne 'exited') { Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue; break }
            Start-Sleep -Seconds $cfg.RetrySeconds
        }
    } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}
