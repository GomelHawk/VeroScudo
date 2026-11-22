# Shared setup of the VeroScudo.Core.*.Tests.ps1 files: dot-sourced inside each file's BeforeAll. A fresh copy of the
# module, a temp home of the file's own, the helpers, and no-op mocks for everything that would change the system.
# Not a test file itself (Pester runs *.Tests.ps1 only).
    # an installed copy loaded in the same session (e.g. after running VeroScudo.ps1 there) makes Pester's mocks ambiguous:
    # unload every copy from this session (memory only - no files are touched), then load the one under test
    Get-Module VeroScudo.Core | Remove-Module -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Core.psm1') -Force
    # SAFETY: everything these tests write or delete must live in a fresh temp folder. A failed setup once left the
    # cleanup pointing at the user's profile (`$script:Home` is `$HOME`), so: never a name that can collide with an
    # automatic variable, refuse to run unless the module's home really is that folder, delete only through Remove-TestDir.
    $script:TestHomeDir = Join-Path ([IO.Path]::GetTempPath()) ("veroscudo-test-" + [guid]::NewGuid())
    function Test-IsTestDir([string]$Path) {
        if (-not $Path -or -not $script:TestHomeDir) { return $false }
        $sep = [IO.Path]::DirectorySeparatorChar                            # '\' on Windows (CI); '/' only in a WSL dev harness
        $full = [IO.Path]::GetFullPath($Path).TrimEnd($sep)
        $root = [IO.Path]::GetFullPath($script:TestHomeDir).TrimEnd($sep)
        ($root -like ([IO.Path]::GetTempPath().TrimEnd($sep) + $sep + 'veroscudo-test-*')) -and ($full -eq $root -or $full.StartsWith($root + $sep, [StringComparison]::OrdinalIgnoreCase))
    }
    function Remove-TestDir { if (Test-IsTestDir $script:TestHomeDir) { Remove-Item -LiteralPath $script:TestHomeDir -Recurse -Force -ErrorAction SilentlyContinue } }
    function Remove-TestFile([string[]]$Paths) { foreach ($f in $Paths) { if (Test-IsTestDir $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } else { throw "test tried to delete outside its temp folder: $f" } } }
    Set-VeroHome $script:TestHomeDir
    if (-not (Test-IsTestDir (Get-VeroPath).Home)) { throw "SAFETY: module home is '$((Get-VeroPath).Home)', not the test folder - refusing to run" }
    # the per-user folder too: credentials, switch requests and tray files must never be written to the real one
    if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw "SAFETY: user folder is '$((Get-VeroPath).UserDir)', not the test folder - refusing to run" }
    New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Get-VeroPath).State -Force | Out-Null
    $script:cfgJson = '{"vpn":{"profile":"MyVPN","server":"vpn.example.com","port":443,"username":"jdoe"},"retrySeconds":7,"vm":"auto","wifiRecoveryFix":true,"lanAllow":[]}'
    $script:multiJson = '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"},{"profile":"Backup","server":"vpn2.example.com","port":8443,"username":"jdoe2"}],"activeProfile":"Work"}'
    Import-VeroNative
    # field-key prefixes as FilterSpec.ToString() prints them
    $script:F = @{ Flags = '632ce23b'; If = '4cd62a49'; Addr = 'b235ae9a'; Proto = '3971ef2b'; RPort = 'c35a604d'; LPort = '0c1ba1af'; App = 'd78e1e87' }
    # a test password as a SecureString, built character by character (test data, never a real secret)
    function New-TestSecret([string]$Text) { $ss = New-Object System.Security.SecureString; foreach ($ch in $Text.ToCharArray()) { $ss.AppendChar($ch) }; $ss }
    function Get-SpecText($specs) { @($specs | ForEach-Object { $_.ToString() }) }

    # SAFETY: nothing in this file may reach the real firewall, WFP, Hyper-V firewall or VPN. File-wide no-op mocks for every
    # command that changes the system; a test that needs a behaviour overrides one of them in its own block.
    foreach ($cmd in 'Set-NetFirewallProfile', 'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule',
                     'Set-NetFirewallHyperVVMSetting', 'New-NetFirewallHyperVRule', 'Set-NetFirewallHyperVRule', 'Remove-NetFirewallHyperVRule',
                     'Set-VeroWfpFilter', 'Clear-VeroWfpFilter', 'Invoke-VeroDial', 'Invoke-VeroHangUp',
                     'Add-DnsClientNrptRule', 'Remove-DnsClientNrptRule', 'Get-DnsClientNrptRule') {
        Mock -ModuleName VeroScudo.Core $cmd { }
    }
    # Hyper-V port ACLs (62-HyperVAcl.ps1): no VM is ever seen or changed by this file unless a test says so
    # the redial's DNS window (Invoke-VeroDnsFirst): never a real DNS query from a test - "no answer" at once
    Mock -ModuleName VeroScudo.Core Start-VeroDnsLookup { [System.Threading.Tasks.Task]::FromResult([System.Net.IPAddress[]]@()) }
    # the local DNS answer (Update-VeroLocalDns): never a real listener on 127.0.0.53:53 from a test (the watchdog loop runs it)
    Mock -ModuleName VeroScudo.Core Update-VeroLocalDns { }
    # routes (Sync-VeroBlackhole): never a real route from a test - "added" / "removed" at once, an empty routing table
    Mock -ModuleName VeroScudo.Core Add-VeroRoute { [uint32]0 }
    Mock -ModuleName VeroScudo.Core Remove-VeroRoute { [uint32]0 }
    Mock -ModuleName VeroScudo.Core Get-VeroRouteTable { }
    Mock -ModuleName VeroScudo.Core Get-VeroAllVmAdapter { }
    Mock -ModuleName VeroScudo.Core Get-VeroVmAdapterAcl { }
    Mock -ModuleName VeroScudo.Core Add-VeroVmAdapterAcl { }
    Mock -ModuleName VeroScudo.Core Remove-VeroVmAdapterAcl { }
    # "nothing found" = no output at all, like the real cmdlets (an explicit $null would be piped on as a value)
    Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVRule { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVVMSetting { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVVMCreator { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; DefaultOutboundAction = 'NotConfigured' }) }
    Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
