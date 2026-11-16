# The rules Windows and Linux/macOS must agree on, from one file both test suites read (shared\vectors.json; the Python
# side is linux/tests/test_shared_vectors.py). A change of such a rule on one platform fails here or there.
# Pure functions only: nothing is read from or written to the state or user folders.
BeforeDiscovery {
    $file = Join-Path $PSScriptRoot '..\..\shared\vectors.json'
    $script:V = if (Test-Path -LiteralPath $file) { [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json } else { $null }
    function Get-Cases([string]$Key) { @(if ($script:V) { $script:V.$Key | ForEach-Object { @{ c = $_ } } }) }
}
BeforeAll {
    Get-Module VeroScudo.Core | Remove-Module -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Core.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Tray.psm1') -Force
    # a home that does not exist: Get-VeroConfig -Raw then finds no stored selection and reads nothing of an installed copy
    $script:SharedHome = Join-Path ([IO.Path]::GetTempPath()) ("veroscudo-test-" + [guid]::NewGuid())
    Set-VeroHome $script:SharedHome
    function Test-Loads([hashtable]$Top, [hashtable]$Entry) {
        $p = [ordered]@{ profile = 'X'; server = 'vpn.example.com'; username = 'u' }
        foreach ($k in $Entry.Keys) { $p[$k] = $Entry[$k] }
        $j = [ordered]@{ profiles = @($p) }
        foreach ($k in $Top.Keys) { $j[$k] = $Top[$k] }
        try { $null = Get-VeroConfig -Raw ($j | ConvertTo-Json -Depth 6); $true } catch { $false }
    }
    function ConvertTo-Table($o) { $h = @{}; if ($o) { foreach ($pr in $o.PSObject.Properties) { $h[$pr.Name] = $pr.Value } }; $h }
}
AfterAll { Set-VeroHome $null }

Describe 'the shared rules file' {
    # a copy of windows\ alone has no shared folder, and the rules below are skipped. In CI the whole repository is there:
    # a missing file would mean nothing here was checked
    It 'is there in CI' { if ($env:CI) { Test-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\shared\vectors.json') | Should -BeTrue } }
}

Describe 'shared rules (shared\vectors.json)' -Skip:(-not $script:V) {
    It 'version: <c.tag> newer than <c.current> = <c.newer>' -ForEach (Get-Cases 'version_newer') {
        Test-VeroNewerVersion -Tag ([string]$c.tag) -Current ([string]$c.current) | Should -Be ([bool]$c.newer)
    }
    It 'release page: <c.url>' -ForEach (Get-Cases 'release_url') {
        Test-VeroReleaseUrl ([string]$c.url) | Should -Be ([bool]$c.ok)
    }
    It 'profile id of <c.name>' -ForEach (Get-Cases 'profile_id') {
        & (Get-Module VeroScudo.Core) { param($n) Get-VeroProfileId -Name $n } ([string]$c.name) | Should -Be ([string]$c.id)
    }
    It 'lanAllow <c.value>' -ForEach (Get-Cases 'lan_allow') {
        & (Get-Module VeroScudo.Core) { param($v) Test-VeroCidr $v } ([string]$c.value) | Should -Be ([bool]$c.ok)
    }
    It 'serverIps <c.value>' -ForEach (Get-Cases 'server_ips') {
        Test-Loads @{} @{ serverIps = @([string]$c.value) } | Should -Be ([bool]$c.ok)
    }
    It 'status page address: <c.url>' -ForEach (Get-Cases 'status_url') {
        Test-VeroStatusPageUrl ([string]$c.url) | Should -Be ([bool]$c.ok)
    }
    It 'usable server address: <c.value>' -ForEach (Get-Cases 'usable_server_ip') {
        & (Get-Module VeroScudo.Core) { param($v) Test-VeroUsableServerIp $v } ([string]$c.value) | Should -Be ([bool]$c.ok)
    }
    It 'config: <c.what>' -ForEach (Get-Cases 'config') {
        Test-Loads (ConvertTo-Table $c.top) (ConvertTo-Table $c.profile) | Should -Be ([bool]$c.ok)
    }
}
