# Pester 5 tests for the parser and classifier in ksbench.ps1 (same vectors as test_ksbench.py).
BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'ksbench.ps1')
    $script:Vec = Get-Content -Raw (Join-Path $PSScriptRoot 'vectors.json') | ConvertFrom-Json
}

Describe 'parse and classify' {
    It '<name>' -ForEach @((Get-Content -Raw (Join-Path $PSScriptRoot 'vectors.json') | ConvertFrom-Json).vectors |
            ForEach-Object { @{ name = $_.name; hex = $_.hex; linktype = $_.linktype; expect = $_.expect } }) {
        $p = [KsBench.Parse]::Hex($hex, [int]$linktype)
        if ($null -eq $expect) { $p | Should -BeNullOrEmpty; return }
        $map = @{ ver = 'Ver'; src = 'Src'; dst = 'Dst'; proto = 'Proto'; sport = 'SPort'; dport = 'DPort'; itype = 'IType' }
        foreach ($k in $expect.PSObject.Properties.Name) {
            if ($k -eq 'cls') { continue }
            $want = $expect.$k
            if ($null -eq $want) { $want = -1 }
            $p.($map[$k]) | Should -Be $want -Because $k
        }
        [KsBench.Parse]::Classify($p, [string[]]$script:Vec.servers) | Should -Be $expect.cls
    }
}

Describe 'pcapng reader' {
    It 'keeps only frames from our MAC, with nanosecond time stamps' {
        $hex = $script:Vec.pcapng.hex
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        $f = Join-Path $TestDrive 'x.pcapng'
        [IO.File]::WriteAllBytes($f, $bytes)
        $got = [KsBench.Parse]::ReadPcapng($f, [string[]]@($script:Vec.pcapng.mac))
        $got.Count | Should -Be 2
        for ($i = 0; $i -lt 2; $i++) {
            $got[$i].Dst | Should -Be $script:Vec.pcapng.expect[$i][1]
            $got[$i].Ts | Should -BeGreaterOrEqual ($script:Vec.pcapng.expect[$i][0] - 0.001)
            $got[$i].Ts | Should -BeLessOrEqual ($script:Vec.pcapng.expect[$i][0] + 0.001)
        }
    }
}

Describe 'verdict' {
    It '<s> with <f> -> <level>' -ForEach @(
        @{ s = 100; f = @(); t = 135; level = 'STRONG' },
        @{ s = 93; f = @('D5'); t = 150; level = 'STRONG' },
        @{ s = 80; f = @('S4', 'D5'); t = 150; level = 'FAIR' },
        @{ s = 40; f = @('D3'); t = 150; level = 'POOR' },
        @{ s = 100; f = @(); t = 60; level = 'UNCLEAR' }
    ) {
        (Get-Verdict $s $f $t 150)[0] | Should -Be $level
    }
}

Describe 'probe helpers' {
    It 'builds a DNS query for a random example.com name' {
        $n = [KsBench.Probe]::UniqueName()
        $n | Should -Match '^ksb-[a-z0-9]{12}\.example\.com$'
        $q = [KsBench.Probe]::DnsPacket($n)
        $q.Length | Should -Be (12 + $n.Length + 2 + 4)
    }
}
