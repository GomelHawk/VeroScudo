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
        $map = @{ ver = 'Ver'; src = 'Src'; dst = 'Dst'; proto = 'Proto'; sport = 'SPort'; dport = 'DPort'; itype = 'IType'; ttl = 'Ttl' }
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

Describe 'Wi-Fi frames (pktmon records raw 802.11 on a Wi-Fi adapter)' {
    BeforeAll { $script:Mine = [string[]]@('02aabbccddee') }
    It 'reads a data frame we sent to the access point' {
        # ToDS data frame: AP 02aabbcc0001, we 02aabbccddee, router 02aabbcc0002; LLC/SNAP; IPv4 192.168.100.26 > 203.0.113.5 TCP 443
        $hex = '0801008002aabbcc000102aabbccddee02aabbcc00020000aaaa030000000800450000280000400040060000c0a8641acb007105d55401bb00000000000000005002000000000000'
        $p = [KsBench.Parse]::HexOut($hex, $script:Mine)
        $p.Dst | Should -Be '203.0.113.5'
        $p.DPort | Should -Be 443
    }
    It 'ignores a frame the access point sent to us' {
        $hex = '08422c0002aabbccddee02aabbcc000102aabbcc0002e0a1aaaa030000000800450000280000400040060000cb007105c0a8641a01bbd55400000000000000005002000000000000'
        [KsBench.Parse]::HexOut($hex, $script:Mine) | Should -BeNullOrEmpty
    }
    It 'still reads an Ethernet frame from our MAC' {
        $hex = '001122334455' + '02aabbccddee' + '0800' + '4500001c00004000401100000a000002c633640700350035000800000000'
        ([KsBench.Parse]::HexOut($hex, $script:Mine)).Dst | Should -Be '198.51.100.7'
    }
}

Describe 'verdict' {
    It '<s> with <f> -> <level>' -ForEach @(
        @{ s = 100; f = @(); t = 90; level = 'STRONG' },
        @{ s = 93; f = @('D5'); t = 100; level = 'STRONG' },
        @{ s = 80; f = @('S4', 'D5'); t = 100; level = 'FAIR' },
        @{ s = 40; f = @('D3'); t = 100; level = 'POOR' },
        @{ s = 100; f = @(); t = 40; level = 'UNCLEAR' }
    ) {
        (Get-Verdict $s $f $t 100)[0] | Should -Be $level
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
