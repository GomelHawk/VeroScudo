#Requires -RunAsAdministrator
# Read-only check of the ACTIVE profile, any type: VeroScudo's status, then whether traffic really goes through the tunnel
# (TCP by IP, DNS, HTTPS). Changes nothing. OpenVPN profiles: also the last lines of openvpn.exe's own log, which only
# administrators can read (it names the server and the user name, never the password).
#   powershell -ExecutionPolicy Bypass -File <repo>\windows\tests-local\Check-Traffic.ps1
param([int]$OpenVpnLogLines = 40)
Import-Module (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'VeroScudo\VeroScudo.Core.psm1') -Force
$cfg = Get-VeroConfig
"== VeroScudo $(Get-Date -Format 'HH:mm:ss')"
Get-VeroStatus -Config $cfg | Format-List Profile, Type, State, Connected, Client, PwRejected, Filters, Server, Conflicts | Out-String -Width 250
'== traffic'
$t = Test-NetConnection 1.1.1.1 -Port 443 -WarningAction SilentlyContinue
'TCP 1.1.1.1:443 : {0} (via {1}, from {2})' -f $(if ($t.TcpTestSucceeded) { 'OK' } else { 'FAILED' }), $t.InterfaceAlias, $(if ($t.SourceAddress) { $t.SourceAddress.IPAddress } else { '-' })
try { 'DNS example.com: ' + (Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction Stop | Select-Object -First 1).IPAddress } catch { "DNS example.com: FAILED ($($_.Exception.Message))" }
try { 'HTTPS          : ' + (Invoke-WebRequest https://example.com -UseBasicParsing -TimeoutSec 15).StatusCode } catch { "HTTPS          : FAILED ($($_.Exception.Message))" }
if ($cfg.Type -eq 'openvpn') {
    $log = (Get-VeroPath -VpnProfile $cfg.Profile).OvpnLog
    "== openvpn.exe log ($log), last $OpenVpnLogLines lines"
    if (Test-Path $log) { Get-Content $log -Tail $OpenVpnLogLines } else { '(no log yet)' }
    $prev = $log -replace '\.log$', '.prev.log'
    if (Test-Path $prev) { "== previous run ($prev), last $OpenVpnLogLines lines"; Get-Content $prev -Tail $OpenVpnLogLines }
}
