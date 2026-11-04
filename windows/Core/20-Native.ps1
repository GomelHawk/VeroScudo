# VeroScudo core, part 20: the native helper (WFP, RasDial, LUIDs) and its Smart App Control record.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- native helpers (WFP, RasDial, LUIDs)
function Import-VeroNative {
    if ('VeroScudo.Wfp' -as [type]) { return }
    $dll = Join-Path $script:ModuleRoot 'VeroScudo.Native.dll'
    try {
        # loaded from its BYTES, not as a file: Smart App Control refuses to map the locally compiled, unsigned DLL as an
        # image (Code Integrity 3077, seen live 2026-11-03), while an assembly loaded from memory is not checked that way -
        # the same way the tray's own Add-Type helpers load. It also leaves the file unlocked, so a reinstall can replace it.
        # The file sits in Program Files (administrators only), so its bytes are as trusted as the file was.
        if (Test-Path $dll) { [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($dll)) }
        else { Add-Type -TypeDefinition (Get-Content (Join-Path $script:ModuleRoot 'VeroScudo.Native.cs') -Raw) -Language CSharp }
        if (-not ('VeroScudo.Wfp' -as [type])) { throw "native helper loaded, but its types are missing: $dll" }
    } catch { $script:NativeLoadFailed = $true; throw }                    # see "the native helper blocked by Windows"
}
# ---------------------------------------------------------------- the native helper blocked by Windows (Smart App Control)
# A process that failed to load VeroScudo.Native.dll keeps failing for its whole life (.NET remembers the failed load), so
# the long-running watchdog exits on such a failure and is started fresh by its task - with a growing wait, so a one-off
# block heals in about a minute and a lasting one is retried every 10 minutes without filling the log.
$script:NativeLoadFailed = $false
function Get-VeroNativeRetrySeconds {
    <# Pure: wait before the next try after the Nth failed load in a row: 1, 5, then 10 minutes. #>
    [CmdletBinding()] param([int]$Count)
    if ($Count -le 1) { 60 } elseif ($Count -eq 2) { 300 } else { 600 }
}
function Get-VeroNativeBlocked {
    $f = (Get-VeroPath).NativeBlocked
    if (Test-Path $f) { try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { Write-Verbose 'native-blocked unreadable' } }
    $null
}
function Set-VeroNativeBlocked {
    [CmdletBinding()] param([string]$Message, [string]$Action = 'core', [switch]$FromTask)
    # -FromTask (On, Off, events...): recorded for the tray, but neither counted nor delaying the watchdog's next try
    $old = Get-VeroNativeBlocked
    $count = if ($FromTask) { $(if ($old) { [int]$old.Count } else { 0 }) } elseif ($old) { [int]$old.Count + 1 } else { 1 }
    $wait = if ($FromTask) { 0 } else { Get-VeroNativeRetrySeconds $count }
    $now = Get-Date
    @{ First = $(if ($old) { [string]$old.First } else { $now.ToString('o') }); Last = $now.ToString('o'); Count = $count
       Next = $(if ($FromTask -and $old) { [string]$old.Next } else { $now.AddSeconds($wait).ToString('o') }); Message = $Message } | ConvertTo-Json | Set-Content (Get-VeroPath).NativeBlocked
    Write-VeroLog ("ERROR: Windows blocked VeroScudo's native helper (Smart App Control or App Control: {0}). The kill-switch filters stay in place; self-repair and automatic redial are paused - next try at {1:HH:mm} (failure {2} in a row)." -f $Message, $now.AddSeconds($wait), $count) $Action
}
function Clear-VeroNativeBlocked {
    [CmdletBinding()] param([string]$Action = 'core')
    $f = (Get-VeroPath).NativeBlocked
    if (Test-Path $f) { Remove-Item $f -Force; Write-VeroLog 'native helper loads again - self-repair and automatic redial are back' $Action }
}
function Test-VeroNativeRetryDue {
    <# Pure apart from the clock: may a fresh watchdog try again now? #>
    [CmdletBinding()] param($Blocked, [datetime]$Now = (Get-Date))
    if (-not $Blocked -or -not [string]$Blocked.Next) { return $true }
    $Now -ge [datetime]::Parse([string]$Blocked.Next, $null, [Globalization.DateTimeStyles]::RoundtripKind)
}
