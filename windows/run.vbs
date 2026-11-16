' Windowless launcher:  wscript.exe //B //Nologo run.vbs <action>
' Only known actions are passed on: the argument ends up on a PowerShell command line.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
' full path from GetSystemDirectory: a bare "powershell.exe" is looked up through the user's App Paths registry key, which a
' non-admin process can point anywhere - and the guard tasks run elevated
ps = """" & fso.GetSpecialFolder(1).Path & "\WindowsPowerShell\v1.0\powershell.exe"""
If WScript.Arguments.Count <> 1 Then WScript.Quit 2
' The guard tasks run elevated with the signed-in user's environment, which any program of that user can add to
' (HKCU\Environment). PowerShell is a .NET program, and the .NET runtime reads some variables before the first line of
' any script runs - a profiler to load, for one. Those are taken out of this process's environment here (wscript is not
' a .NET program), so the PowerShell started below never sees them; the Windows folder comes from the system itself.
Set env = sh.Environment("Process")
drop = ""
For Each kv In env
  eq = InStr(2, kv, "=")
  If eq > 0 Then
    n = UCase(Left(kv, eq - 1))
    If Left(n, 4) = "COR_" Or Left(n, 8) = "CORECLR_" Or Left(n, 8) = "COMPLUS_" Or Left(n, 7) = "DOTNET_" Or Left(n, 18) = "APPDOMAIN_MANAGER_" Or Left(n, 8) = "OPENSSL_" Or n = "__COMPAT_LAYER" Or n = "PSEXECUTIONPOLICYPREFERENCE" Then drop = drop & Left(kv, eq - 1) & vbLf
  End If
Next
For Each n In Split(drop, vbLf)
  If n <> "" Then
    On Error Resume Next
    env.Remove n
    On Error GoTo 0
  End If
Next
env("SystemRoot") = fso.GetSpecialFolder(0).Path
env("windir") = fso.GetSpecialFolder(0).Path
a = WScript.Arguments(0)
If a = "tray" Then
  sh.Run ps & " -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dir & "\VeroScudoTray.ps1""", 0, False
ElseIf InStr(1, "|arm|disarm|on|on-disconnect|on-force|off|on-event|netdown|reconnect|redial|watchdog|check|switch|openvpn|", "|" & a & "|", vbBinaryCompare) > 0 Then
  ' wait for the guard: Task Scheduler then sees the task as running and its IgnoreNew setting prevents a second copy
  sh.Run ps & " -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & dir & "\VeroScudo.ps1"" -Action " & a, 0, True
Else
  WScript.Quit 2
End If
