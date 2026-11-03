' Windowless launcher:  wscript.exe //B //Nologo run.vbs <action>
' Only known actions are passed on: the argument ends up on a PowerShell command line.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
' full path from GetSystemDirectory: a bare "powershell.exe" is looked up through the user's App Paths registry key, which a
' non-admin process can point anywhere - and the guard tasks run elevated
ps = """" & fso.GetSpecialFolder(1).Path & "\WindowsPowerShell\v1.0\powershell.exe"""
If WScript.Arguments.Count <> 1 Then WScript.Quit 2
a = WScript.Arguments(0)
If a = "tray" Then
  sh.Run ps & " -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dir & "\VeroScudoTray.ps1""", 0, False
ElseIf InStr(1, "|arm|disarm|on|on-disconnect|on-force|off|on-event|reconnect|watchdog|check|switch|openvpn|", "|" & a & "|", vbBinaryCompare) > 0 Then
  ' wait for the guard: Task Scheduler then sees the task as running and its IgnoreNew setting prevents a second copy
  sh.Run ps & " -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & dir & "\VeroScudo.ps1"" -Action " & a, 0, True
Else
  WScript.Quit 2
End If
