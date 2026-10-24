' Windowless launcher:  wscript.exe //B //Nologo run.vbs <action>
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
If WScript.Arguments(0) = "tray" Then
  sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dir & "\VeroScudoTray.ps1""", 0, False
Else
  sh.Run "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & dir & "\VeroScudo.ps1"" -Action " & WScript.Arguments(0), 0, False
End If
