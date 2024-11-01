Execution policy issues.
```
powershell -ExecutionPolicy Bypass -File script.ps1
```
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
* Contrained Langauge Bypass. Use installutil to bypass .exe restrictions. `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=false /U C:\users\Public\bypass-clm.exe`
* Seatbelt.exe `Seatbelt.exe -group=all -full`
https://github.com/GhostPack/Seatbelt
