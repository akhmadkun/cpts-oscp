# nmap

```bash
> nmap -Pn -p- --min-rate 4100 10.10.10.60
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-12 15:57 +0700
Nmap scan report for 10.10.10.60
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
```

```bash
> nmap -p80,443 -sCV 10.10.10.60
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-12 15:58 +0700
Nmap scan report for 10.10.10.60
Host is up (0.18s latency).

PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.10 seconds
```

# ffuf

```bash
ffuf -u 'https://10.10.10.60/FUZZ' -w ~/seclists/Discovery/Web-Content/common.txt -ic -c
```
![](images/Pasted%20image%2020250912160750.png)
