# nmap

```bash
> nmap -Pn --min-rate 4000 -p- 10.10.10.75
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-25 09:46 +0700
Nmap scan report for 10.10.10.75
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

 
```bash
> nmap -Pn -p22,80 -sCV 10.10.10.75
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-26 14:59 +0700
Nmap scan report for 10.10.10.75
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.87 seconds
```

# web pages

![[Pasted image 20250826150039.png]]

## dirbust nibbleblog dir

#ffuf
```bash
 ffuf -u 'http://10.10.10.75/nibbleblog/FUZZ' -w ~/seclists/Discovery/Web-Content/common.txt -ic -c
```
![[Pasted image 20250831163744.png]]


#gobuster
```bash
 gobuster dir -u 'http://10.10.10.75/nibbleblog/' -w ~/seclists/Discovery/Web-Content/common.txt
```

==/content/private/config.xml==
```xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?> <config><name type="string">Nibbles</name><slogan type="string">Yum yum</slogan><footer type="string">Powered by Nibbleblog</footer><advanced_post_options type="integer">0</advanced_post_options><url type="string">http://10.10.10.134/nibbleblog/</url><path type="string">/nibbleblog/</path><items_rss type="integer">4</items_rss><items_page type="integer">6</items_page><language type="string">en_US</language><timezone type="string">UTC</timezone><timestamp_format type="string">%d %B, %Y</timestamp_format><locale type="string">en_US</locale><img_resize type="integer">1</img_resize><img_resize_width type="integer">1000</img_resize_width><img_resize_height type="integer">600</img_resize_height><img_resize_quality type="integer">100</img_resize_quality><img_resize_option type="string">auto</img_resize_option><img_thumbnail type="integer">1</img_thumbnail><img_thumbnail_width type="integer">190</img_thumbnail_width><img_thumbnail_height type="integer">190</img_thumbnail_height><img_thumbnail_quality type="integer">100</img_thumbnail_quality><img_thumbnail_option type="string">landscape</img_thumbnail_option><theme type="string">simpler</theme><notification_comments type="integer">1</notification_comments><notification_session_fail type="integer">0</notification_session_fail><notification_session_start type="integer">0</notification_session_start><notification_email_to type="string">admin@nibbles.com</notification_email_to><notification_email_from type="string">noreply@10.10.10.134</notification_email_from><seo_site_title type="string">Nibbles - Yum yum</seo_site_title><seo_site_description type="string"/><seo_keywords type="string"/><seo_robots type="string"/><seo_google_code type="string"/><seo_bing_code type="string"/><seo_author type="string"/><friendly_urls type="integer">0</friendly_urls><default_homepage type="integer">0</default_homepage></config>
```

==/content/private/users.xml==
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?> <users><user username="admin"><id type="integer">0</id><session_fail_count type="integer">0</session_fail_count><session_date type="integer">1514544131</session_date></user><blacklist type="string" ip="10.10.10.1"><date type="integer">1512964659</date><fail_count type="integer">1</fail_count></blacklist></users>
```

db.xml
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?> <plugin name="Categories" author="Diego Najar" version="3.6" installed_at="1512926436"><position type="integer">0</position><title type="string">Categories</title></plugin>
```

#LinEnum 
```bash
[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh

```
