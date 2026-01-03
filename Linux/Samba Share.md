
```bash
sudo pacman -S samba
```

`/etc/samba/smb.conf`
```
[share]
        path = /home/akhmadm/tmp
        browseable = yes
        read only = no
        guest ok = yes
        force user = akhmadm
```

`open fw ports`
```bash
> sudo ufw allow in on virbr0 from any to any port 445 proto tcp
Rule added
> sudo ufw allow in on virbr0 from any to any port 139 proto tcp
Rule added
```

`create smb user and enable`
```bash
sudo smbpasswd -a akhmadm
sudo smbpasswd -e akhmadm
```

`access from windows guest`
```
\\192.168.122.1\share
```

