# Add New Rules

```bash
> ufw allow 6200/tcp
Rule added

> ufw status
Firewall loaded

To                         Action  From
--                         ------  ----
22:tcp                     ALLOW   Anywhere
22:udp                     ALLOW   Anywhere
21:tcp                     ALLOW   Anywhere
3632:tcp                   ALLOW   Anywhere
3632:udp                   ALLOW   Anywhere
139:tcp                    ALLOW   Anywhere
139:udp                    ALLOW   Anywhere
445:tcp                    ALLOW   Anywhere
445:udp                    ALLOW   Anywhere
6200:tcp                   ALLOW   Anywhere
```

```bash
sudo ufw allow in on incusbr1 from any to 10.99.1.1 proto udp port 67
sudo ufw allow in on incusbr1 from any to 10.99.1.1 proto udp port 68
sudo ufw allow in on incusbr1 to 10.99.1.1 port 53

> sudo ufw status numbered
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 67/udp on incusbr1         ALLOW IN    Anywhere
[ 2] 68/udp on incusbr1         ALLOW IN    Anywhere
[ 3] 53 on incusbr1             ALLOW IN    Anywhere
[ 4] 4444/tcp on tun0           ALLOW IN    Anywhere
[ 5] 4445/tcp on tun0           ALLOW IN    Anywhere
[ 6] 67/udp on virbr0           ALLOW IN    Anywhere
[ 7] 68/udp on virbr0           ALLOW IN    Anywhere
[ 8] 53 on virbr0               ALLOW IN    Anywhere
```

