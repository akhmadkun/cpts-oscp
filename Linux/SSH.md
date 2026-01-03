
# No Matching Key Exchange Method

```bash
> ssh -l admin 10.10.10.7
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

```bash
> ssh -l admin 10.10.10.7 -oKexAlgorithms=+diffie-hellman-group14-sha1
```

# No Matching Host Key Type

```bash
> ssh -l admin 10.10.10.7 -oKexAlgorithms=+diffie-hellman-group14-sha1
Unable to negotiate with 10.10.10.7 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

```bash
> ssh -l admin 10.10.10.7 -oKexAlgorithms=+diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-rsa
```

