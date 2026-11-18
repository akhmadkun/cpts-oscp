
## activate service

```
sudo systemctl enable --now tailscaled

systemctl status tailscaled
```

## connect to tailscale

```bash
sudo tailscale up

tailscale status

tailscale ip -4

ip addr show tailscale0
```

## accept advertised routes

```bash
sudo tailscale set --accept-routes=true
```
## cek routing table tailscale

```
ip route show table 52
```

