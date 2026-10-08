
```
cat /etc/sysctl.d/99-mpls.conf
net.mpls.platform_labels = 1048575
```

## Load Module

```
/etc/modules-load.d/mpls.conf

load mpls_router
load mpls_iptunnel
load mpls_gso

```