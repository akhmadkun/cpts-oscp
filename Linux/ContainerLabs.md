# Junos Bind Directory

```yaml
name: ipsec-vsrx-http-poc
prefix: ""

topology:
  nodes:
    vsrx-a:
      kind: juniper_vsrx
      image: eacik8ssrv6/juniper_vsrx:23.2R2.21
      startup-config: configs/startup.conf

      binds:
        - ./configs:/lab-config:ro

      exec:
        - sh -c 'cd /lab-config && nohup python3 -m http.server 81 --bind 0.0.0.0 --directory /lab-config >/tmp/config-http.log 2>&1 &'

    br-univ:
      kind: bridge

  links:
    - endpoints: ["vsrx-a:eth1", "br-univ:eth1"]
```

## Load Replace

```
admin@poc-vsrx-a# load replace http://10.0.0.2:81/01.conf routing-instance mgmt_junos
/var/home/admin/...transferring.file.........A100% of  184  B 3038 kBps
load complete

[edit]
admin@poc-vsrx-a# show | compare
[edit system]
-  host-name poc-vsrx-a;
+  host-name vvfat-test-1;
[edit interfaces ge-0/0/0 unit 0 family inet]
        address 198.18.10.12/24 { ... }
+       address 198.18.20.12/24;
```