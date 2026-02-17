
# clabs yml

```yaml
name: qinq-lab
topology:
  nodes:
    ce1:
      kind: vr-vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    pe1:
      kind: vr-vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    pe2:
      kind: vr-vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    ce2:
      kind: vr-vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
  links:
    # Link between CE1 and PE1
    - endpoints: ["ce1:ge-0/0/0", "pe1:ge-0/0/0"]
    # Link between PE1 and PE2 (Provider Core)
    - endpoints: ["pe1:ge-0/0/1", "pe2:ge-0/0/1"]
    # Link between PE2 and CE2
    - endpoints: ["pe2:ge-0/0/0", "ce2:ge-0/0/0"]
```

# ce1

```bash
conf t
set interfaces ge-0/0/0 vlan-tagging
set interfaces ge-0/0/0 unit 101 vlan-id 101
set interfaces ge-0/0/0 unit 101 family inet address 192.168.101.1/24
commit and-quit
```

# pe1 (enterprise style)

```bash

set interfaces ge-0/0/0 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/0 unit 0 family bridge vlan-id-list 101-120

set interfaces ge-0/0/1 flexible-vlan-tagging
set interfaces ge-0/0/1 unit 0 vlan-id 200
set interfaces ge-0/0/1 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/1 unit 0 family bridge inner-vlan-id-list 101-120

set bridge-domains bd vlan-id-list 101-120

```

# pe1 (service provider style)


```bash
set interface ge-0/0/0 vlan-tagging 
set interface ge-0/0/0 encapsulation flexible-ethernet-services

set interface ge-0/0/0 unit 100 encapsulation vlan-bridge
set interface ge-0/0/0 unit 100 vlan-id 101
set interface ge-0/0/0 unit 100 input-vlan-map push vlan-id 200
set interface ge-0/0/0 unit 100 output-vlan-map pop

set interface ge-0/0/1 stacked-vlan-tagging
set interface ge-0/0/1 encapsulation flexible-ethernet-services

set interface ge-0/0/1 unit 0 encapsulation vlan-bridge
set interface ge-0/0/1 unit 0 vlan-tags outer 200 inner 101

set bridge-domains bd interface ge-0/0/0.100
set bridge-domains bd interface ge-0/0/1.0
```

# pe2

```bash
conf t
# Provider-facing interface (S-VLAN + C-VLANs)
set interfaces ge-0/0/1 flexible-vlan-tagging
set interfaces ge-0/0/1 unit 0 vlan-id 200
set interfaces ge-0/0/1 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/1 unit 0 family bridge inner-vlan-id-list 101-120

# Customer-facing interface (C-VLANs)
set interfaces ge-0/0/0 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/0 unit 0 family bridge vlan-id-list 101-120

# Bridge Domain
set bridge-domains bd vlan-id-list 101-120
commit and-quit
```

# pe2 alternatif

```bash
ge-0/0/0 {
    vlan-tagging;
    encapsulation flexible-ethernet-services;
    unit 100 {
        encapsulation vlan-bridge;
        vlan-id 100;
        input-vlan-map {
            push;
            vlan-id 200;
        }
        output-vlan-map pop;
    }
}
ge-0/0/1 {
    stacked-vlan-tagging;
    encapsulation flexible-ethernet-services;
    unit 0 {
        encapsulation vlan-bridge;
        vlan-tags outer 200 inner 100;
    }
}
```
# ce2

```
conf t
set interfaces ge-0/0/0 vlan-tagging
set interfaces ge-0/0/0 unit 101 vlan-id 101
set interfaces ge-0/0/0 unit 101 family inet address 192.168.101.2/24
commit and-quit
```


# Verify

## ce1

```
user@ce1> ping 192.168.101.2 count 5
PING 192.168.101.2 (192.168.101.2): 56 data bytes
64 bytes from 192.168.101.2: icmp_seq=0 ttl=64 time=3.562 ms
64 bytes from 192.168.101.2: icmp_seq=1 ttl=64 time=2.998 ms
...
--- 192.168.101.2 ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
```

## linux hosts

```
sudo ip netns exec pe2 tcpdump -nne -i eth2
```