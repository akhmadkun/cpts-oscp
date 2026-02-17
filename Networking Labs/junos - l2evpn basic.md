
# KVM Tweaks

```bash
echo 0 | sudo tee /sys/module/kvm/parameters/halt_poll_ns
```

```bash
echo "options kvm halt_poll_ns=0" | sudo tee /etc/modprobe.d/kvm.conf
```
# Topology & IP Scheme

|**Node**|**Role**|**Interface**|**IP Address**|**Description**|
|---|---|---|---|---|
|**Spine1**|RR / Underlay|lo0|**3.3.3.3/32**|Router ID|
|||xe-0/0/0|10.1.1.0/31|Link to Leaf1|
|||xe-0/0/1|10.1.1.2/31|Link to Leaf2|
|**Leaf1**|VTEP|lo0|**1.1.1.1/32**|VTEP Source IP|
|||xe-0/0/0|10.1.1.1/31|Link to Spine1|
|||xe-0/0/1|-|Access Port (VLAN 10)|
|**Leaf2**|VTEP|lo0|**2.2.2.2/32**|VTEP Source IP|
|||xe-0/0/0|10.1.1.3/31|Link to Spine1|
|||xe-0/0/1|-|Access Port (VLAN 10)|
# Containerlab Topology

```yaml
name: junos-evpn
topology:
  kinds:
    vr-vqfx:
      image: vrnetlab/vr-vqfx:17.4.1R1.16 # Sesuaikan tag image Anda
    linux:
      image: alpine:latest

  nodes:
    spine1: { kind: vr-vqfx }
    leaf1:  { kind: vr-vqfx }
    leaf2:  { kind: vr-vqfx }
    host1:
      kind: linux
      exec:
        - ip addr add 192.168.10.11/24 dev eth1
    host2:
      kind: linux
      exec:
        - ip addr add 192.168.10.12/24 dev eth1

  links:
    # Interface mapping: eth1 -> xe-0/0/0, eth2 -> xe-0/0/1
    - endpoints: ["leaf1:eth1", "spine1:eth1"]
    - endpoints: ["leaf2:eth1", "spine1:eth2"]
    - endpoints: ["leaf1:eth2", "host1:eth1"]
    - endpoints: ["leaf2:eth2", "host2:eth1"]
```

# Spine

```bash
# Masuk mode configure
configure

# 1. Interfaces & Loopback
set interfaces xe-0/0/0 unit 0 family inet address 10.1.1.0/31
set interfaces xe-0/0/1 unit 0 family inet address 10.1.1.2/31
set interfaces lo0 unit 0 family inet address 3.3.3.3/32

# 2. Underlay Routing (OSPF)
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf area 0.0.0.0 interface xe-0/0/0.0
set protocols ospf area 0.0.0.0 interface xe-0/0/1.0
set routing-options router-id 3.3.3.3

# 3. Overlay BGP (Route Reflector)
set protocols bgp group OVERLAY type internal
set protocols bgp group OVERLAY local-address 3.3.3.3
set protocols bgp group OVERLAY family evpn signaling
set protocols bgp group OVERLAY cluster 3.3.3.3
set protocols bgp group OVERLAY neighbor 1.1.1.1
set protocols bgp group OVERLAY neighbor 2.2.2.2
set protocols bgp group OVERLAY local-as 65001

commit
```

# Leaf1

```bash
configure

# 1. Interfaces (Uplink L3 & Access L2)
set interfaces xe-0/0/0 unit 0 family inet address 10.1.1.1/31
set interfaces lo0 unit 0 family inet address 1.1.1.1/32

# Access Port (Host) - Disable LLDP here if needed
set interfaces xe-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces xe-0/0/1 unit 0 family ethernet-switching vlan members TENANT_A
set protocols lldp interface xe-0/0/1 disable

# 2. Underlay Routing (OSPF)
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf area 0.0.0.0 interface xe-0/0/0.0
set routing-options router-id 1.1.1.1

# 3. Overlay BGP
set protocols bgp group OVERLAY type internal
set protocols bgp group OVERLAY local-address 1.1.1.1
set protocols bgp group OVERLAY family evpn signaling
set protocols bgp group OVERLAY neighbor 3.3.3.3
set protocols bgp group OVERLAY local-as 65001

# 4. VLAN & VXLAN Definition
set vlans TENANT_A vlan-id 10
set vlans TENANT_A vxlan vni 10010

# 5. EVPN Configuration (The "Magic" Part)
# Mendefinisikan encapsulation type
set protocols evpn encapsulation vxlan
# Default gateway advertising (optional for L2 only, but good practice)
set protocols evpn default-gateway no-gateway-community
# Mapping VNI ke EVPN dan set Ingress Replication (karena underlay unicast)
set protocols evpn extended-vni-list all
set protocols evpn vni-options vni 10010 vrf-target target:65001:10010

# 6. Switch-Options (VTEP Parameters)
set switch-options vtep-source-interface lo0.0
set switch-options route-distinguisher 1.1.1.1:10010
set switch-options vrf-target target:65001:10010 auto

commit
```

# Leaf2

```bash
configure

# 1. Interfaces
set interfaces xe-0/0/0 unit 0 family inet address 10.1.1.3/31
set interfaces lo0 unit 0 family inet address 2.2.2.2/32
set interfaces xe-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces xe-0/0/1 unit 0 family ethernet-switching vlan members TENANT_A
set protocols lldp interface xe-0/0/1 disable

# 2. Underlay (OSPF)
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf area 0.0.0.0 interface xe-0/0/0.0
set routing-options router-id 2.2.2.2

# 3. Overlay BGP
set protocols bgp group OVERLAY type internal
set protocols bgp group OVERLAY local-address 2.2.2.2
set protocols bgp group OVERLAY family evpn signaling
set protocols bgp group OVERLAY neighbor 3.3.3.3
set protocols bgp group OVERLAY local-as 65001

# 4. VLAN & VXLAN
set vlans TENANT_A vlan-id 10
set vlans TENANT_A vxlan vni 10010

# 5. EVPN
set protocols evpn encapsulation vxlan
set protocols evpn default-gateway no-gateway-community
set protocols evpn extended-vni-list all
set protocols evpn vni-options vni 10010 vrf-target target:65001:10010

# 6. Switch-Options
set switch-options vtep-source-interface lo0.0
set switch-options route-distinguisher 2.2.2.2:10010
set switch-options vrf-target target:65001:10010 auto

commit
```

# Verification

```bash
# Di Leaf1
run show bgp summary

# Di Leaf1
run show route table bgp.evpn.0 match-prefix 3:*:*

# Di Leaf1
run show interfaces vtep

# Di Leaf1
run show interfaces vtep

# type 2 route
run show ethernet-switching table
run show evpn database

```

