
# Yaml

```yaml
name: l3-leaf-spine
prefix: ""
topology:
  kinds:
    ceos:
      image: ceos:4.35.0F
  nodes:
    # Spine Layer BGP ASN : 65010
    spine1: { kind: ceos } # R-ID : 192.168.0.1
    spine2: { kind: ceos } # R-ID : 192.168.0.2

    # Leaf Layer BGP ASN : 65020
    leaf1: { kind: ceos } # R-ID : 192.168.0.11
    leaf2: { kind: ceos } # R-ID : 192.168.0.12
    leaf3: { kind: ceos } # R-ID : 192.168.0.13
    leaf4: { kind: ceos } # R-ID : 192.168.0.14

    # Host Rak 1 : 172.16.100.10
    host1: { kind: ceos }

    # Host Rak 1 : 172.16.200.10
    host2: { kind: ceos }

  links:
    # --- Uplinks Rak 1 (Leaf 1 & 2) To Spines ---
    - endpoints: ["leaf1:eth1", "spine1:eth1"] # 10.10.1.0/31
    - endpoints: ["leaf1:eth2", "spine2:eth1"] # 10.10.2.0/31
    - endpoints: ["leaf2:eth1", "spine1:eth2"] # 10.10.1.2/31
    - endpoints: ["leaf2:eth2", "spine2:eth2"] # 10.10.2.2/31
    
    # --- Uplinks Rak 2 (Leaf 3 & 4) To Spines ---
    - endpoints: ["leaf3:eth1", "spine1:eth3"] # 10.10.1.4/31
    - endpoints: ["leaf3:eth2", "spine2:eth3"] # 10.10.2.4/31
    - endpoints: ["leaf4:eth1", "spine1:eth4"] # 10.10.1.6/31
    - endpoints: ["leaf4:eth2", "spine2:eth4"] # 10.10.2.6/31

    # --- MLAG Peer-Links | VLAN 4094 | LACP Po10 | iBGP---
    - endpoints: ["leaf1:eth3", "leaf2:eth3"]
    - endpoints: ["leaf1:eth4", "leaf2:eth4"]

    # --- MLAG Peer-Links | VLAN 4094 | LACP Po10 | iBGP---
    - endpoints: ["leaf3:eth3", "leaf4:eth3"]
    - endpoints: ["leaf3:eth4", "leaf4:eth4"]

    # --- Dual-Homed Hosts LACP Po50  ---
    - endpoints: ["host1:eth1", "leaf1:eth5"]
    - endpoints: ["host1:eth2", "leaf2:eth5"]

    # --- Dual-Homed Hosts LACP Po50  ---
    - endpoints: ["host2:eth1", "leaf3:eth5"]
    - endpoints: ["host2:eth2", "leaf4:eth5"]

```

# Task List

_"Kita bangun 2 Rak Data Center pakai desain Arista UCN. Spine (ASN 65010) dan SEMUA Leaf (ASN 65020). Host-1 di Vlan 100, Host-2 di Vlan 200."_

1. **Underlay P2P & Loopback:** Bikin IP _point-to-point_ `/31` antara semua Leaf dan Spine. Set IP Loopback0 untuk BGP Router-ID.
    
2. **MLAG & VARP (Anycast Gateway):** * Bikin MLAG domain di Rak 1 (Leaf 1 & 2) dan Rak 2 (Leaf 3 & 4).
    
    
    - Aktifkan VARP (Virtual ARP) di _interface_ Vlan100 (Rak 1) dan Vlan200 (Rak 2) sebagai _default gateway_ yang aktif/aktif.
        
3. **BGP Routing (The Trap):** * Bikin eBGP dari Leaf ke Spine dengan `maximum-paths 4` buat ECMP.
    
    
    - Tambahin sesi iBGP antar MLAG peer di setiap rak untuk _failover_.
        
    - Jangan lupa _advertise_ network Vlan ke BGP.
        
4. **Host Connectivity:** Bikin cEOS Host-1 dan Host-2 jalanin LACP Port-Channel ke arah Leaf, kasih IP, dan arahin _default route_-nya ke IP VARP.

# Config Guide

## Spine 1 & 2

```bash
configure
! IP Point-to-Point ke Leaf 1-4
interface Ethernet1
   no switchport
   ip address 10.10.1.0/31
interface Ethernet2
   no switchport
   ip address 10.10.1.2/31
interface Ethernet3
   no switchport
   ip address 10.10.1.4/31
interface Ethernet4
   no switchport
   ip address 10.10.1.6/31

interface Loopback0
   ip address 192.168.0.1/32

! BGP ASN 65010
router bgp 65010
   router-id 192.168.0.1
   maximum-paths 4 ecmp 4
   neighbor EBGP-TO-LEAF peer-group
   neighbor EBGP-TO-LEAF remote-as 65020
   neighbor 10.10.1.1 peer-group EBGP-TO-LEAF
   neighbor 10.10.1.3 peer-group EBGP-TO-LEAF
   neighbor 10.10.1.5 peer-group EBGP-TO-LEAF
   neighbor 10.10.1.7 peer-group EBGP-TO-LEAF
   network 192.168.0.1/32
end
```

## Leaf 1 & 2

```bash
configure
! Persiapan L2 & VARP MAC
vlan 100,4094
ip virtual-router mac-address 00:1c:73:00:00:99

! MLAG Peer-Link
interface Port-Channel10
   switchport mode trunk
   switchport trunk group MLAGPEER
interface Ethernet3
   channel-group 10 mode active
interface Ethernet4
   channel-group 10 mode active

! IP Control Plane MLAG
interface Vlan4094
   ip address 10.0.0.1/30

mlag configuration
   domain-id RACK1
   local-interface Vlan4094
   peer-address 10.0.0.2
   peer-link Port-Channel10

! P2P ke Spine 1 & 2
interface Ethernet1
   no switchport
   ip address 10.10.1.1/31
interface Ethernet2
   no switchport
   ip address 10.10.2.1/31

! Loopback & Gateway VARP Host
interface Loopback0
   ip address 192.168.0.11/32
interface Vlan100
   ip address 172.16.100.2/24
   ip virtual-router address 172.16.100.1

! LACP ke Host-1
interface Port-Channel50
   switchport access vlan 100
   mlag 50
interface Ethernet5
   channel-group 50 mode active

! BGP ASN 65020 (Common Leaf)
router bgp 65020
   router-id 192.168.0.11
   maximum-paths 4 ecmp 4
   
   ! Peering ke Spine (eBGP)
   neighbor EBGP-TO-SPINE peer-group
   neighbor EBGP-TO-SPINE remote-as 65010
   neighbor EBGP-TO-SPINE allowas-in 1
   neighbor 10.10.1.0 peer-group EBGP-TO-SPINE
   neighbor 10.10.2.0 peer-group EBGP-TO-SPINE
   
   ! Peering ke Leaf-2 (iBGP via Peer-Link)
   neighbor 10.0.0.2 remote-as 65020
   neighbor 10.0.0.2 next-hop-self
   neighbor 10.0.0.2 allowas-in 1
   
   ! Advertise Network
   network 192.168.0.11/32
   network 172.16.100.0/24
end
```

Leaf 3 & 4

```bash
configure
vlan 200,4094
ip virtual-router mac-address 00:1c:73:00:00:99

interface Port-Channel10
   switchport mode trunk
   switchport trunk group MLAGPEER
interface Ethernet3
   channel-group 10 mode active
interface Ethernet4
   channel-group 10 mode active

interface Vlan4094
   ip address 10.0.0.5/30

mlag configuration
   domain-id RACK2
   local-interface Vlan4094
   peer-address 10.0.0.6
   peer-link Port-Channel10

interface Ethernet1
   no switchport
   ip address 10.10.1.5/31
interface Ethernet2
   no switchport
   ip address 10.10.2.5/31

interface Loopback0
   ip address 192.168.0.13/32
interface Vlan200
   ip address 172.16.200.2/24
   ip virtual-router address 172.16.200.1

interface Port-Channel50
   switchport access vlan 200
   mlag 50
interface Ethernet5
   channel-group 50 mode active

router bgp 65020
   router-id 192.168.0.13
   maximum-paths 4 ecmp 4
   neighbor EBGP-TO-SPINE peer-group
   neighbor EBGP-TO-SPINE remote-as 65010
   neighbor EBGP-TO-SPINE allowas-in 1
   neighbor 10.10.1.4 peer-group EBGP-TO-SPINE
   neighbor 10.10.2.4 peer-group EBGP-TO-SPINE
   
   neighbor 10.0.0.6 remote-as 65020
   neighbor 10.0.0.6 next-hop-self
   neighbor 10.0.0.6 allowas-in 1
   
   network 192.168.0.13/32
   network 172.16.200.0/24
end
```

