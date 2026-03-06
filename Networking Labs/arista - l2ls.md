
# Yaml

```yaml
name: arista-l2ls-routing

topology:
  kinds:
    ceos:
      image: ceos:4.35.0F
    linux:
      image: ghcr.io/srl-labs/network-multitool:latest

  nodes:
    spine1: { kind: ceos }
    spine2: { kind: ceos }
    leaf1:  { kind: ceos }
    leaf2:  { kind: ceos }
    
    # Host 1 - VLAN 100
    host1:
      kind: linux
      exec:
        - ip link set eth1 down
        - ip link set eth2 down
        - ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
        - ip link set eth1 master bond0
        - ip link set eth2 master bond0
        - ip link set bond0 up
        - ip link set eth1 up
        - ip link set eth2 up
        - ip addr add 172.20.0.100/24 dev bond0
        - ip route add default via 172.20.0.1
        
    # Host 2 - VLAN 200
    host2:
      kind: linux
      exec:
        - ip link set eth1 down
        - ip link set eth2 down
        - ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
        - ip link set eth1 master bond0
        - ip link set eth2 master bond0
        - ip link set bond0 up
        - ip link set eth1 up
        - ip link set eth2 up
        - ip addr add 172.30.0.100/24 dev bond0
        - ip route add default via 172.30.0.1

  links:
    # SPINE PEER-LINK
    - endpoints: ["spine1:eth1", "spine2:eth1"]
    - endpoints: ["spine1:eth2", "spine2:eth2"]
    
    # LEAF PEER-LINK
    - endpoints: ["leaf1:eth1", "leaf2:eth1"]
    - endpoints: ["leaf1:eth2", "leaf2:eth2"]

    # LEAF-SPINE BOW-TIE
    - endpoints: ["leaf1:eth3", "spine1:eth3"]
    - endpoints: ["leaf1:eth4", "spine2:eth3"]
    - endpoints: ["leaf2:eth3", "spine1:eth4"]
    - endpoints: ["leaf2:eth4", "spine2:eth4"]

    # DUAL-HOMED HOST 1 (VLAN 100)
    - endpoints: ["leaf1:eth5", "host1:eth1"]
    - endpoints: ["leaf2:eth5", "host1:eth2"]
    
    # DUAL-HOMED HOST 2 (VLAN 200)
    - endpoints: ["leaf1:eth6", "host2:eth1"]
    - endpoints: ["leaf2:eth6", "host2:eth2"]
```

# Task List



# Config Guide

## Leaf 1 & Leaf 2

```bash
configure terminal
! Aktifkan LACP Fast untuk mempercepat deteksi LACP
lacp rate fast

vlan 100,200
vlan 4094
   trunk group mlagpeer

! Peer-Link antar Spine
interface Ethernet1-2
   channel-group 10 mode active
interface Port-Channel10
   switchport mode trunk
   switchport trunk group mlagpeer

! Downlink ke Leaf (MLAG ID disamakan di kedua Spine)
interface Ethernet3-4
   channel-group 12 mode active
interface Port-Channel12
   description DOWNLINK_TO_LEAF_PAIR
   switchport mode trunk
   mlag 12

! MLAG Configuration
interface Vlan4094
   ip address 172.16.11.1/30  ! (Ganti jadi .2 di Spine-2)
mlag configuration
   domain-id SPINE_MLAG
   local-interface Vlan4094
   peer-address 172.16.11.2   ! (Ganti jadi .1 di Spine-2)
   peer-link Port-Channel10
```

## Spine 1 & Spine 2

```bash
configure terminal
! Jangan lupa nyalakan routing global!
ip routing
lacp rate fast

! VARP Global vMAC (Sama di Leaf1 dan Leaf2)
ip virtual-router mac-address 00:1c:73:00:00:99

vlan 100,200
vlan 4094
   trunk group mlagpeer

! Peer-Link antar Leaf
interface Ethernet1-2
   channel-group 10 mode active
interface Port-Channel10
   switchport mode trunk
   switchport trunk group mlagpeer

! Uplink ke Spine (MLAG ID disamakan di kedua Leaf)
interface Ethernet3-4
   channel-group 12 mode active
interface Port-Channel12
   description UPLINK_TO_SPINE_PAIR
   switchport mode trunk
   mlag 12

! Downlink ke Host1 (VLAN 100)
interface Ethernet5
   channel-group 1 mode active
interface Port-Channel1
   description HOST_1_VLAN_100
   switchport access vlan 100
   mlag 1
   port-channel lacp fallback static

! Downlink ke Host2 (VLAN 200)
interface Ethernet6
   channel-group 2 mode active
interface Port-Channel2
   description HOST_2_VLAN_200
   switchport access vlan 200
   mlag 2
   port-channel lacp fallback static

! SVI Peering MLAG
interface Vlan4094
   ip address 172.16.12.1/30  ! (Ganti jadi .2 di Leaf-2)

! SVI Gateway Host1 (VLAN 100)
interface Vlan100
   ip address 172.20.0.2/24   ! (Ganti jadi .3 di Leaf-2)
   ip virtual-router address 172.20.0.1

! SVI Gateway Host2 (VLAN 200)
interface Vlan200
   ip address 172.30.0.2/24   ! (Ganti jadi .3 di Leaf-2)
   ip virtual-router address 172.30.0.1

! MLAG Configuration
mlag configuration
   domain-id LEAF_MLAG
   local-interface Vlan4094
   peer-address 172.16.12.2   ! (Ganti jadi .1 di Leaf-2)
   peer-link Port-Channel10
```
