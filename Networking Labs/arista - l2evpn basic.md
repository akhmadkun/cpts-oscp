
# IP Address

| **Node**   | **Role**    | **Interface** | **IP Address** | **Description**       |
| ---------- | ----------- | ------------- | -------------- | --------------------- |
| **Spine1** | Underlay/RR | Loopback0     | **3.3.3.3/32** | Router ID & BGP ID    |
|            |             | Ethernet1     | 10.1.1.0/31    | Link to Leaf1         |
|            |             | Ethernet2     | 10.1.1.2/31    | Link to Leaf2         |
| **Leaf1**  | VTEP        | Loopback0     | **1.1.1.1/32** | VTEP Source IP        |
|            |             | Ethernet1     | 10.1.1.1/31    | Link to Spine1        |
|            |             | Ethernet2     | -              | Access Port (VLAN 10) |
| **Leaf2**  | VTEP        | Loopback0     | **2.2.2.2/32** | VTEP Source IP        |
|            |             | Ethernet1     | 10.1.1.3/31    | Link to Spine1        |
|            |             | Ethernet2     | -              | Access Port (VLAN 10) |
# CLAB Topology

```yaml
name: arista-evpn
topology:
  kinds:
    ceos:
      image: ceos:latest
    linux:
      image: alpine:latest
  nodes:
    spine1: { kind: ceos }
    leaf1:  { kind: ceos }
    leaf2:  { kind: ceos }
    host1:
      kind: linux
      exec:
        - ip addr add 192.168.10.11/24 dev eth1
    host2:
      kind: linux
      exec:
        - ip addr add 192.168.10.12/24 dev eth1

  links:
    - endpoints: ["leaf1:eth1", "spine1:eth1"]
    - endpoints: ["leaf2:eth1", "spine1:eth2"]
    - endpoints: ["leaf1:eth2", "host1:eth1"]
    - endpoints: ["leaf2:eth2", "host2:eth1"]
```

# Config Stesp

## Pre-Requisites

```
configure terminal
service routing protocols model multi-agent
write
reload now
! Tunggu switch up kembali
```

## Spine1

```bash
hostname Spine1

! Interfaces
interface Ethernet1
   no switchport
   ip address 10.1.1.0/31
!
interface Ethernet2
   no switchport
   ip address 10.1.1.2/31
!
interface Loopback0
   ip address 3.3.3.3/32

! Underlay Routing (OSPF)
router ospf 1
   router-id 3.3.3.3
   network 0.0.0.0/0 area 0

! Overlay Routing (BGP EVPN)
router bgp 65001
   router-id 3.3.3.3
   no bgp default ipv4-unicast
   distance bgp 20 200 200
   maximum-paths 4 ecmp 4
   !
   ! Define Peer Group for Leafs
   neighbor EVPN-CLIENTS peer group
   neighbor EVPN-CLIENTS remote-as 65001
   neighbor EVPN-CLIENTS update-source Loopback0
   neighbor EVPN-CLIENTS route-reflector-client
   neighbor EVPN-CLIENTS send-community
   !
   ! Neighbors (Leaf1 & Leaf2 Loopbacks)
   neighbor 1.1.1.1 peer group EVPN-CLIENTS
   neighbor 2.2.2.2 peer group EVPN-CLIENTS
   !
   address-family evpn
      neighbor EVPN-CLIENTS activate
```

## Leaf 1

```bash
hostname Leaf1

! Access Port to Host & LLDP Security
vlan 10
   name TENANT_A
!
interface Ethernet2
   switchport access vlan 10
   no lldp transmit
!
! Underlay Interfaces
interface Ethernet1
   no switchport
   ip address 10.1.1.1/31
!
interface Loopback0
   description VTEP_SOURCE
   ip address 1.1.1.1/32

! Underlay Routing (OSPF)
router ospf 1
   router-id 1.1.1.1
   network 0.0.0.0/0 area 0

! VXLAN Interface
interface Vxlan1
   vxlan source-interface Loopback0
   vxlan udp-port 4789
   vxlan vlan 10 vni 10010

! Overlay Routing (BGP EVPN)
router bgp 65001
   router-id 1.1.1.1
   no bgp default ipv4-unicast
   !
   ! Peering to Spine (3.3.3.3)
   neighbor 3.3.3.3 remote-as 65001
   neighbor 3.3.3.3 update-source Loopback0
   neighbor 3.3.3.3 send-community
   !
   address-family evpn
      neighbor 3.3.3.3 activate
   !
   ! VNI Advertisement
   vlan 10
      rd 1.1.1.1:10010
      route-target both 10010:10010
      redistribute learned
```

## Leaf 2

```bash
hostname Leaf2

! Access Port to Host
vlan 10
   name TENANT_A
!
interface Ethernet2
   switchport access vlan 10
   no lldp transmit
!
! Underlay Interfaces
interface Ethernet1
   no switchport
   ip address 10.1.1.3/31
!
interface Loopback0
   description VTEP_SOURCE
   ip address 2.2.2.2/32

! Underlay Routing (OSPF)
router ospf 1
   router-id 2.2.2.2
   network 0.0.0.0/0 area 0

! VXLAN Interface
interface Vxlan1
   vxlan source-interface Loopback0
   vxlan udp-port 4789
   vxlan vlan 10 vni 10010

! Overlay Routing (BGP EVPN)
router bgp 65001
   router-id 2.2.2.2
   no bgp default ipv4-unicast
   !
   ! Peering to Spine (3.3.3.3)
   neighbor 3.3.3.3 remote-as 65001
   neighbor 3.3.3.3 update-source Loopback0
   neighbor 3.3.3.3 send-community
   !
   address-family evpn
      neighbor 3.3.3.3 activate
   !
   ! VNI Advertisement
   vlan 10
      rd 2.2.2.2:10010
      route-target both 10010:10010
      redistribute learned
```


# Verification

## Underlay Check

```bash
Leaf1# ping 2.2.2.2
! Expect: 0% packet loss
```

## Control Plane Check

```bash
Leaf1# show bgp evpn summary
! Expect: Neighbor 3.3.3.3 State = Estab

Leaf1# show bgp evpn route-type imet
! Expect: Route dari 2.2.2.2 (Leaf2)
```

## Data Plane Check

```bash
Leaf1# show interfaces vxlan 1
! Expect: Status Up, Vlan 10 maps to vni 10010

Leaf1# show vxlan flood vtep
! Expect: Vlan 10 -> IP Address 2.2.2.2
```

## End to End Check

```bash
(Host1 Linux Shell)# ping 192.168.10.12
```
