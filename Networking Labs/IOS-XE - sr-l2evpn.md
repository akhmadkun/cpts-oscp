
# Topology

```yaml
name: lab-csr-evpn
prefix: ""
topology:
  nodes:
    pe1:
      kind: cisco_csr1000v
      image: arthurk99/cisco-csr1000v:17.03.08
    p1:
      kind: cisco_csr1000v
      image: arthurk99/cisco-csr1000v:17.03.08
    pe2:
      kind: cisco_csr1000v
      image: arthurk99/cisco-csr1000v:17.03.08
    ce1:
      kind: linux
      image: alpine:latest
    ce2:
      kind: linux
      image: alpine:latest

  links:
    - endpoints: ["pe1:eth1", "p1:eth1"] # Gi2 to Gi2
    - endpoints: ["p1:eth2", "pe2:eth1"] # Gi3 to Gi2
    - endpoints: ["ce1:eth1", "pe1:eth2"] # Gi3
    - endpoints: ["ce2:eth1", "pe2:eth2"] # Gi3
```

# Underlay

## P1

```bash
interface GigabitEthernet2
 mtu 1550
 ip address 10.0.1.11 255.255.255.0
 ip ospf network point-to-point
 ip ospf 1 area 0
 
interface GigabitEthernet3
 mtu 1550
 ip address 10.0.2.11 255.255.255.0
 ip ospf network point-to-point
 ip ospf 1 area 0
 

segment-routing mpls
!
router ospf 1
 router-id 3.3.3.3
 segment-routing mpls
!
```

## PE1

```bash
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
 ip ospf 1 area 0
 
interface GigabitEthernet2
 mtu 1550
 ip address 10.0.1.1 255.255.255.0
 ip ospf network point-to-point
 ip ospf 1 area 0
 
segment-routing mpls
 connected-prefix-sid-map
  address-family ipv4
   1.1.1.1/32 index 1 range 1
  exit-address-family
 
router ospf 1
 router-id 1.1.1.1
 segment-routing mpls

```

## PE2

```bash
interface Loopback0
 ip address 2.2.2.2 255.255.255.255
 ip ospf 1 area 0
 
interface GigabitEthernet2
 mtu 1550
 ip address 10.0.2.2 255.255.255.0
 ip ospf network point-to-point
 ip ospf 1 area 0

segment-routing mpls
 !
 connected-prefix-sid-map
  address-family ipv4
   2.2.2.2/32 index 2 range 1
  exit-address-family
 !
!
router ospf 1
 router-id 2.2.2.2
 segment-routing mpls
```

# Overlay

## PE1

```bash
router bgp 65000
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes
 neighbor 2.2.2.2 remote-as 65000
 neighbor 2.2.2.2 update-source Loopback0
 !
 address-family l2vpn evpn
  neighbor 2.2.2.2 activate
  neighbor 2.2.2.2 send-community both
```

## PE2

```bash
router bgp 65000
 bgp router-id 2.2.2.2
 bgp log-neighbor-changes
 neighbor 1.1.1.1 remote-as 65000
 neighbor 1.1.1.1 update-source Loopback0
 !
 address-family l2vpn evpn
  neighbor 1.1.1.1 activate
  neighbor 1.1.1.1 send-community both
```

# L2VPN

## PE1

```bash
interface GigabitEthernet3
 service instance 100 ethernet
  encapsulation dot1q 100
  rewrite ingress tag pop 1 symmetric

l2vpn evpn
 replication-type ingress
!
l2vpn evpn instance 100 vlan-based
 route-target export 65000:100
 route-target import 65000:100
 replication-type ingress

bridge-domain 100
 member GigabitEthernet3 service-instance 100
 member evpn-instance 100
```

## PE2

```bash
interface GigabitEthernet3
 service instance 100 ethernet
  encapsulation dot1q 100
  rewrite ingress tag pop 1 symmetric
 !
l2vpn evpn
 replication-type ingress
!
l2vpn evpn instance 100 vlan-based
 route-target export 65000:100
 route-target import 65000:100
 replication-type ingress
```

### untagged

```
interface GigabitEthernet3
 service instance 100 ethernet
  encapsulation untagged
```
## CE1 & CE2

```bash
ip link add link eth1 name eth1.100 type vlan id 100
ip addr add 192.168.100.1/24 dev eth1.100
ip link set eth1 up
ip link set eth1.100 up
```

# Verification

```bash
show mpls forwarding-table

show bgp l2vpn evpn summary

show bridge-domain 100

show l2vpn evpn evi 100 detail
```