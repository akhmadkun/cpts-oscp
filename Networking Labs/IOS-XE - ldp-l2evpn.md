# Yaml

```yml
name: evpn-ldp-lab
topology:
  nodes:
    pe1:
      kind: cisco_c8000v
      image: arthurk99/cisco-c8000v:17.11.01a
    p1:
      kind: cisco_c8000v
      image: arthurk99/cisco-c8000v:17.11.01a
    pe2:
      kind: cisco_c8000v
      image: arthurk99/cisco-c8000v:17.11.01a
    host1:
      kind: arista_ceos
      image: ceos:4.35.0F
    host2:
      kind: arista_ceos
      image: ceos:4.35.0F

  links:
    - endpoints: ["pe1:eth2", "p1:eth2"]
    - endpoints: ["pe2:eth2", "p1:eth3"]
    - endpoints: ["pe1:eth3", "host1:eth1"]
    - endpoints: ["pe2:eth3", "host2:eth1"]
```

# Config Guide

## Phase 1: The Underlay (OSPF & LDP)

**Goal:** Make sure all routers can reach each other's Loopback IPs and can exchange MPLS labels.

- **OSPF** provides the basic routing map (IP reachability).
    
- **LDP** assigns labels for normal unicast traffic (like replies to pings).
    
- **mLDP** builds a "tree" for multicast traffic (like broadcast ARP requests).

```bash
hostname PE1
! We need multicast routing enabled for mLDP to build its trees
multicast-routing
!
! Loopback acts as our Router ID and BGP source IP
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
 ip router ospf 1 area 0
!
! The physical interface facing the P1 core router
interface GigabitEthernet2
 description TO_P1
 ip address 10.1.12.1 255.255.255.0
 ip router ospf 1 area 0
 no shutdown
!
router ospf 1
 router-id 1.1.1.1
 ! This automatically turns on LDP on all OSPF interfaces
 mpls ldp autoconfig
```

## Phase 2: The Control Plane (BGP EVPN)

**Goal:** Use BGP to share MAC addresses between PE routers so they know where the hosts live.

- **P1** will act as a Route Reflector. This means PE1 and PE2 only need to peer with P1, instead of peering with everyone in the network.
    
- We use the **l2vpn evpn** address family because standard BGP only shares IP addresses, but we need to share MAC addresses.

`P1`
```bash
router bgp 65000
 bgp router-id 2.2.2.2
 neighbor 1.1.1.1 remote-as 65000
 neighbor 1.1.1.1 update-source Loopback0
 neighbor 3.3.3.3 remote-as 65000
 neighbor 3.3.3.3 update-source Loopback0
 !
 address-family l2vpn evpn
  neighbor 1.1.1.1 activate
  neighbor 1.1.1.1 send-community both
  neighbor 1.1.1.1 route-reflector-client
  neighbor 3.3.3.3 activate
  neighbor 3.3.3.3 send-community both
  neighbor 3.3.3.3 route-reflector-client
```

`PE1`
```bash
router bgp 65000
 bgp router-id 1.1.1.1
 neighbor 2.2.2.2 remote-as 65000
 neighbor 2.2.2.2 update-source Loopback0
 !
 address-family l2vpn evpn
  neighbor 2.2.2.2 activate
  neighbor 2.2.2.2 send-community both
```


## Phase 3: The EVPN Overlay & Attachment Circuit

**Goal:** Create the virtual switch (MAC-VRF) and connect our physical host port to it.

- **core-tree mldp-p2mp:** This is the magic command. It tells the router, "When you get a broadcast packet (like an ARP), do not make copies yourself. Send it into the mLDP multicast tree in the core network."

`PE1`

```bash
! Create the EVPN instance (our virtual switch)
l2vpn evpn instance 10 mac-based
 route-target export 65000:10
 route-target import 65000:10
 ! Tell EVPN to use mLDP for BUM traffic
 core-tree mldp-p2mp default-root
!
! Bind the EVPN instance to a Virtual Forwarding Instance (VFI)
vfi EVPN-10 l2vc
 evpn instance 10
!
! Connect the Arista host to the EVPN instance
interface GigabitEthernet3
 description TO_HOST1
 no ip address
 no shutdown
 service instance 10 ethernet
  encapsulation untagged
  xconnect vfi EVPN-10
```

# Testing

To prove the lab works, the junior engineer should follow these verification steps in order:

**1. Test the Data Plane (The Ping Test)** Log into Host 1 and ping Host 2. The first ping might drop while ARP and MAC addresses are shared, but subsequent pings should succeed.

- `ping 192.168.10.2`

**2. Verify the Underlay (OSPF & LDP)** If the ping fails, check the foundation first. On PE1, check if LDP neighbors are formed and if Loopback IPs have labels.

- `show mpls ldp neighbor` (Should show P1 as a neighbor).
    
- `show mpls forwarding-table` (Ensure there is a label for 3.3.3.3, which is PE2).
    

**3. Verify the BGP EVPN Control Plane** Check if BGP is actually sharing the MAC addresses. On PE1:

- `show bgp l2vpn evpn summary` (Verify the BGP session to P1 is 'Established').
    
- `show bgp l2vpn evpn` (Look for Route Type 2 [MAC/IP] routes. You should see Host 2's MAC address learned from 3.3.3.3).
    

**4. Verify the Underlay Multicast (mLDP)** Verify that the `core-tree` command successfully built an mLDP tree for the broadcast traffic. On PE1 or P1:

- `show mpls mldp database` (This shows the Root and Opaque values for the Multipoint tree).
    
- `show l2vpn evpn mcast` (This verifies that EVPN Instance 10 is successfully mapped to an mLDP tree instead of using Ingress Replication).