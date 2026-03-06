
# Underlay

## P1

```bash
! 1. IP Addressing
interface Loopback0
 ipv4 address 11.11.11.11 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 ipv4 address 10.11.1.11 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/0/0/1
 ipv4 address 10.11.2.11 255.255.255.0
 no shutdown
!
! 2. OSPF & BFD (Underlay)
router ospf 1
 router-id 11.11.11.11
 area 0
  interface Loopback0
   passive enable
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
   bfd fast-detect
  !
  interface GigabitEthernet0/0/0/1
   network point-to-point
   bfd fast-detect
  !
 !
!
! 3. LDP (Label Distribution)
mpls ldp
 nsr
 igp sync delay on-session-up 10
 router-id 11.11.11.11
 interface GigabitEthernet0/0/0/0
 !
 interface GigabitEthernet0/0/0/1
 !
!
commit
```

## PE1

```bash
! 1. IP Addressing
interface Loopback0
 ipv4 address 1.1.1.1 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 ipv4 address 10.11.1.1 255.255.255.0
 no shutdown
!
! 2. OSPF & BFD
router ospf 1
 router-id 1.1.1.1
 area 0
  interface Loopback0
   passive enable
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
   bfd fast-detect
  !
 !
!
! 3. LDP
mpls ldp
 nsr
 igp sync delay on-session-up 10
 router-id 1.1.1.1
 interface GigabitEthernet0/0/0/0
 !
!
! 4. iBGP (Ke PE2)
router bgp 65000
 bgp router-id 1.1.1.1
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 address-family l2vpn evpn
 !
 neighbor 2.2.2.2
  remote-as 65000
  update-source Loopback0
  address-family vpnv4 unicast
  !
  address-family l2vpn evpn
  !
 !
!
commit
```

## PE2

```bash
interface Loopback0
 ipv4 address 2.2.2.2 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 ipv4 address 10.11.2.2 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 2.2.2.2
 area 0
  interface Loopback0
   passive enable
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
   bfd fast-detect
  !
 !
!
mpls ldp
 nsr
 igp sync delay on-session-up 10
 router-id 2.2.2.2
 interface GigabitEthernet0/0/0/0
 !
!
router bgp 65000
 bgp router-id 2.2.2.2
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 address-family l2vpn evpn
 !
 neighbor 1.1.1.1
  remote-as 65000
  update-source Loopback0
  address-family vpnv4 unicast
  !
  address-family l2vpn evpn
  !
 !
!
commit
```

## tshoot

```bash
clear bgp *
```

# L3VPN & VRF

## PE1

```bash
! 1. Buat VRF Pelanggan
vrf VPN-DC
 rd 65000:206
 address-family ipv4 unicast
  import route-target
   65000:20
  !
  export route-target
   65000:20
  !
 !
!
! 2. Buat Interface Pelanggan (Simulasi CE)
interface Loopback10
 vrf VPN-DC
 ipv4 address 192.168.10.1 255.255.255.0
!
! 3. Injeksi Rute VRF ke BGP
router bgp 65000
 vrf VPN-DC
  address-family ipv4 unicast
   redistribute connected
  !
 !
!
commit
```

## PE2

```bash
! 1. Buat VRF Pelanggan
vrf VPN-DC
 rd 65000:206
 address-family ipv4 unicast
  import route-target
   65000:20
  !
  export route-target
   65000:20
  !
 !
!
! 2. Buat Interface Pelanggan (Simulasi CE)
interface Loopback10
 vrf VPN-DC
 ipv4 address 192.168.20.1 255.255.255.0
!
! 3. Injeksi Rute VRF ke BGP
router bgp 65000
 vrf VPN-DC
  address-family ipv4 unicast
   redistribute connected
  !
 !
!
commit
```

## Verification

```bash
show bgp vpnv4 unicast summary

show route vrf VPN-DC

ping vrf VPN-DC 192.168.10.1 source 192.168.20.1
```

# L2VPN & EVPN IRB

## PE1

```bash
! 1. Buat Port L2 Pelanggan (Simulasi Trunk)
interface GigabitEthernet0/0/0/2
 no shutdown
!
interface GigabitEthernet0/0/0/2.321 l2transport
 encapsulation dot1q 321
!
! 2. Buat Gateway BVI untuk VLAN 321
interface BVI321
 vrf VPN-DC
 ipv4 address 10.10.10.1 255.255.255.0
 mac-address 0000.aaaa.bbbb
!
! 3. Konfigurasi Protokol EVPN (Control Plane)
evpn
 evi 321
  bgp
   rd 65000:321
   route-target import 65000:321
   route-target export 65000:321
  !
  advertise-mac
 !
!
! 4. Pengikatan L2VPN Bridge-Domain
l2vpn
 bridge group EVPN_ALL_ACTIVE
  bridge-domain EVPN_321
   interface GigabitEthernet0/0/0/2.321
   !
   routed interface BVI321
   !
   evi 321
   !
  !
 !
!
commit
```

## PE2

```bash
! 1. Buat Port L2 Pelanggan (Simulasi Trunk)
interface GigabitEthernet0/0/0/2
 no shutdown
!
interface GigabitEthernet0/0/0/2.321 l2transport
 encapsulation dot1q 321
!
! 2. Buat Gateway BVI untuk VLAN 321
interface BVI321
 vrf VPN-DC
 ipv4 address 10.10.10.2 255.255.255.0
 mac-address 0000.aaaa.cccc
!
! 3. Konfigurasi Protokol EVPN (Control Plane)
evpn
 evi 321
  bgp
   rd 65000:321
   route-target import 65000:321
   route-target export 65000:321
  !
  advertise-mac
 !
!
! 4. Pengikatan L2VPN Bridge-Domain
l2vpn
 bridge group EVPN_ALL_ACTIVE
  bridge-domain EVPN_321
   interface GigabitEthernet0/0/0/2.321
   !
   routed interface BVI321
   !
   evi 321
   !
  !
 !
!
commit
```