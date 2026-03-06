# Topology

```yaml
name: lab-sr-basic
topology:
  nodes:
    pe1:
      kind: cisco_xrd
      image: ios-xr/xrd-control-plane:7.11.2
    p1:
      kind: cisco_xrd
      image: ios-xr/xrd-control-plane:7.11.2
    pe2:
      kind: cisco_xrd
      image: ios-xr/xrd-control-plane:7.11.2
  links:
    - endpoints: ["pe1:Gi0-0-0-0", "p1:Gi0-0-0-0"] # Link PE1 ke P1
    - endpoints: ["p1:Gi0-0-0-1", "pe2:Gi0-0-0-0"] # Link P1 ke PE2
```

# Segment Routing

## P1

```bash
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
router ospf 1
 router-id 11.11.11.11
 segment-routing mpls
 area 0
  interface Loopback0
   passive enable
   prefix-sid index 11
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
  !
  interface GigabitEthernet0/0/0/1
   network point-to-point
  !
 !
!
commit
```

## PE1

```bash
! 1. Konfigurasi IP Dasar
interface Loopback0
 ipv4 address 1.1.1.1 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 ipv4 address 10.11.1.1 255.255.255.0
 no shutdown
!
! 2. Konfigurasi OSPF dengan Segment Routing
router ospf 1
 router-id 1.1.1.1
 ! Aktifkan fitur SR untuk membagikan label MPLS
 segment-routing mpls
 !
 area 0
  interface Loopback0
   passive enable
   ! Berikan nomor punggung (Index 1 = Label 16001)
   prefix-sid index 1
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
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
 segment-routing mpls
 area 0
  interface Loopback0
   passive enable
   prefix-sid index 2
  !
  interface GigabitEthernet0/0/0/0
   network point-to-point
  !
 !
!
commit
```

## Verification

```bash
show mpls ldp neighbor 

show route ospf wide

show mpls forwarding
```

# L3VPN

## PE1

```bash
! 1. Konfigurasi VRF Pelanggan
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
! 2. Simulasi Network Pelanggan (CE)
interface Loopback10
 vrf VPN-DC
 ipv4 address 192.168.10.1 255.255.255.0
!
! 3. Konfigurasi iBGP & Injeksi Rute
router bgp 65000
 bgp router-id 1.1.1.1
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 neighbor 2.2.2.2
  remote-as 65000
  update-source Loopback0
  address-family vpnv4 unicast
  !
 !
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
interface Loopback10
 vrf VPN-DC
 ipv4 address 192.168.20.1 255.255.255.0
!
router bgp 65000
 bgp router-id 2.2.2.2
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 neighbor 1.1.1.1
  remote-as 65000
  update-source Loopback0
  address-family vpnv4 unicast
  !
 !
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
show route vrf VPN-DC
show bgp vpnv4 unicast vrf VPN-DC 192.168.20.0/24
show cef vrf VPN-DC 192.168.20.1
ping vrf VPN-DC 192.168.20.1 source lo10
show bgp vpnv4 unicast labels
```