
# Yaml

```yaml
name: rsvp-vpn-lab
prefix: ""
topology:
  nodes:
    # loopback0 : 1.1.1.1/32 | OSPF Area 0
    # MP-BGP L3VPN to R4
    r1:
      kind: juniper_vjunosrouter
      image: vrnetlab/juniper_vjunos-router:25.4R1.12
    # loopback0 : 2.2.2.2/32 | OSPF Area 0
    r2:
      kind: juniper_vjunosrouter
      image: vrnetlab/juniper_vjunos-router:25.4R1.12
    # loopback0 : 3.3.3.3/32 | OSPF Area 0
    r3:
      kind: juniper_vjunosrouter
      image: vrnetlab/juniper_vjunos-router:25.4R1.12
    # loopback0 : 4.4.4.4/32 | OSPF Area 0
    # MP-BGP L3VPN to R4
    r4:
      kind: juniper_vjunosrouter
      image: vrnetlab/juniper_vjunos-router:25.4R1.12

  links:
    # RSVP Primary Path
    - endpoints: ["r1:eth1", "r2:eth1"] # 10.10.12.0/24
    - endpoints: ["r2:eth2", "r4:eth2"] # 10.10.24.0/24
    
    # RSVP Secondary Path
    - endpoints: ["r1:eth2", "r3:eth2"] # 10.10.13.0/24
    - endpoints: ["r3:eth1", "r4:eth1"] # 10.10.34.0/24

```

# Task List

- **Task 1: Underlay (IGP & MPLS)**
    
    - Konfigurasi IP Address di semua _interface_ fisik dan Loopback0 (R1=1.1.1.1, R2=2.2.2.2, dst).
        
    - Aktifkan OSPF Area 0, MPLS, dan RSVP di semua _interface_ transit. Jangan lupa nyalakan _Traffic Engineering extensions_ di OSPF.
        
- **Task 2: RSVP-TE dengan Secondary Path**
    
    - Di **R1** dan **R4**, buat RSVP LSP yang saling terhubung.
        
    - Gunakan fitur `path` untuk mendefinisikan _strict hop_. Jalur via R2 sebagai **Primary**, dan jalur via R3 sebagai **Secondary** (dengan mode _standby_).
        
- **Task 3: MP-BGP (Control Plane L3VPN)**
    
    - Bangun sesi iBGP antara Loopback R1 dan R4. Aktifkan _address family_ khusus untuk mendistribusikan rute VPN (`inet-vpn unicast`).
        
- **Task 4: L3VPN / VRF (Data Plane)**
    
    - Di **R1** dan **R4**, buat _routing-instance_ bertipe VRF dengan nama `VPN-A`.
        
    - Gunakan Route Distinguisher dan VRF Target bebas (misal: `65000:100`).
        
    - Buat _interface_ `lo0.100` dan masukkan ke dalam VRF sebagai simulasi _network_ pelanggan (R1 = `192.168.1.1/24`, R4 = `192.168.4.1/24`).
	     
- Task 5: Carrier-Grade Fast Reroute (FRR)

# Config Guide

## R1

```bash
conf t
# Interface & Loopback
set interfaces ge-0/0/0 unit 0 family inet address 10.10.12.1/24
set interfaces ge-0/0/0 unit 0 family mpls
set interfaces ge-0/0/1 unit 0 family inet address 10.10.13.1/24
set interfaces ge-0/0/1 unit 0 family mpls
set interfaces lo0 unit 0 family inet address 1.1.1.1/32

# OSPF & Underlay MPLS
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf traffic-engineering
set protocols mpls interface ge-0/0/0.0
set protocols mpls interface ge-0/0/1.0
set protocols mpls interface lo0.0
set protocols rsvp interface ge-0/0/0.0
set protocols rsvp interface ge-0/0/1.0
set protocols rsvp interface lo0.0

# RSVP-TE Primary & Secondary Path
set protocols mpls path PATH-VIA-R2 10.10.12.2 strict
set protocols mpls path PATH-VIA-R3 10.10.13.3 strict
set protocols mpls label-switched-path LSP-R1-TO-R4 to 4.4.4.4 primary PATH-VIA-R2
set protocols mpls label-switched-path LSP-R1-TO-R4 secondary PATH-VIA-R3 standby

# MP-BGP L3VPN
set routing-options autonomous-system 65000
set protocols bgp group IBGP-VPN type internal
set protocols bgp group IBGP-VPN local-address 1.1.1.1
set protocols bgp group IBGP-VPN family inet-vpn unicast
set protocols bgp group IBGP-VPN neighbor 4.4.4.4

# VRF & Customer Interface
set interfaces lo0 unit 100 family inet address 192.168.1.1/24
set routing-instances VPN-A instance-type vrf
set routing-instances VPN-A interface lo0.100
set routing-instances VPN-A route-distinguisher 1.1.1.1:100
set routing-instances VPN-A vrf-target target:65000:100
commit
```

# Verify

```bash
admin@r1# run show rsvp neighbor
RSVP neighbor: 4 learned
Address            Idle Up/Dn LastChange HelloInt HelloTx/Rx MsgRcvd
2.2.2.2               0  1/0        1:40        9    12/12   0
3.3.3.3               0  1/0        1:40        9    12/12   0
10.10.13.3            0  1/0        1:40        9    13/12   0
10.10.12.2            0  1/0        1:40        9    11/10   0
```