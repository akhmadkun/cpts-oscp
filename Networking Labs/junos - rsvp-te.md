
# Yaml

```yaml
name: rsvp-te-basic
prefix: ""
topology:
  nodes:
    r1:
      kind: juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    r2:
      kind: juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    r3:
      kind: juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
    r4:
      kind: juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9

  links:
    # R1 (ge-0/0/0) <---> R2 (ge-0/0/0) : 10.10.12.0/24
    - endpoints: ["r1:eth1", "r2:eth1"]

    # R2 (ge-0/0/1) <---> R3 (ge-0/0/1) : 10.10.23.0/24
    - endpoints: ["r2:eth2", "r3:eth2"]

    # R3 (ge-0/0/0) <---> R4 (ge-0/0/0) : 10.10.34.0/24
    - endpoints: ["r3:eth1", "r4:eth1"]
```

# Task List

- **Task 1: IP Addressing & Data Plane MPLS**
    
    - Konfigurasikan IP _address_ pada semua _link point-to-point_ (`ge-0/0/0` dan `ge-0/0/1`) serta `lo0.0` di keempat router.
        
    - Aktifkan pemrosesan label di _Data Plane_ untuk semua antarmuka fisik transit. _(Hint: family...)_
        
- **Task 2: IGP & Traffic Engineering (TED)**
    
    - Aktifkan OSPF Area 0 di semua _link_ fisik dan _loopback_.
        
    - Karena kita akan menggunakan CSPF, pastikan router bisa mendistribusikan informasi _bandwidth_/metrik tambahan. Aktifkan _Traffic Engineering extensions_ di dalam OSPF.
        
- **Task 3: Control Plane MPLS & RSVP**
    
    - Aktifkan protokol MPLS dan RSVP pada seluruh antarmuka fisik dan _loopback_ di keempat router agar mereka bisa saling bertukar pesan persinyalan jalur.
        
- **Task 4: Tunnel Provisioning**
    
    - Di **R1**, buat satu buah RSVP Label-Switched Path (LSP) menuju IP Loopback **R4**. Beri nama `LSP-R1-to-R4`.
        
    - Di **R4**, buat LSP balasan menuju IP Loopback **R1**. Beri nama `LSP-R4-to-R1`.

# Answer

## R1

```bash
conf t
# Task 1: IP & Data Plane
set interfaces ge-0/0/0 unit 0 family inet address 10.1.2.1/24
set interfaces ge-0/0/0 unit 0 family mpls
set interfaces lo0 unit 0 family inet address 1.1.1.1/32

# Task 2: OSPF & TE
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf traffic-engineering

# Task 3: MPLS & RSVP Control Plane
set protocols mpls interface ge-0/0/0.0
set protocols mpls interface lo0.0
set protocols rsvp interface ge-0/0/0.0
set protocols rsvp interface lo0.0

# Task 4: RSVP LSP
set protocols mpls label-switched-path LSP-R1-to-R4 to 4.4.4.4
commit
```

## R4

```bash
conf t
set interfaces ge-0/0/0 unit 0 family inet address 10.3.4.4/24
set interfaces ge-0/0/0 unit 0 family mpls
set interfaces lo0 unit 0 family inet address 4.4.4.4/32

set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set protocols ospf area 0.0.0.0 interface lo0.0 passive
set protocols ospf traffic-engineering

set protocols mpls interface ge-0/0/0.0
set protocols mpls interface lo0.0
set protocols rsvp interface ge-0/0/0.0
set protocols rsvp interface lo0.0

set protocols mpls label-switched-path LSP-R4-to-R1 to 1.1.1.1
commit
```