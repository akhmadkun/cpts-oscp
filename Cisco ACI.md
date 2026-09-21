# Cisco ACI Customer Introduction & Operational Overview

## Audience

Tim Network, Data Center, Infrastructure, Security, dan Operation yang akan terlibat dalam implementasi dan operasional Cisco ACI.

## Duration

± 2 Hours

## Main Objectives

Setelah sesi ini, peserta diharapkan memahami:

- Apa sebenarnya Cisco ACI dan masalah apa yang diselesaikannya.
    
- Komponen utama ACI Fabric dan fungsi masing-masing.
    
- Bagaimana endpoint berkomunikasi di dalam ACI.
    
- Konsep Tenant, VRF, Bridge Domain, Application Profile, EPG, dan Contract.
    
- Perbedaan paradigma jaringan tradisional dengan ACI.
    
- Bagaimana ACI terhubung ke jaringan di luar fabric.
    
- Bagaimana server physical dan virtual terhubung ke ACI.
    
- Dasar operasional dan troubleshooting ACI.
    
- Hal-hal penting yang perlu dipersiapkan sebelum implementasi dan migrasi production.
    

---

# 1. Opening and Context

**Estimated time: 5–10 minutes**

## 1.1 Why Are We Here?

Cisco ACI yang sudah dibeli bukan hanya sekumpulan Nexus switch.

ACI adalah sebuah **Data Center Networking System** yang menggabungkan:

- Switching infrastructure.
    
- Centralized policy.
    
- Centralized management.
    
- Automation.
    
- Endpoint awareness.
    
- Integration dengan virtualization dan orchestration platform.
    
- Telemetry dan operational visibility.
    

Pesan utama:

> Dalam ACI kita tidak lagi hanya mengkonfigurasi VLAN dan interface.  
> Kita mendefinisikan bagaimana sebuah application atau group of endpoints boleh berkomunikasi.

---

## 1.2 Traditional Data Center Networking vs ACI

### Traditional Network

Biasanya administrator berpikir dalam bentuk:

```text
Switch
  ↓
Interface
  ↓
VLAN
  ↓
SVI
  ↓
ACL
  ↓
Routing
```

Konfigurasi tersebar pada banyak perangkat.

Contoh:

```text
Leaf/Access Switch
Core Switch
Firewall
Load Balancer
Hypervisor vSwitch
```

Jika aplikasi baru membutuhkan konektivitas, administrator perlu memastikan konfigurasi konsisten pada banyak titik.

---

### Cisco ACI

ACI menggunakan pendekatan:

```text
Application Requirement
        ↓
Endpoint Group
        ↓
Policy
        ↓
ACI Fabric
```

Kita mendefinisikan:

- Endpoint berada dalam group apa.
    
- Endpoint menggunakan subnet apa.
    
- Group mana boleh berbicara dengan group lain.
    
- Service apa yang diizinkan.
    

Fabric kemudian menerapkan policy tersebut.

---

# 2. Cisco ACI Architecture

**Estimated time: 15 minutes**

## 2.1 ACI Fabric Components

ACI terdiri dari tiga komponen utama:

```text
          APIC Cluster
              |
      -------------------
      |                 |
    Spine             Spine
     / \               / \
    /   \             /   \
 Leaf  Leaf         Leaf  Leaf
```

Komponen utama:

- APIC
    
- Spine Switch
    
- Leaf Switch
    

---

# 3. APIC — Application Policy Infrastructure Controller

## 3.1 What Is APIC?

APIC adalah centralized controller untuk Cisco ACI.

Fungsi utama:

- Policy management.
    
- Fabric configuration.
    
- Fabric discovery.
    
- Automation API.
    
- Health monitoring.
    
- Fault management.
    
- Integration dengan VMware, OpenStack, Kubernetes, dan tools automation lainnya.
    

---

## 3.2 Important APIC Concept

APIC **bukan bagian dari data forwarding path**.

Jika seluruh APIC mengalami failure:

```text
Endpoint A
   |
 Leaf
   |
 Spine
   |
 Leaf
   |
Endpoint B
```

traffic tetap berjalan berdasarkan policy yang sudah terprogram pada switch.

Namun administrator tidak dapat melakukan perubahan policy sampai APIC kembali tersedia.

---

## 3.3 APIC Cluster

Production deployment biasanya menggunakan minimal:

```text
3 APIC Controllers
```

Tujuan:

- High availability.
    
- Database replication.
    
- Controller redundancy.
    

---

# 4. Spine and Leaf Architecture

## 4.1 Leaf Switch

Leaf merupakan tempat endpoint atau external network terhubung.

Contoh:

```text
Server
Firewall
Router
Load Balancer
VMware ESXi
Storage
```

semuanya biasanya terhubung ke leaf.

Leaf mempunyai fungsi:

- Endpoint attachment.
    
- Policy enforcement.
    
- Layer 2 forwarding.
    
- Layer 3 routing.
    
- VXLAN encapsulation.
    

---

## 4.2 Spine Switch

Spine menyediakan connectivity antar leaf.

Tidak ada endpoint yang langsung terhubung ke spine.

Arsitektur:

```text
        Spine1       Spine2
       /   |   \    /   |   \
      /    |    \  /    |    \
    Leaf1 Leaf2 Leaf3 Leaf4
```

Setiap leaf terhubung ke setiap spine.

---

## 4.3 Why Leaf-Spine?

Keuntungan:

- Predictable latency.
    
- Horizontal scalability.
    
- Equal-cost multipath.
    
- Tidak bergantung pada spanning tree untuk fabric forwarding.
    
- Semua leaf mempunyai jarak yang relatif sama.
    

---

# 5. ACI Underlay and Overlay

**Estimated time: 10 minutes**

ACI sebenarnya mempunyai dua jaringan.

## 5.1 Underlay Network

Underlay adalah IP fabric internal antara leaf dan spine.

Secara konseptual:

```text
Leaf
 |
IP Network
 |
Spine
 |
IP Network
 |
Leaf
```

Underlay berfungsi membawa VXLAN packet.

---

## 5.2 Overlay Network

Overlay menggunakan VXLAN.

Endpoint traffic dibungkus menjadi VXLAN ketika melewati fabric.

Contoh:

```text
Server A
   |
Leaf1
   |
VXLAN
   |
Spine
   |
VXLAN
   |
Leaf2
   |
Server B
```

---

## 5.3 Important Message

Administrator biasanya tidak perlu mengkonfigurasi VXLAN tunnel satu per satu.

ACI secara otomatis membangun forwarding infrastructure berdasarkan policy.

---

# 6. Endpoint Concept

**Estimated time: 10 minutes**

Endpoint adalah device atau workload yang terhubung ke ACI.

Contoh:

```text
Physical Server
Virtual Machine
Container
Firewall
Load Balancer
Router
```

ACI mempelajari endpoint berdasarkan informasi seperti:

```text
MAC Address
IP Address
Attachment Location
EPG Membership
```

---

## 6.1 Endpoint Database

Leaf mengetahui endpoint lokal.

Fabric juga memiliki distributed endpoint information.

Contoh:

```text
MAC: 0050.56AA.BBCC
IP : 10.10.10.20
EPG: WEB
Leaf: LEAF101
Port: eth1/10
```

Informasi tersebut sangat penting ketika melakukan troubleshooting.

---

# 7. ACI Logical Policy Model

**Estimated time: 25 minutes**

Ini adalah bagian paling penting dari sesi.

Hierarchy sederhana:

```text
Tenant
 └── VRF
      └── Bridge Domain
           └── Subnet

Tenant
 └── Application Profile
      └── EPG
```

Hubungan communication:

```text
EPG
 |
Contract
 |
EPG
```

---

# 8. Tenant

Tenant adalah logical container utama dalam ACI.

Contoh:

```text
Tenant-PRODUCTION
Tenant-DEVELOPMENT
Tenant-DMZ
```

Tenant dapat digunakan untuk:

- Memisahkan environment.
    
- Memisahkan business unit.
    
- Memisahkan customer.
    
- Memisahkan security domain.
    

---

## 8.1 Built-In Tenants

ACI mempunyai beberapa system tenant seperti:

```text
common
infra
mgmt
```

### common

Dapat digunakan untuk resource yang akan dipakai bersama beberapa tenant.

Contoh:

```text
Shared L3Out
Shared Services
Common Contracts
```

---

# 9. VRF

VRF menyediakan Layer 3 routing domain.

Contoh:

```text
Tenant PROD

VRF PROD
```

VRF menentukan:

```text
Routing table
```

Dua endpoint pada VRF berbeda tidak dapat berkomunikasi secara langsung tanpa desain khusus.

---

# 10. Bridge Domain

Bridge Domain atau BD merupakan Layer 2 forwarding domain.

Analogi sederhananya:

```text
Traditional Network

VLAN + SVI

ACI

Bridge Domain + Subnet
```

Tetapi BD tidak sama persis dengan VLAN.

---

## 10.1 BD Responsibilities

BD menentukan beberapa hal seperti:

- Layer 2 forwarding.
    
- Layer 3 gateway.
    
- ARP behavior.
    
- Unknown unicast behavior.
    
- Routing behavior.
    

---

# 11. ACI Subnet and Distributed Gateway

Pada ACI, gateway biasanya didefinisikan pada Bridge Domain.

Contoh:

```text
BD-WEB
Subnet:

10.10.10.1/24
```

ACI menggunakan konsep **Distributed Anycast Gateway**.

Artinya gateway yang sama tersedia pada seluruh leaf yang membutuhkan subnet tersebut.

---

## 11.1 Traditional Gateway

```text
Server
 |
Access Switch
 |
Distribution Switch
 |
SVI Gateway
```

---

## 11.2 ACI Distributed Gateway

```text
Server A              Server B
   |                     |
 Leaf1                 Leaf2
GW 10.10.10.1        GW 10.10.10.1
```

Gateway secara logical berada dekat dengan endpoint.

---

# 12. Application Profile

Application Profile merupakan container untuk mendefinisikan aplikasi.

Contoh aplikasi tiga tier:

```text
APPLICATION-PROFILE
   |
   +-- WEB-EPG
   |
   +-- APP-EPG
   |
   +-- DB-EPG
```

---

# 13. Endpoint Group — EPG

EPG adalah sekumpulan endpoint yang memiliki policy connectivity yang sama.

Contoh:

```text
WEB-EPG
APP-EPG
DB-EPG
```

Endpoint dapat dimasukkan ke EPG berdasarkan:

- Physical interface.
    
- VLAN encapsulation.
    
- VMware port group.
    
- VMM integration.
    
- Static port binding.
    

---

# 14. VLAN in ACI

VLAN tetap digunakan di ACI, terutama pada edge antara endpoint dan leaf.

Contoh:

```text
VMware ESXi
   |
VLAN 100
   |
Leaf
   |
EPG-WEB
```

Namun VLAN bukan lagi core forwarding mechanism antar leaf.

Di dalam fabric:

```text
VXLAN
```

yang digunakan.

---

# 15. Contracts

**Estimated time: 15 minutes**

Secara default:

```text
EPG A
   X
EPG B
```

EPG yang berbeda tidak otomatis boleh berkomunikasi.

Communication dikontrol menggunakan:

```text
Contract
```

---

## 15.1 Provider and Consumer

Contoh:

```text
WEB EPG
Consumer
   |
HTTP Contract
   |
Provider
APP EPG
```

Meaning:

WEB boleh mengakses APP menggunakan service yang didefinisikan dalam contract.

---

## 15.2 Filters

Contract menggunakan filter.

Contoh:

```text
TCP
Destination Port 443
```

atau:

```text
TCP 80
TCP 443
```

---

## 15.3 Three-Tier Application Example

```text
Internet
   |
Firewall
   |
WEB EPG
   |
HTTP/HTTPS Contract
   |
APP EPG
   |
Database Contract
   |
DB EPG
```

Policy dapat dibuat sesuai application flow.

---

# 16. ACI Policy Enforcement Model

ACI menggunakan model:

```text
White-list
```

Secara konseptual:

```text
Traffic between different EPGs
DENY by default

unless

Contract permits it
```

Ini membuat application communication lebih eksplisit.

---

# 17. Network-Centric vs Application-Centric Design

**Estimated time: 10 minutes**

Ada dua pendekatan umum untuk implementasi ACI.

---

## 17.1 Network-Centric Design

Biasanya digunakan pada fase migration.

Mapping:

```text
Existing VLAN
     |
     v
ACI EPG
```

Contoh:

```text
VLAN 10 → EPG VLAN10
VLAN 20 → EPG VLAN20
VLAN 30 → EPG VLAN30
```

Keuntungan:

- Migration lebih sederhana.
    
- Minimal perubahan pada existing application.
    
- Mudah dipahami oleh network team.
    

---

## 17.2 Application-Centric Design

EPG dibuat berdasarkan fungsi aplikasi.

Contoh:

```text
WEB
APP
DB
```

Keuntungan:

- Policy lebih granular.
    
- Lebih sesuai dengan konsep ACI.
    
- Lebih mudah menerapkan zero-trust segmentation.
    

Tetapi membutuhkan pemahaman application dependency yang baik.

---

# 18. External Connectivity

**Estimated time: 10 minutes**

ACI harus terhubung ke network di luar fabric.

Ada dua konsep penting:

```text
L2Out
L3Out
```

---

# 19. L3Out

L3Out digunakan untuk Layer 3 connectivity ke external network.

Contoh:

```text
ACI Fabric
   |
Border Leaf
   |
Router / Firewall
   |
Campus / WAN / Internet
```

Routing protocol yang umum:

```text
BGP
OSPF
Static Routing
```

---

## 19.1 Common L3Out Use Cases

- Internet connectivity.
    
- WAN connectivity.
    
- Legacy data center.
    
- Firewall connectivity.
    
- Campus network.
    
- MPLS network.
    

---

# 20. L2Out

L2Out digunakan untuk Layer 2 extension ke external network.

Contoh:

```text
ACI
 |
Leaf
 |
Layer2
 |
Legacy Switch
```

Biasanya digunakan saat migration atau kebutuhan bridging tertentu.

---

# 21. Border Leaf

Leaf yang digunakan untuk external Layer 3 connectivity sering disebut:

```text
Border Leaf
```

Border leaf tetap merupakan leaf biasa secara hardware, namun mempunyai fungsi external connectivity.

---

# 22. Service Integration

ACI dapat diintegrasikan dengan:

```text
Firewall
Load Balancer
IPS
Other Network Services
```

Contoh:

```text
EPG A
 |
Service Graph
 |
Firewall
 |
EPG B
```

Salah satu mekanisme yang sering digunakan:

```text
Policy Based Redirect
```

---

# 23. VMware Integration

**Estimated time: 10 minutes**

ACI dapat terintegrasi dengan VMware vCenter.

Konsep:

```text
APIC
 |
VMM Domain
 |
vCenter
 |
ESXi
 |
VM
```

ACI dapat membuat atau berasosiasi dengan port group pada virtual infrastructure.

---

## 23.1 Why VMM Integration?

ACI dapat mengetahui:

```text
VM identity
VM location
EPG membership
Hypervisor attachment
```

Jika VM berpindah ESXi host, policy tetap mengikuti workload.

---

# 24. Physical Domain

Physical Domain digunakan ketika endpoint terhubung langsung ke leaf.

Contoh:

```text
Bare Metal Server
      |
    Leaf
      |
Physical Domain
```

---

# 25. Domain Concept

Beberapa domain umum:

```text
Physical Domain

VMM Domain

External Routed Domain

External Bridged Domain
```

Domain membantu ACI mengetahui di mana suatu EPG dapat digunakan.

---

# 26. VLAN Pool

ACI memerlukan VLAN pool untuk menentukan range VLAN yang boleh digunakan pada suatu domain.

Contoh:

```text
VLAN Pool

100-199
```

Digunakan bersama:

```text
Domain
AEP
Interface Policy
```

---

# 27. Access Policy Overview

Ini adalah bagian yang biasanya terasa kompleks pada awal mempelajari ACI.

Hubungan sederhananya:

```text
Interface
   |
Interface Policy Group
   |
AEP
   |
Domain
   |
VLAN Pool
```

---

# 28. Interface Policy

Interface policy menentukan behavior port.

Contoh:

```text
Speed
CDP
LLDP
LACP
MCP
Storm Control
```

---

# 29. Interface Policy Group

Policy Group menggabungkan beberapa policy.

Contoh:

```text
ESXi-VPC-POLICY-GROUP
```

yang berisi:

```text
LACP Active
LLDP Enabled
CDP Enabled
```

---

# 30. AEP — Attachable Access Entity Profile

AEP menjadi penghubung antara:

```text
Interface Policy
```

dan:

```text
Domain
```

Secara konseptual:

```text
Interface
   |
Policy Group
   |
AEP
   |
Domain
   |
VLAN Pool
```

---

# 31. vPC in ACI

ACI mendukung Virtual Port Channel.

Contoh:

```text
        Server
       /      \
    Leaf1    Leaf2
       \      /
        vPC
```

Keuntungan:

- Link redundancy.
    
- Leaf redundancy.
    
- Active-active forwarding.
    

---

# 32. ACI Fabric Forwarding Example

**Estimated time: 10 minutes**

Misalkan:

```text
VM-A
IP 10.10.10.10
EPG WEB
Leaf101

VM-B
IP 10.20.20.20
EPG APP
Leaf102
```

Traffic flow:

```text
VM-A
 |
Leaf101
 |
Policy Check
 |
VXLAN Encapsulation
 |
Spine
 |
Leaf102
 |
VM-B
```

Leaf101 melakukan:

```text
Endpoint lookup
Routing
Policy enforcement
VXLAN encapsulation
```

---

# 33. ACI Troubleshooting Methodology

Ketika troubleshooting ACI, jangan langsung melihat VLAN.

Mulai dengan tiga pertanyaan:

```text
1. Endpoint ada di mana?
2. Endpoint berada dalam EPG apa?
3. Policy mengizinkan traffic atau tidak?
```

---

# 34. Endpoint Verification

Hal yang perlu diperiksa:

```text
MAC Address
IP Address
Leaf
Interface
EPG
VLAN
```

Contoh CLI:

```text
show endpoint
```

---

# 35. Fault and Health Score

APIC menyediakan:

```text
Health Score
Fault
Event
Audit Log
```

Contoh objek:

```text
Tenant Health
Application Health
EPG Health
Fabric Health
Node Health
Interface Health
```

---

# 36. Fault Severity

Fault biasanya dikategorikan:

```text
Critical
Major
Minor
Warning
Info
```

Administrator harus memahami root cause dan affected object.

---

# 37. Operational Tools

Beberapa tools penting:

```text
APIC GUI
APIC CLI
Leaf CLI
Spine CLI
API
Visore
MO Query
Fault Search
Endpoint Tracker
```

---

# 38. Managed Object Model

ACI menggunakan object-based configuration.

Contoh object:

```text
Tenant
VRF
Bridge Domain
EPG
Contract
Filter
L3Out
```

Semua object memiliki:

```text
Distinguished Name
```

Contoh:

```text
uni/tn-PROD/ap-WEB/epg-FRONTEND
```

---

# 39. Why the Object Model Matters

GUI bukan satu-satunya cara mengoperasikan ACI.

Karena semua configuration adalah object, ACI dapat dikelola melalui:

```text
GUI
REST API
Python
Terraform
Ansible
Automation Platform
```

---

# 40. Automation Opportunities

ACI sangat cocok untuk automation.

Contoh:

```text
Create Tenant

Create VRF

Create Bridge Domain

Create EPG

Create Contract

Create L3Out
```

dapat dilakukan melalui API.

---

# 41. Migration Considerations

**Estimated time: 10 minutes**

Sebelum migration ke ACI, customer harus mempunyai inventory yang jelas.

Minimal:

```text
Existing VLANs
Subnets
Default Gateways
Physical Servers
Virtual Servers
Firewall Dependencies
Load Balancer Dependencies
Routing
L2 Extension
Application Dependencies
```

---

# 42. Application Dependency Mapping

Salah satu pekerjaan terpenting sebelum segmentation:

```text
Who talks to whom?
```

Contoh:

```text
WEB → APP TCP 8443

APP → DB TCP 1521

DB → Backup TCP 443
```

Informasi ini akan digunakan untuk membuat contract.

---

# 43. Migration Strategy

Umumnya migration dilakukan secara bertahap.

Contoh:

```text
Phase 1
Build ACI Fabric

Phase 2
Connect ACI to Existing Network

Phase 3
Extend Selected VLANs

Phase 4
Move Endpoint

Phase 5
Move Gateway

Phase 6
Implement Contracts

Phase 7
Optimize Policy
```

---

# 44. Brownfield Migration

Pada brownfield environment:

```text
Existing Network
       |
      L2/L3
       |
    ACI Fabric
```

ACI dapat hidup berdampingan dengan existing network selama proses migration.

---

# 45. Common Migration Mistake

Kesalahan umum:

### Membuat segmentation terlalu agresif sejak awal.

Jika application dependency belum diketahui dengan baik:

```text
WEB
APP
DB
Middleware
Backup
Monitoring
Security Scanner
```

maka contract yang terlalu ketat dapat menyebabkan application outage.

Pendekatan yang lebih aman:

```text
Connectivity First
       ↓
Stabilize
       ↓
Observe Traffic
       ↓
Apply Segmentation
```

---

# 46. Operational Responsibilities

Setelah ACI production, perlu ada kejelasan ownership.

Contoh:

| Area                   | Possible Owner       |
| ---------------------- | -------------------- |
| Fabric Hardware        | Network Team         |
| Tenant Configuration   | Network / Cloud Team |
| Contracts              | Network + Security   |
| Application Dependency | Application Team     |
| VMware Integration     | Virtualization Team  |
| Firewall Integration   | Security Team        |
| Automation             | NetDevOps Team       |

ACI secara alami membutuhkan kolaborasi lintas tim.

---

# 47. Important Design Questions Before Implementation

Beberapa pertanyaan yang perlu dijawab:

### Fabric

- Berapa spine?
    
- Berapa leaf?
    
- Berapa leaf pair?
    
- Apakah membutuhkan border leaf khusus?
    
- Apakah membutuhkan service leaf?
    

### Connectivity

- Bagaimana ACI terhubung ke core?
    
- Apakah menggunakan BGP atau OSPF?
    
- Apakah gateway akan dipindahkan ke ACI?
    

### Virtualization

- Apakah menggunakan VMware?
    
- Apakah menggunakan VMM integration?
    
- Berapa vCenter?
    

### Security

- Di mana posisi firewall?
    
- Apakah east-west firewall diperlukan?
    
- Apakah akan menggunakan Service Graph / PBR?
    

### Migration

- Network-centric atau application-centric?
    
- Apakah L2 extension diperlukan?
    
- Bagaimana rollback strategy?
    

---

# 48. Common Misconceptions

## Misconception 1

> ACI adalah Nexus switch dengan GUI.

Tidak.

ACI adalah:

```text
Policy-based data center networking system
```

---

## Misconception 2

> ACI tidak menggunakan VLAN.

Salah.

VLAN tetap digunakan pada edge.

Namun transport antar leaf menggunakan:

```text
VXLAN
```

---

## Misconception 3

> APIC membawa traffic.

Tidak.

APIC adalah controller.

Traffic berjalan melalui:

```text
Leaf
Spine
Leaf
```

---

## Misconception 4

> Semua traffic antar EPG otomatis boleh lewat.

Tidak.

Secara default membutuhkan:

```text
Contract
```

---

# 49. Operational Mindset Shift

Engineer tradisional biasanya bertanya:

```text
VLAN berapa?
Port switch mana?
SVI ada di mana?
```

ACI engineer perlu menambahkan pertanyaan:

```text
Endpoint ada di EPG apa?

EPG menggunakan BD apa?

BD menggunakan VRF apa?

Contract mana yang mengizinkan traffic?

Endpoint dipelajari di leaf mana?
```

---

# 50. Recommended Troubleshooting Flow

Gunakan urutan:

```text
Application
     ↓
Endpoint
     ↓
EPG
     ↓
Bridge Domain
     ↓
VRF
     ↓
Contract
     ↓
Routing
     ↓
Fabric
```

Jangan langsung menyimpulkan masalah berada di fabric.

---

# 51. Example Troubleshooting Scenario

User melaporkan:

```text
WEB server tidak bisa connect ke DB.
```

Check:

### Step 1

Apakah WEB endpoint dipelajari?

```text
WEB
10.10.10.10
```

### Step 2

Apakah DB endpoint dipelajari?

```text
DB
10.30.30.10
```

### Step 3

EPG:

```text
WEB-EPG
DB-EPG
```

### Step 4

Apakah ada contract?

```text
WEB → DB
```

### Step 5

Apakah filter mengizinkan service database?

Contoh:

```text
TCP 1521
```

### Step 6

Jika policy benar, baru lanjutkan ke:

```text
Routing
L3Out
External firewall
Server firewall
```

---

# 52. Recommended Day-2 Operational Skills

Tim operasional sebaiknya menguasai:

### Basic

- Tenant navigation.
    
- EPG configuration.
    
- Contract configuration.
    
- Static port binding.
    
- Endpoint tracking.
    
- Fault analysis.
    

### Intermediate

- L3Out troubleshooting.
    
- vPC troubleshooting.
    
- VMM integration.
    
- Endpoint move.
    
- Contract troubleshooting.
    
- External connectivity.
    

### Advanced

- Service Graph.
    
- PBR.
    
- Multi-Pod.
    
- Multi-Site.
    
- Automation.
    
- API.
    
- Terraform / Ansible.
    
- Advanced telemetry.
    

---

# 53. Suggested Implementation Philosophy

Untuk customer yang baru menggunakan ACI:

```text
Start Simple
     ↓
Make Connectivity Stable
     ↓
Build Operational Familiarity
     ↓
Introduce Segmentation
     ↓
Introduce Automation
```

Jangan mencoba menggunakan seluruh fitur ACI pada hari pertama.

---

# 54. Example Initial Deployment Model

Deployment awal dapat menggunakan:

```text
Tenant PROD

VRF PROD

BD WEB
BD APP
BD DB

EPG WEB
EPG APP
EPG DB
```

dengan contract:

```text
WEB → APP

APP → DB
```

dan external connectivity:

```text
L3Out
   |
Firewall / Core
```

---

# 55. Example Full Architecture

```text
                         Internet / WAN
                               |
                           Firewall
                               |
                             L3Out
                               |
                        Border Leaf Pair
                           /       \
                          /         \
                      Spine1       Spine2
                      / | \         / | \
                     /  |  \       /  |  \
                  Leaf Leaf Leaf Leaf Leaf Leaf
                   |    |         |      |
                  ESXi Server    ESXi   Storage
                   |
               Virtual Machines
                   |
        -------------------------
        |          |            |
      WEB EPG    APP EPG      DB EPG
        |          |            |
        +--Contract--Contract----+
```

---

# 56. What the Customer Should Prepare Next

Sebelum implementation workshop berikutnya, siapkan:

## Network Information

- Existing topology.
    
- VLAN list.
    
- Subnet list.
    
- Default gateway.
    
- Routing information.
    
- Core connectivity.
    

## Server Information

- Physical server list.
    
- VMware host list.
    
- vCenter information.
    
- Server NIC configuration.
    

## Application Information

- Application inventory.
    
- Application dependency.
    
- Required ports.
    

## Security Information

- Firewall topology.
    
- Security zone.
    
- Existing ACL.
    
- North-south traffic.
    
- East-west traffic.
    

---

# 57. Suggested Next Workshops

Setelah sesi overview ini, training atau workshop berikutnya dapat dibagi menjadi:

### Workshop 1 — Fabric Operations

- Fabric discovery.
    
- Node management.
    
- Interface configuration.
    
- vPC.
    
- Fabric health.
    

### Workshop 2 — Tenant Networking

- Tenant.
    
- VRF.
    
- Bridge Domain.
    
- EPG.
    
- Contract.
    

### Workshop 3 — External Connectivity

- L3Out.
    
- BGP.
    
- OSPF.
    
- Static routing.
    

### Workshop 4 — VMware Integration

- VMM Domain.
    
- VMware vCenter.
    
- Dynamic EPG assignment.
    

### Workshop 5 — Security Integration

- Firewall integration.
    
- Service Graph.
    
- Policy Based Redirect.
    

### Workshop 6 — Troubleshooting

- Endpoint troubleshooting.
    
- Contract troubleshooting.
    
- L3Out troubleshooting.
    
- Fault analysis.
    

---

# 58. Key Takeaways

Jika hanya mengingat beberapa hal dari sesi ini, ingat lima konsep berikut:

### 1. ACI is Policy-Based Networking

Konfigurasi dibuat berdasarkan policy dan application requirement.

### 2. Leaf Is the Main Intelligence Point

Leaf melakukan:

```text
Endpoint learning
Routing
Policy enforcement
VXLAN
```

### 3. Endpoint Group Is Fundamental

Endpoint dengan policy yang sama ditempatkan dalam:

```text
EPG
```

### 4. Contracts Control Communication

Traffic antar EPG dikontrol oleh:

```text
Contract
```

### 5. ACI Is More Than Switching

ACI mencakup:

```text
Networking
Policy
Automation
Security Integration
Virtualization Integration
Telemetry
Operations
```

---

# 59. Final Mental Model

Model paling sederhana untuk memahami ACI:

```text
          APPLICATION
               |
               v
          +---------+
          |   EPG   |
          +---------+
               |
            Contract
               |
          +---------+
          |   EPG   |
          +---------+
               |
         Bridge Domain
               |
              VRF
               |
          ACI Fabric
               |
          External Network
```

Dan secara physical:

```text
             APIC
               |
       -----------------
       |               |
     Spine           Spine
      / \             / \
     /   \           /   \
   Leaf   Leaf     Leaf   Leaf
    |      |        |      |
 Server   ESXi    Router  Firewall
```

---

# 60. Closing

Cisco ACI mengubah cara kita melihat data center network.

Dari:

```text
Port
VLAN
SVI
ACL
```

menjadi:

```text
Endpoint
Application
Policy
Intent
```

Namun konsep dasar networking tetap sangat penting:

```text
Ethernet
VLAN
ARP
Routing
BGP
OSPF
VXLAN
TCP/IP
```

ACI tidak menggantikan fundamental networking.

ACI menyediakan **framework untuk mengelola networking tersebut secara centralized, policy-driven, dan scalable**.