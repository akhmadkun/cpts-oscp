
# Source

https://arista.my.site.com/AristaCommunity/s/article/vxlan-routing-with-mlag#Comm_Kna_ka08C0000008TyeQAE_78

# Concept Behind
### **Ringkasan Artikel: VXLAN Routing dengan MLAG**

Artikel dari dokumentasi Arista ini membahas konsep, cara operasi, dan panduan konfigurasi untuk menggabungkan dua teknologi jaringan: **VXLAN Routing** dan **MLAG (Multi-Chassis Link Aggregation)** pada switch Arista.

Poin-poin utama dalam artikel:

1. **MLAG (Redundansi Active-Active):** Teknologi yang memungkinkan dua switch fisik Arista beroperasi dan terlihat sebagai satu switch logis. Ini memberikan jalur koneksi yang tahan gangguan dan mendistribusikan beban lalu lintas jaringan secara optimal tanpa risiko _looping_ (sehingga tidak wajib menggunakan Spanning Tree).
    
2. **VXLAN Overlay:** VXLAN adalah protokol standar yang membungkus (enkapsulasi) paket data Layer 2 (MAC address) ke dalam paket Layer 3 (IP). Ini memungkinkan pembuatan jaringan lokal yang membentang luas melewati infrastruktur IP modern (_leaf-spine architecture_).
    
3. **Kombinasi MLAG & VXLAN (Logical VTEP):** Ketika MLAG digabungkan dengan VXLAN, kedua switch MLAG dikonfigurasi menggunakan satu alamat IP _Virtual Tunnel Interface (VTI)_ yang sama. Keduanya bertindak sebagai satu "Logical VTEP (VXLAN Tunnel Endpoint)".
    
4. **VXLAN Routing:** Sementara VXLAN biasa hanya menyambungkan perangkat di _subnet_ yang sama (Layer 2), **VXLAN Routing** memungkinkan paket dikirim dan dirutekan (_routed_) antar _subnet_ IP yang berbeda di dalam terowongan VXLAN tersebut.
    
5. **Direct Routing dengan Anycast IP:** Artikel ini menggunakan model _Direct Routing_, di mana proses perpindahan antar-_subnet_ dilakukan langsung di switch pertama (first-hop) tempat server terhubung. Arista menggunakan fitur `ip address virtual`, sehingga seluruh switch di jaringan membagikan satu IP Gateway dan MAC Address yang sama. Fitur tambahan **Virtual VTEP (vVTEP)** digunakan untuk memastikan sistem tidak kelebihan beban saat menjawab permintaan identitas alamat (ARP request).
    
6. **Panduan Konfigurasi:** Artikel memberikan langkah teknis bertahap, mulai dari membuat _port-channel_ MLAG, mengatur IP Anycast, memetakan VLAN ke VNI (VXLAN Network Identifier), hingga mengiklankan rute melalui protokol BGP.
    

---

### **Penjelasan Sederhana: Bagaimana Cara Kerjanya?**

Agar lebih mudah dipahami, mari gunakan analogi **sistem pengiriman surat di dalam sebuah kawasan perkantoran besar (Data Center).**

**1. MLAG = Pintu Kembar yang Selalu Terbuka** Bayangkan sebuah ruangan kantor (Server) memiliki dua pintu keluar yang dijaga oleh dua resepsionis berbeda (2 buah Switch Arista). Dengan MLAG, kedua resepsionis ini bekerja sama dan menyamar menjadi _satu resepsionis gabungan_. Jika salah satu pintu macet atau resepsionisnya sakit, pintu satunya tetap beroperasi penuh. Server tidak akan pernah menyadari adanya masalah dan tidak pernah terputus.

**2. VXLAN = Terowongan Amplop Rahasia** Komputer di Gedung A ingin mengirim data ke Komputer di Gedung B yang berada di departemen yang sama. Daripada harus melewati jalan raya umum yang rumit, VXLAN membuatkan "terowongan rahasia". Resepsionis (VTEP) akan memasukkan surat tersebut ke dalam amplop khusus (enkapsulasi IP), mengirimkannya lewat jalur cepat, dan resepsionis di Gedung B akan membuka amplopnya untuk diberikan langsung ke tujuan. Komputer merasa mereka berada di satu ruangan yang sama.

**3. VXLAN Routing = Resepsionis yang Bisa Menerjemahkan Lintas Departemen** Lalu, bagaimana jika Komputer A (Tim HR) ingin mengirim surat ke Komputer C (Tim IT) yang _berbeda_ departemen (_beda subnet_)? Di sinilah fungsi Routing. Resepsionis tidak hanya membungkus surat ke dalam amplop, tapi ia cukup pintar untuk melihat tujuan akhirnya, mencarikan rute lintas departemen, dan langsung mengubah jalurnya saat itu juga sebelum mengirimkannya lewat terowongan VXLAN.

**4. Anycast IP (Direct Routing) = Alamat Customer Service Universal** Biasanya, jika Anda pindah ke gedung lain, Anda harus mencari alamat _Default Gateway_ (atau mesin sortir surat) yang baru. Dengan fitur **Anycast IP**, _semua resepsionis di seluruh kawasan perkantoran memiliki alamat IP Gateway yang sama persis_. Jadi, di mana pun sebuah server dicolokkan, ia selalu merasa terhubung langsung ke "Pusat Bantuan" yang tepat. Switch pertama yang menerima data dari server akan langsung mengeksekusi rutenya (_Direct Routing_) saat itu juga, membuat lalu lintas jaringan menjadi sangat cepat, efisien, dan tidak perlu bolak-balik ke router pusat.

**Kesimpulan:** Dengan menggabungkan MLAG dan VXLAN Routing, Data Center memiliki jaringan yang **tahan banting** (server terhubung ke dua switch sekaligus) dan **sangat cerdas** (setiap switch berfungsi sebagai router yang bisa mengirim data langsung ke tujuan akhir secara efisien melintasi jaringan besar).
# Yaml

```yaml
name: vxlan-mlag
prefix: ""

mgmt:
  network: custom_mgmt
  ipv4-subnet: 172.100.100.0/24

topology:
  kinds:
    ceos:
      image: ceos:4.35.0F
  nodes:
    spine1: { kind: ceos }
    spine2: { kind: ceos }
    leaf11: { kind: ceos }
    leaf12: { kind: ceos }
    leaf21: { kind: ceos }
    leaf22: { kind: ceos }
    host1: { kind: ceos }
    host2: { kind: ceos }
    
  links:
    # MLAG Peer Links
    - endpoints: ["leaf11:eth1", "leaf12:eth1"]
    - endpoints: ["leaf11:eth2", "leaf12:eth2"]
    - endpoints: ["leaf21:eth1", "leaf22:eth1"]
    - endpoints: ["leaf21:eth2", "leaf22:eth2"]
    
    # Underlay Spine-Leaf
    - endpoints: ["leaf11:eth3", "spine1:eth1"]
    - endpoints: ["leaf11:eth4", "spine2:eth1"]
    - endpoints: ["leaf12:eth3", "spine1:eth2"]
    - endpoints: ["leaf12:eth4", "spine2:eth2"]
    - endpoints: ["leaf21:eth3", "spine1:eth3"]
    - endpoints: ["leaf21:eth4", "spine2:eth3"]
    - endpoints: ["leaf22:eth3", "spine1:eth4"]
    - endpoints: ["leaf22:eth4", "spine2:eth4"]
    
    # Hosts (Dual-Homed ke MLAG)
    - endpoints: ["host1:eth1", "leaf11:eth5"]
    - endpoints: ["host1:eth2", "leaf12:eth5"]
    - endpoints: ["host2:eth1", "leaf21:eth5"]
    - endpoints: ["host2:eth2", "leaf22:eth5"]
```


# Task List

#### Phase 1: Preparation & Powering Up

- [ ] Open your terminal and navigate to the folder containing the `vxlan-mlag.clab.yml` file.
    
- [ ] Run the command `sudo clab deploy -t vxlan-mlag.clab.yml` to spin up all the virtual routers and switches.
    
- [ ] Verify that all 8 containers (2 Spines, 4 Leafs, 2 Hosts) are in a `running` state.
    
- [ ] Access each switch's CLI by typing `docker exec -it clab-vxlan-mlag-<node_name> Cli` (default login is `admin`).
    

#### Phase 2: Building the "Highway" (Underlay IP & BGP)

_Goal: Ensure all Leaf switches can communicate with each other through the Spine switches._

- [x] **On all Spines and Leafs:** Configure IP addresses on the physical interfaces connecting them (the uplinks and downlinks).
    
- [x] **On all Spines and Leafs:** Create a `Loopback0` interface. Think of this as the main ID card for each switch.
    
- [x] **On all Spines and Leafs:** Enable BGP routing. Advertise your connected networks so the Spines and Leafs know how to reach each other.
    
- [ ] **How to verify:** From Leaf11, try to `ping` Leaf21's Loopback0 IP. If it replies, your highway is ready!
    

#### Phase 3: Creating the "Twin Doors" (MLAG)

_Goal: Combine 2 physical Leaf switches in the same rack so they appear as 1 logical switch to the servers below them. This provides redundancy._

- [x] **On Leaf11 & Leaf12 (Rack 1):** Create VLAN 4094 and assign an IP address. This is the dedicated "heartbeat" link so the switches know their partner is alive.
    
- [x] **On Leaf11 & Leaf12:** Enable `mlag configuration` and point it to the partner's heartbeat IP.
    
- [x] **How to verify:** Type `show mlag`. Make sure the status shows **Active/Active** and the peer link is **Up**.
    
- [x] Repeat these exact steps for Leaf21 & Leaf22 in Rack 2.
    

#### Phase 4: Tunnels & The Anycast Gateway (VXLAN)

_Goal: Wrap L2 packets inside L3 packets (VXLAN encapsulation) and create the exact same IP Gateway on all Leaf switches so the hosts always have a local exit point._

- [ ] **On all Leafs:** Create VLAN 10 and VLAN 20.
    
- [ ] **On all Leafs:** Configure the VLAN 10 & 20 interfaces using the `ip address virtual` command. Set them to `10.10.10.254` and `10.10.20.254`.
    
- [ ] **On all Leafs:** Set the `virtual-router mac-address` to `00:aa:aa:aa:aa:aa` (This MUST be identical across all leaf switches!).
    
- [ ] **On all Leafs:** Create `Loopback1`. Add the **Primary IP** (for the data tunnel) and the **Secondary IP** (to handle ARP broadcasts). _Important: Leafs in the same rack (e.g., Leaf11 & Leaf12) must use the EXACT same IP addresses for Loopback1._
    
- [ ] **On all Leafs:** Enter `interface Vxlan1`, set the source to Loopback1, then map VLAN 10 to VNI 1010, and VLAN 20 to VNI 1020.
    
- [ ] Don't forget to configure the `flood vtep` pointing to the remote rack's Loopback1 IP.
    
#### Phase 4.5: Advertising the Tunnel IPs (BGP Underlay)

_Goal: Tell the rest of the network (via the Spines) where your new VXLAN tunnels are located._

- [ ] **On all Leafs:** Go back into your BGP configuration (`router bgp <ASN>`).
    
- [ ] **On all Leafs:** Advertise the Loopback1 IPs (both the Primary data IP and the Secondary virtual IP) using the `network` command. _(Example: `network 2.2.2.1/32` and `network 2.2.2.4/32`)._
    
- [ ] **How to verify:** Go to Spine1 and type `show ip route`. You must see the `/32` Loopback1 addresses from all the Leaf switches in the routing table. If they are missing, your tunnels will fail!

#### Phase 5: Connecting the Hosts & Final Verification

_Goal: Connect the servers to the switches and test the end-to-end connection._

- [ ] **On Leaf11 & Leaf12:** Configure the ports facing Host 1 as a Port-Channel (using LACP) and assign them to VLAN 10.
    
- [ ] **On Host 1:** Bundle its ports into a Port-Channel, assign the IP `10.10.10.1/24`, and set its default route/gateway to `10.10.10.254`.
    
- [ ] Repeat these steps for Host 2 in Rack 2 (use VLAN 20, IP `10.10.20.1/24`, Gateway `10.10.20.254`).
    
- [ ] **The Final Exam:** Go to Host 1 and type `ping 10.10.20.1`. If you get a reply, congratulations! You have successfully built a VXLAN routed network!
# Leaf 11

## MLAG

```bash
! 1. Buat VLAN khusus untuk sinkronisasi MLAG (Control Plane)
vlan 4094
   trunk group MLAG
!
! 2. Gabungkan interface antar-leaf menjadi Port-Channel untuk Peer Link
interface Port-Channel1000
   switchport mode trunk
   switchport trunk group MLAG
!
interface Ethernet1-2
   channel-group 1000 mode active
!
! 3. Beri IP untuk heartbeat dan sinkronisasi MAC antar MLAG Peer
interface Vlan4094
   ip address 10.0.0.1/30
!
! 4. Aktifkan MLAG Domain
mlag configuration
   domain-id RACK1
   local-interface Vlan4094
   peer-address 10.0.0.2
   peer-link Port-Channel1000  
```

## VxLAN

```bash
! 1. Buat VLAN untuk Tenant (Overlay)
vlan 10,20
!
! 2. Definisikan Virtual Router MAC (Sama di SEMUA Leaf di semua rak)
ip virtual-router mac-address 00:aa:aa:aa:aa:aa
!
! 3. Konfigurasi Anycast IP Gateway (Direct Routing)
! Menggunakan 'ip address virtual' agar hemat IP, switch akan me-route langsung di first-hop.
interface Vlan10
   ip address virtual 10.10.10.254/24
interface Vlan20
   ip address virtual 10.10.20.254/24
!
! 4. Konfigurasi Loopback untuk VTEP
interface Loopback1
   ! IP VTEP Logis (Sama persis antara Leaf11 dan Leaf12)
   ip address 2.2.2.1/32
   ! Virtual VTEP (Sama persis antara Leaf11 dan Leaf12), dipakai untuk merespon ARP 
   ip address 2.2.2.4/32 secondary
!
! 5. Konfigurasi VXLAN Interface
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   ! Mapping VLAN ke VNI
   vxlan vlan 10 vni 1010
   vxlan vlan 20 vni 1020
   ! Head-End Replication (HER) statis ke VTEP Rak 2 (Sesuai panduan artikel)
   vxlan vlan 10-20 flood vtep 2.2.2.2
```

## Tuning MAC

```bash
! Set ARP timeout lebih cepat dari MAC aging-time untuk memaksa refresh
mac address-table aging-time 1800
!
interface Vlan10
   arp timeout 1500
interface Vlan20
   arp timeout 1500
```

## Host

```bash
interface Port-Channel10
   switchport access vlan 10
   mlag 10
!
interface Ethernet5
   channel-group 10 mode active
```

# Leaf 21

## MLAG

```bash
! 1. Buat VLAN khusus untuk sinkronisasi MLAG
vlan 4094
   trunk group MLAG
!
! 2. Gabungkan interface antar-leaf menjadi Port-Channel
interface Port-Channel1000
   switchport mode trunk
   switchport trunk group MLAG
!
interface Ethernet1-2
   channel-group 1000 mode active
!
! 3. Beri IP untuk heartbeat dan sinkronisasi MAC (Leaf21 pakai .5, Leaf22 pakai .6)
interface Vlan4094
   ip address 10.0.0.5/30
!
! 4. Aktifkan MLAG Domain untuk Rak 2
mlag configuration
   domain-id RACK2
   local-interface Vlan4094
   peer-address 10.0.0.6
   peer-link Port-Channel1000
```

## VxLAN

```bash
! 1. Buat VLAN untuk Tenant (Overlay)
vlan 10,20
!
! 2. Definisikan Virtual Router MAC (WAJIB SAMA dengan Leaf di Rak 1)
ip virtual-router mac-address 00:aa:aa:aa:aa:aa
!
! 3. Konfigurasi Anycast IP Gateway (WAJIB SAMA dengan Rak 1)
! Karena konsepnya distributed, host di mana pun gateway-nya tetap IP ini.
interface Vlan10
   ip address virtual 10.10.10.254/24
interface Vlan20
   ip address virtual 10.10.20.254/24
!
! 4. Konfigurasi Loopback untuk VTEP Rak 2
interface Loopback1
   ! IP VTEP Logis Rak 2 (Sama antara Leaf21 dan Leaf22)
   ip address 2.2.2.2/32
   ! Virtual VTEP Rak 2 (Sama antara Leaf21 dan Leaf22), dipakai untuk merespon ARP
   ip address 2.2.2.5/32 secondary
!
! 5. Konfigurasi VXLAN Interface
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   ! Mapping VLAN ke VNI
   vxlan vlan 10 vni 1010
   vxlan vlan 20 vni 1020
   ! Head-End Replication (HER) statis MENUNJUK ke VTEP Rak 1 (2.2.2.1)
   vxlan vlan 10-20 flood vtep 2.2.2.1
```

## Tuning MAC

```bash
! Set ARP timeout lebih cepat dari MAC aging-time
mac address-table aging-time 1800
!
interface Vlan10
   arp timeout 1500
interface Vlan20
   arp timeout 1500
```

## Host

```bash
! Mengarah ke Host2
interface Port-Channel20
   switchport access vlan 20
   mlag 20
!
interface Ethernet5
   channel-group 20 mode active
```