# Topology

```
                    Management Network
                   172.20.20.0/24
   ───────────────────────────────────────────────
        ┌──────────────────┐        ┌──────────────────┐
        │      leaf1       │        │      leaf2       │
        │     (cEOS)       │        │     (cEOS)       │
        │                  │        │                  │
        │ mgmt: .11        │        │ mgmt: .12        │
        │                  │        │                  │
        │ eth1 ────────────┼────────┼────────── eth1   │
        │ eth2 ────────────┼────────┼────────── eth2   │
        │   PEER-LINK      │        │   PEER-LINK      │
        │   (Po1)          │        │   (Po1)          │
        │                  │        │                  │
        │ eth3 ────────────┼────────┼────────── eth3   │
        │   KEEPALIVE      │        │   KEEPALIVE      │
        │                  │        │                  │
        │ eth4             │        │ eth4             │
        └─────┬────────────┘        └────────────┬─────┘
              │                                  │
              │                                  │
              │        LACP (802.3ad)            │
              │                                  │
        ┌─────┴──────────────────────────────────┴──┐
        │   eth1                              eth2  │
        │        client   bond0                     │
        │      (Linux)   (eth1 + eth2)              │
        │                                           │
        │ mgmt: 172.20.20.13                        │
        │ IP : 192.168.10.100/24                    │
        │ GW : 192.168.10.1                         │
        └───────────────────────────────────────────┘

```

# leaf 1

```
enable
configure terminal
hostname Leaf1

! 1. Buat VLAN untuk Testing & MLAG Peering
vlan 10
   name CLIENT_DATA
vlan 4094
   name MLAG_PEER
   trunk group MLAGPEER

! 2. Konfigurasi Peer Link (Membawa VLAN 4094)
interface Ethernet1
   channel-group 1 mode active
interface Ethernet2
   channel-group 1 mode active
!
interface Port-Channel1
   description MLAG_PEER_LINK
   switchport mode trunk
   switchport trunk group MLAGPEER
   ! Best practice: Matikan spanning tree di peer link jika config benar
   spanning-tree link-type point-to-point

! 3. Konfigurasi SVI untuk MLAG Peering
interface Vlan4094
   description MLAG_PEERING
   ip address 10.1.1.1/30
   no autostate

! 4. Konfigurasi Keepalive Link (L3 terpisah)
interface Ethernet3
   description MLAG_KEEPALIVE
   no switchport
   ip address 10.2.2.1/30

! 5. Konfigurasi Global MLAG
mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.1.1.2
   peer-link Port-Channel1
   ! IP Peer untuk heartbeat (via Eth3)
   peer-address heartbeat 10.2.2.2 

! 6. Konfigurasi Member Port ke Host (MLAG Interface)
interface Ethernet4
   channel-group 10 mode active
!
interface Port-Channel10
   description HOST_UPLINK
   switchport mode access
   switchport access vlan 10
   ! "mlag 10" adalah ID yang menyatukan Po10 di Leaf1 dan Po10 di Leaf2
   mlag 10

! 7. Gateway untuk Host (VARP / Anycast Gateway)
interface Vlan10
   ip address 192.168.10.2/24
   ! Virtual Router IP (Shared Gateway)
   ip virtual-router address 192.168.10.1
```

# leaf2

```
enable
configure terminal
hostname Leaf2

! 1. VLAN
vlan 10
   name CLIENT_DATA
vlan 4094
   name MLAG_PEER
   trunk group MLAGPEER

! 2. Peer Link
interface Ethernet1
   channel-group 1 mode active
interface Ethernet2
   channel-group 1 mode active
!
interface Port-Channel1
   description MLAG_PEER_LINK
   switchport mode trunk
   switchport trunk group MLAGPEER
   spanning-tree link-type point-to-point

! 3. SVI Peering
interface Vlan4094
   description MLAG_PEERING
   ip address 10.1.1.2/30
   no autostate

! 4. Keepalive Link
interface Ethernet3
   description MLAG_KEEPALIVE
   no switchport
   ip address 10.2.2.2/30

! 5. Global MLAG (Perhatikan IP Peer dibalik)
mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.1.1.1
   peer-link Port-Channel1
   peer-address heartbeat 10.2.2.1

! 6. Member Port
interface Ethernet4
   channel-group 10 mode active
!
interface Port-Channel10
   description HOST_UPLINK
   switchport mode access
   switchport access vlan 10
   ! ID harus SAMA dengan Leaf1
   mlag 10

! 7. Gateway (VARP)
interface Vlan10
   ip address 192.168.10.3/24
   ! Virtual Router IP (SAMA PERSIS dengan Leaf1)
   ip virtual-router address 192.168.10.1
```

# linux lacp rate fast

```yml
client:
      kind: linux
      mgmt_ipv4: 172.20.20.13
      exec:
        - ip link set eth1 down
        - ip link set eth2 down
        
        # PERUBAHAN ADA DI SINI:
        # miimon 100    : Cek fisik link setiap 100ms
        # lacp_rate fast: Minta kirim PDU tiap 1 detik
        - ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
        
        - ip link set eth1 master bond0
        - ip link set eth2 master bond0
        - ip link set bond0 up
        - ip link set eth1 up
        - ip link set eth2 up
        - ip addr add 192.168.10.100/24 dev bond0
        - ip route add default via 192.168.10.1
```

```bash
# Masuk ke Client
docker exec -it clab-arista-mlag-poc-client sh

# Hapus bond lama (Opsional, atau timpa parameter via sysfs)
# Cara cepat via sysfs tanpa hapus interface:
echo 1 > /sys/class/net/bond0/bonding/lacp_rate
echo 100 > /sys/class/net/bond0/bonding/miimon
```