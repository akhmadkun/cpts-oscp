
# yaml topoloy

```yaml
name: vxlan-evpn-lab

topology:
  nodes:
    # --- Leaf Switches (vJunos-Switch) ---
    leaf1:
      kind: juniper_vjunosswitch
      image: vrnetlab/juniper_vjunos-switch:25.4R1.12      
      exec:
        # Optimasi buffer interface agar OSPF/BGP tidak flapping
        - ip link set dev eth1 txqueuelen 10000
        - ip link set dev eth2 txqueuelen 10000

    leaf2:
      kind: juniper_vjunosswitch
      image: vrnetlab/juniper_vjunos-switch:25.4R1.12      
      exec:
        - ip link set dev eth1 txqueuelen 10000
        - ip link set dev eth2 txqueuelen 10000

    # --- Clients (Linux) ---
    client1:
      kind: linux
      image: ghcr.io/srl-labs/network-multitool:latest
      exec:
        # Assign IP ke Client 1 (VLAN 10)
        - ip addr add 192.168.10.1/24 dev eth1

    client2:
      kind: linux
      image: ghcr.io/srl-labs/network-multitool:latest
      exec:
        # Assign IP ke Client 2 (VLAN 10)
        - ip addr add 192.168.10.2/24 dev eth1

  links:
    # Underlay Link antar Leaf (xe-0/0/0)
    - endpoints: ["leaf1:eth1", "leaf2:eth1"]
    
    # Client Links (xe-0/0/1)
    - endpoints: ["leaf1:eth2", "client1:eth1"]
    - endpoints: ["leaf2:eth2", "client2:eth1"]
```

# Underlay

```
# 1. Interfaces
set interfaces xe-0/0/0 unit 0 family inet address 10.0.0.1/30
set interfaces lo0 unit 0 family inet address 1.1.1.1/32

# 2. Routing Options (Router ID)
set routing-options router-id 1.1.1.1

# 3. OSPF (Underlay Routing)
set protocols ospf area 0.0.0.0 interface xe-0/0/0.0 interface-type p2p
set protocols ospf area 0.0.0.0 interface lo0.0 passive
```

# Overlay

```
set protocols bgp group OVERLAY type internal
set protocols bgp group OVERLAY local-address 1.1.1.1
set protocols bgp group OVERLAY family evpn signaling
set protocols bgp group OVERLAY neighbor 2.2.2.2
set routing-options autonomous-system 65001
```

# VLAN

```
set vlans VLAN10 vlan-id 10 vxlan vni 10010
set interfaces xe-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces xe-0/0/1 unit 0 family ethernet-switching vlan members VLAN10
```

# EVPN & Switch-Options

```
# 1. Global Switch Options
set switch-options vtep-source-interface lo0.0
set switch-options route-distinguisher 1.1.1.1:1
set switch-options vrf-target target:65001:10010

# 2. Mengaktifkan Protokol EVPN
set protocols evpn encapsulation vxlan
set protocols evpn default-gateway no-gateway-community
set protocols evpn extended-vni-list all
```

# Verify

```
show bgp summary
show route table bgp.evpn.0 match-prefix 3:*
show route table bgp.evpn.0 match-prefix 2:*
show ethernet-switching table
```

# Test Dual Customer

```
# 1. Hapus config access port lama (bersih-bersih)
delete interfaces xe-0/0/1 unit 0 family ethernet-switching

# 2. Buat VLAN Baru (VLAN 20)
set vlans VLAN20 vlan-id 20

# 3. Mapping VLAN 20 ke VNI Baru (Misal: 10020)
set vlans VLAN20 vxlan vni 10020

# 4. Konfigurasi Port ke Client jadi TRUNK
set interfaces xe-0/0/1 unit 0 family ethernet-switching interface-mode trunk
set interfaces xe-0/0/1 unit 0 family ethernet-switching vlan members VLAN10
set interfaces xe-0/0/1 unit 0 family ethernet-switching vlan members VLAN20

# --- Bagian EVPN tidak perlu diubah! ---
# Karena kita sudah pakai 'set protocols evpn extended-vni-list all',
# EVPN otomatis mendeteksi ada VNI baru (10020) dan langsung meng-advertise-nya.
# RD dan RT akan mengikuti induknya (switch-options).
```
