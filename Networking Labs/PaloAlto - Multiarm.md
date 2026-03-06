
# Skenario 1

```bash
# 1. Create a Management Profile to Allow Ping to the Gateway
set network profiles interface-management-profile Allow-Ping ping yes

# 2. Configure Layer 3 Interfaces and IP Addresses
set network interface ethernet ethernet1/1 layer3 ip 192.168.1.1/24
set network interface ethernet ethernet1/1 layer3 interface-management-profile Allow-Ping

set network interface ethernet ethernet1/2 layer3 ip 192.168.2.1/24
set network interface ethernet ethernet1/2 layer3 interface-management-profile Allow-Ping

# 3. Create Layer 3 Zones and Assign Interfaces
set zone LAN1 network layer3 ethernet1/1
set zone LAN2 network layer3 ethernet1/2

# 4. Add Both Interfaces to the Default Virtual Router (VR) for Routing
set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]

# 5. Create a SINGLE Security Policy for Bidirectional Traffic (Intra & Inter-Zone)
set rulebase security rules Allow-All-LAN action allow
set rulebase security rules Allow-All-LAN from [ LAN1 LAN2 ]
set rulebase security rules Allow-All-LAN to [ LAN1 LAN2 ]
set rulebase security rules Allow-All-LAN source any
set rulebase security rules Allow-All-LAN destination any
set rulebase security rules Allow-All-LAN application any
set rulebase security rules Allow-All-LAN service application-default
```

# Skenario 2

```bash
# 1. Buat object VLAN
set network vlan VLAN34

# 2. Konfigurasi Interface Layer 2 dan masukkan ke VLAN yang sama
set network interface ethernet ethernet1/3 layer2 
set network interface ethernet ethernet1/4 layer2 
set network vlan VLAN34 interface ethernet1/3
set network vlan VLAN34 interface ethernet1/4

# 3. Buat Zone L2 agar trafik L2 intra-vlan (Client3 ke Client4) diinspeksi/diizinkan
set zone LAN34-L2 network layer2 [ ethernet1/3 ethernet1/4 ]

# 4. Buat SVI (VLAN Interface) sebagai Gateway L3
set network interface vlan units vlan.34 ip 192.168.34.1/24
set network interface vlan units vlan.34 interface-management-profile Allow-Ping
set network vlan vlan34 virtual-interface vlan.34

# 5. Buat Zone L3 untuk SVI dan masukkan SVI ke Virtual Router default
set zone LAN34 network layer3 vlan.34
set network virtual-router default interface vlan.34

# 6. Update Security Policy sebelumnya dengan menambahkan zone LAN34
# Ini tetap menjaga aturan "hanya 1 policy" untuk seluruh trafik antar-klien
set rulebase security rules Allow-All-LAN from [ LAN1 LAN2 LAN34 ]
set rulebase security rules Allow-All-LAN to [ LAN1 LAN2 LAN34 ]
```

# Skenario 3

```bash
# 1. Konfigurasi Interface dan Zone Untrust
set network interface ethernet ethernet1/5 layer3 ip 203.0.113.1/30
set network interface ethernet ethernet1/5 layer3 interface-management-profile Allow-Ping
set zone Untrust network layer3 ethernet1/5

# Masukkan ke Virtual Router
set network virtual-router default interface ethernet1/5

# 2. Buat Default Route ke ISP
set network virtual-router default routing-table ip static-route Default-Route destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route Default-Route nexthop ip-address 203.0.113.2

# 3. Konfigurasi Source NAT (DIPP)
set rulebase nat rules Internet-Access source-translation dynamic-ip-and-port interface-address interface ethernet1/5
set rulebase nat rules Internet-Access to Untrust
set rulebase nat rules Internet-Access from [ LAN1 LAN2 LAN34 ]
set rulebase nat rules Internet-Access source any
set rulebase nat rules Internet-Access destination any

# 4. Buat Security Policy Outbound
set rulebase security rules Allow-Internet action allow
set rulebase security rules Allow-Internet from [ LAN1 LAN2 LAN34 ]
set rulebase security rules Allow-Internet to Untrust
set rulebase security rules Allow-Internet source any
set rulebase security rules Allow-Internet destination any
set rulebase security rules Allow-Internet application any
set rulebase security rules Allow-Internet service application-default
```

# Skenario 4

```bash
# 1. Konfigurasi Interface dan Zone DMZ
set network interface ethernet ethernet1/6 layer3 ip 10.0.0.1/24
set network interface ethernet ethernet1/6 layer3 interface-management-profile Allow-Ping
set zone DMZ network layer3 ethernet1/6
set network virtual-router default interface ethernet1/6

# 2. Konfigurasi Destination NAT
set rulebase nat rules Inbound-Web destination-translation translated-address 10.0.0.100
set rulebase nat rules Inbound-Web to Untrust
set rulebase nat rules Inbound-Web from Untrust
set rulebase nat rules Inbound-Web source any
set rulebase nat rules Inbound-Web destination 203.0.113.1
set rulebase nat rules Inbound-Web service any

# 3. Buat Security Policy Inbound (Zone Untrust -> Zone DMZ, Destination IP Web Server)
set rulebase security rules Allow-Inbound-Web action allow
set rulebase security rules Allow-Inbound-Web from Untrust
set rulebase security rules Allow-Inbound-Web to DMZ
set rulebase security rules Allow-Inbound-Web source any
set rulebase security rules Allow-Inbound-Web destination 10.0.0.100
set rulebase security rules Allow-Inbound-Web application any
set rulebase security rules Allow-Inbound-Web service application-default
```
