
# Topology

```yaml
name: mclag-lab

topology:
  nodes:
    pe1:
      kind: vr-juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
      exec:
        - ip link set dev eth2 txqueuelen 10000
        - ip link set dev eth3 txqueuelen 10000
        - ip link set dev eth4 txqueuelen 10000
    
    pe2:
      kind: vr-juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
      exec:
        - ip link set dev eth2 txqueuelen 10000
        - ip link set dev eth3 txqueuelen 10000
        - ip link set dev eth4 txqueuelen 10000

    ce1:
      kind: vr-juniper_vmx
      image: vrnetlab/juniper_vmx:18.2R1.9
      exec:
        - ip link set dev eth2 txqueuelen 10000
        - ip link set dev eth3 txqueuelen 10000

  links:
    # ICCP Link (Control Plane L3)
    - endpoints: ["pe1:eth2", "pe2:eth2"]
    
    # ICL Link (Data Plane L2 Trunk)
    - endpoints: ["pe1:eth3", "pe2:eth3"]
    
    # Member Links (MC-LAG ke arah CE)
    - endpoints: ["pe1:eth4", "ce1:eth2"]
    - endpoints: ["pe2:eth4", "ce1:eth3"]
```

# PE1

```bash
# 1. Konfigurasi ICCP (Control Link)
set interfaces ge-0/0/0 description "ICCP-LINK"
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30

# 2. Protokol ICCP
set protocols iccp local-ip-addr 10.0.0.1
set protocols iccp peer-ip-addr 10.0.0.2
set protocols iccp session-establishment-hold-time 50
set protocols iccp redundancy-group-id-list 1
set protocols iccp liveness-detection minimum-receive-interval 60
set protocols iccp liveness-detection transmit-interval-minimum 60

# 3. ICL (Inter-Chassis Data Link)
# Ini adalah trunk penghubung antar chassis
set interfaces ge-0/0/1 description "ICL-LINK"
set interfaces ge-0/0/1 flexible-vlan-tagging
set interfaces ge-0/0/1 encapsulation flexible-ethernet-services
set interfaces ge-0/0/1 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/1 unit 0 family bridge vlan-id-list 100

# 4. Member Link (MC-AE)
set interfaces ge-0/0/2 description "TO-CE1"
set interfaces ge-0/0/2 gigether-options 802.3ad ae0

# 5. Konfigurasi Aggregated Ethernet (ae0)
set interfaces ae0 flexible-vlan-tagging
set interfaces ae0 encapsulation flexible-ethernet-services
set interfaces ae0 aggregated-ether-options lacp active
set interfaces ae0 aggregated-ether-options lacp system-id 00:00:00:00:00:01
set interfaces ae0 aggregated-ether-options lacp admin-key 1
set interfaces ae0 aggregated-ether-options mc-ae mc-ae-id 1
set interfaces ae0 aggregated-ether-options mc-ae chassis-id 0
set interfaces ae0 aggregated-ether-options mc-ae mode active-active
set interfaces ae0 aggregated-ether-options mc-ae status-control active
set interfaces ae0 aggregated-ether-options mc-ae redundancy-group 1
set interfaces ae0 unit 0 family bridge interface-mode access
set interfaces ae0 unit 0 family bridge vlan-id 100

# 6. Bridge Domain
set bridge-domains VL100 vlan-id 100
set bridge-domains VL100 interface ae0.0
set bridge-domains VL100 interface ge-0/0/1.0

# 7. IRB untuk Gateway (Optional - buat tes ping)
set interfaces irb unit 100 family inet address 192.168.10.1/24
set bridge-domains VL100 routing-interface irb.100
```

# PE2

```bash
# 1. ICCP
set interfaces ge-0/0/0 description "ICCP-LINK"
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/30

set protocols iccp local-ip-addr 10.0.0.2
set protocols iccp peer-ip-addr 10.0.0.1
set protocols iccp session-establishment-hold-time 50
set protocols iccp redundancy-group-id-list 1
set protocols iccp liveness-detection minimum-receive-interval 60
set protocols iccp liveness-detection transmit-interval-minimum 60

# 2. ICL Link
set interfaces ge-0/0/1 description "ICL-LINK"
set interfaces ge-0/0/1 flexible-vlan-tagging
set interfaces ge-0/0/1 encapsulation flexible-ethernet-services
set interfaces ge-0/0/1 unit 0 family bridge interface-mode trunk
set interfaces ge-0/0/1 unit 0 family bridge vlan-id-list 100

# 3. Member Link
set interfaces ge-0/0/2 description "TO-CE1"
set interfaces ge-0/0/2 gigether-options 802.3ad ae0

# 4. Aggregated Ethernet (ae0)
# Perhatikan chassis-id dan status-control
set interfaces ae0 flexible-vlan-tagging
set interfaces ae0 encapsulation flexible-ethernet-services
set interfaces ae0 aggregated-ether-options lacp active
set interfaces ae0 aggregated-ether-options lacp system-id 00:00:00:00:00:01
set interfaces ae0 aggregated-ether-options lacp admin-key 1
set interfaces ae0 aggregated-ether-options mc-ae mc-ae-id 1
set interfaces ae0 aggregated-ether-options mc-ae chassis-id 1
set interfaces ae0 aggregated-ether-options mc-ae mode active-active
set interfaces ae0 aggregated-ether-options mc-ae status-control standby
set interfaces ae0 aggregated-ether-options mc-ae redundancy-group 1
set interfaces ae0 unit 0 family bridge interface-mode access
set interfaces ae0 unit 0 family bridge vlan-id 100

# 5. Bridge & IRB
set bridge-domains VL100 vlan-id 100
set bridge-domains VL100 interface ae0.0
set bridge-domains VL100 interface ge-0/0/1.0
set interfaces irb unit 100 family inet address 192.168.10.1/24
set bridge-domains VL100 routing-interface irb.100
```

# CE1

```bash
set interfaces ge-0/0/0 gigether-options 802.3ad ae0
set interfaces ge-0/0/1 gigether-options 802.3ad ae0

set interfaces ae0 aggregated-ether-options lacp active
set interfaces ae0 unit 0 family inet address 192.168.10.100/24
```