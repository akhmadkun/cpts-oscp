
# R1

```bash
# 1. IP Addressing & ISO Family
set interfaces ge-0/0/0 unit 0 family inet address 10.10.12.1/24
set interfaces ge-0/0/0 unit 0 family iso
set interfaces lo0 unit 0 family inet address 1.1.1.1/32

# 2. Set NET (Network Entity Title) di Loopback
set interfaces lo0 unit 0 family iso address 49.0001.0000.0000.0001.00

# 3. Routing Protocol IS-IS (Disable L2 globally)
set protocols isis level 2 disable
set protocols isis interface ge-0/0/0.0
set protocols isis interface lo0.0 passive
commit
```

# R2

```bash
# 1. IP Addressing & ISO Family
set interfaces ge-0/0/0 unit 0 family inet address 10.10.12.2/24
set interfaces ge-0/0/0 unit 0 family iso
set interfaces ge-0/0/1 unit 0 family inet address 10.10.25.2/24
set interfaces ge-0/0/1 unit 0 family iso
set interfaces lo0 unit 0 family inet address 2.2.2.2/32
set interfaces lo0 unit 0 family iso address 49.0001.0000.0000.0002.00

# 2. Routing Protocol IS-IS (Per-interface level optimization)
set protocols isis interface ge-0/0/0.0 level 2 disable  # Ke arah R1 (L1)
set protocols isis interface ge-0/0/1.0 level 1 disable  # Ke arah R5 (L2)
set protocols isis interface lo0.0 passive
commit
```

# R3

```bash
set interfaces ge-0/0/0 unit 0 family inet address 10.10.34.3/24
set interfaces ge-0/0/0 unit 0 family iso
set interfaces lo0 unit 0 family inet address 3.3.3.3/32
set interfaces lo0 unit 0 family iso address 49.0002.0000.0000.0003.00

set protocols isis level 2 disable
set protocols isis interface ge-0/0/0.0
set protocols isis interface lo0.0 passive
commit
```

# R4

```bash
set interfaces ge-0/0/0 unit 0 family inet address 10.10.34.4/24
set interfaces ge-0/0/0 unit 0 family iso
set interfaces ge-0/0/1 unit 0 family inet address 10.10.54.4/24
set interfaces ge-0/0/1 unit 0 family iso
set interfaces lo0 unit 0 family inet address 4.4.4.4/32
set interfaces lo0 unit 0 family iso address 49.0002.0000.0000.0004.00

set protocols isis interface ge-0/0/0.0 level 2 disable  # Ke arah R3 (L1)
set protocols isis interface ge-0/0/1.0 level 1 disable  # Ke arah R5 (L2)
set protocols isis interface lo0.0 passive
commit
```

R5

```bash
set interfaces ge-0/0/0 unit 0 family inet address 10.10.25.5/24
set interfaces ge-0/0/0 unit 0 family iso
set interfaces ge-0/0/1 unit 0 family inet address 10.10.54.5/24
set interfaces ge-0/0/1 unit 0 family iso
set interfaces lo0 unit 0 family inet address 5.5.5.5/32
set interfaces lo0 unit 0 family iso address 49.0000.0000.0000.0005.00

# Matikan L1 secara global karena ini murni Core
set protocols isis level 1 disable
set protocols isis interface ge-0/0/0.0
set protocols isis interface ge-0/0/1.0
set protocols isis interface lo0.0 passive
commit
```