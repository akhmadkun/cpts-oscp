
# R1

```bash
# IP & IPv6
set interfaces ge-0/0/0 unit 0 family inet address 10.10.12.1/24
set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:10:12::1/64
set interfaces ge-0/0/0 unit 0 family iso
set interfaces lo0 unit 0 family inet address 1.1.1.1/32
set interfaces lo0 unit 0 family inet6 address 2001:db8::1/128
set interfaces lo0 unit 0 family iso address 49.0001.0000.0000.0001.00

# IS-IS Advanced Features
set protocols isis level 2 disable
set protocols isis level 1 wide-metrics-only
set protocols isis topologies ipv6-unicast
set protocols isis interface ge-0/0/0.0
set protocols isis interface lo0.0 passive
commit
```

## R2

```bash
# IP & IPv6
set interfaces ge-0/0/0 unit 0 family inet address 10.10.12.2/24
set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:10:12::2/64
set interfaces ge-0/0/0 unit 0 family iso
set interfaces ge-0/0/1 unit 0 family inet address 10.10.23.2/24
set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:10:23::2/64
set interfaces ge-0/0/1 unit 0 family iso
set interfaces lo0 unit 0 family inet address 2.2.2.2/32
set interfaces lo0 unit 0 family inet6 address 2001:db8::2/128
set interfaces lo0 unit 0 family iso address 49.0001.0000.0000.0002.00

# Route Leaking Policy (L2 to L1)
set policy-options policy-statement LEAK-L2-TO-L1 term LOOPBACK-R4 from protocol isis
set policy-options policy-statement LEAK-L2-TO-L1 term LOOPBACK-R4 from level 2
set policy-options policy-statement LEAK-L2-TO-L1 term LOOPBACK-R4 from route-filter 4.4.4.4/32 exact
set policy-options policy-statement LEAK-L2-TO-L1 term LOOPBACK-R4 from route-filter 2001:db8::4/128 exact
set policy-options policy-statement LEAK-L2-TO-L1 term LOOPBACK-R4 then accept

# IS-IS Advanced Features
set protocols isis level 1 wide-metrics-only
set protocols isis level 2 wide-metrics-only
set protocols isis level 2 authentication-key KunciRahasia
set protocols isis level 2 authentication-type md5
set protocols isis topologies ipv6-unicast

# Apply Route Leaking
set protocols isis export LEAK-L2-TO-L1 level 1

# Interfaces
set protocols isis interface ge-0/0/0.0 level 2 disable
set protocols isis interface ge-0/0/1.0 level 1 disable
set protocols isis interface lo0.0 passive
commit
```
