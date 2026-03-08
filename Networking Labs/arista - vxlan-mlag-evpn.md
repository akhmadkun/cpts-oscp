
# Task List

**Mission:** Build a modern Data Center network from zero. You will configure the physical highway (Underlay), bind the switches together for redundancy (MLAG), create isolated virtual buildings (VRFs), and connect them using a smart automated tunnel system (BGP EVPN).

Do not move to the next phase until you have verified the current one!
#### Phase 1: The Physical Highway (IP Addressing & Underlay BGP)

_Goal: Assign IP addresses to the cables connecting Spines and Leafs, and make sure they can reach each other's Loopback IPs._

- [ ] **Spines & Leafs:** Configure `/31` IP addresses on all physical interfaces connecting the Spines to the Leafs.
    
- [ ] **Spines & Leafs:** Create `Loopback0` and assign a unique `/32` IP address to every switch. This is their main Router-ID.
    
- [ ] **Spines & Leafs:** Enable `ip routing`.
    
- [ ] **Spines & Leafs:** Configure standard eBGP (`router bgp <ASN>`). Spines use ASN 65000, Rack 1 uses 65001, Rack 2 uses 65002.
    
- [ ] **Spines & Leafs:** Peer them together and advertise `Loopback0` into BGP using the `network` command.
    
- [ ] **Verification:** Go to Leaf11 and type `show ip route`. You MUST see the `Loopback0` IPs of the Spines and the **REMOTE Leafs (Rack 2)**. _(Note: You will NOT see your twin Leaf's Loopback0 because you share the same BGP AS Number—this is normal!)_.
    

#### Phase 2: The Twin Doors (MLAG Configuration)

_Goal: Make the two Leaf switches in the same rack act as one logical switch._

- [ ] **Leafs (Rack 1 & 2):** Create `vlan 4094` for the MLAG heartbeat.
    
- [ ] **Leafs (Rack 1 & 2):** Bundle the direct cables between the twin Leafs into a Port-Channel (e.g., `Po1000`), set it as a trunk, and assign IP addresses to `interface vlan 4094`.
    
- [ ] **Leafs (Rack 1 & 2):** Configure the `mlag configuration` block. Set the `domain-id`, the local interface, and the peer's heartbeat IP.
    
- [ ] **Verification:** Type `show mlag`. The status must be **Active/Active**.
    

#### Phase 3: The Virtual Building & Anycast Gateway (VRF & SVIs)

_Goal: Create an isolated tenant space (VRF) and set up the default gateways for the servers._

- [ ] **All Leafs:** Create a VRF using `vrf instance TENANT-A`. Enable routing for it using `ip routing vrf TENANT-A`.
    
- [ ] **All Leafs:** Set the universal Anycast MAC address globally: `ip virtual-router mac-address 00:aa:aa:aa:aa:aa`.
    
- [ ] **All Leafs:** Create VLAN 10 and VLAN 20.
    
- [ ] **All Leafs:** Create `interface Vlan10` and `interface Vlan20`. Put them inside the VRF (`vrf TENANT-A`). Assign the exact same Anycast IPs (`ip address virtual 10.10.10.254/24` and `10.10.20.254/24`) on every leaf.
    
- [ ] **All Leafs:** Create VLAN 1000. This will be our "Transit VLAN" for the VRF. Create `interface Vlan1000` and put it inside `vrf TENANT-A`. No IP address is needed here.
    

#### Phase 4: The Tunnels (VXLAN Interface)

_Goal: Configure the hardware tunnel endpoints (VTEP) and map the VLANs to VXLAN Network Identifiers (VNIs)._

- [ ] **All Leafs:** Create `interface Loopback1`. Assign the Primary IP (for data) and the Secondary IP (Virtual VTEP for ARP). Remember: Twin leafs in the same rack share the EXACT same Loopback1 IPs!
    
- [ ] **All Leafs:** Go back to BGP (`router bgp <ASN>`) and advertise these `Loopback1` IPs into the IPv4 Underlay network.
    
- [ ] **All Leafs:** Create `interface Vxlan1`. Set the source-interface to `Loopback1` and UDP port to `4789`.
    
- [ ] **All Leafs:** Inside `interface Vxlan1`, map VLAN 10 to VNI 1010, and VLAN 20 to VNI 1020 (These are L2VNIs).
    
- [ ] **All Leafs:** Inside `interface Vxlan1`, map your VRF to a unique routing VNI: `vxlan vrf TENANT-A vni 10000` (This is the L3VNI).
    

#### Phase 5: The Smart Brain (BGP EVPN)

_Goal: Turn on EVPN so the switches can share MAC and IP addresses dynamically without static flooding._

- [ ] **Spines:** Inside BGP, activate the EVPN family for all neighbors (`address-family evpn`, then `neighbor <IP> activate`). **Crucial Step:** Tell the Spines to pass the EVPN Route Targets by adding `neighbor <IP> send-community extended` for every Leaf neighbor!
    
- [ ] **Leafs:** Inside BGP, activate EVPN towards the Spines. Tell BGP to send extended communities (`neighbor <IP> send-community`).
    
- [ ] **Leafs:** Inside BGP, configure the Layer 2 EVPN. Create a block for `vlan 10` and `vlan 20`. Set `rd auto`, `route-target both auto`, and `redistribute learned` (to share Host MACs).
    
- [ ] **Leafs:** Inside BGP, configure the Layer 3 EVPN. Create a block for `vrf TENANT-A`. Manually set the RD using your Loopback0 IP and L3VNI (`rd <Loopback0-IP>:10000`). Set the Route-Targets to match the VNI universally (`route-target import evpn 10000:10000` and `route-target export evpn 10000:10000`). Don't forget `redistribute connected`!.
    

#### Phase 6: Server Connection & The Ultimate Test

_Goal: Plug in the servers and prove the network works._

- [ ] **Leafs:** Configure the server-facing ports as LACP Port-Channels and assign them to the correct VLANs (VLAN 10 for Host 1, VLAN 20 for Host 2). Add the `mlag` command to the Port-Channel.
    
- [ ] **Hosts:** Configure the Port-Channel, assign the host IP, and set the default route to the Anycast Gateway (e.g., `ip route 0.0.0.0/0 10.10.10.254`).
    
- [ ] **Verification 1:** From Leaf11, type `show bgp evpn summary`. The sessions to the Spines must be established.
    
- [ ] **Verification 2:** From Leaf11, type `show bgp evpn route-type mac-ip`. You should see the MACs/IPs of Host 2.
    
- [ ] **Verification 3:** From Host 1, `ping 10.10.20.1` (Host 2). If it replies, you are officially an EVPN engineer!