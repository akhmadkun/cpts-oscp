# Install

```bash
sudo pacman -S openvswitch
```

### Enable Services

```bash
sudo systemctl enable --now ovs-vswitchd.service
sudo ovs-vsctl show
```

### add new bridge (named ovs)

```bash
sudo ovs-vsctl add-br ovs
sudo ovs-vsctl show
```

### deploy containerlab

```yaml
name: iol-ovs
prefix: ""
# OVS bridge 'ovs' must already exist on the host.
# Containerlab attaches the veth peers created for each link to that bridge.

topology:
  nodes:
    ovs:
      kind: ovs-bridge

    r1:
      kind: cisco_iol
      image: arthurk99/cisco-iol:17.15.01
      startup-config: configs/r1.partial.cfg

    r2:
      kind: cisco_iol
      image: arthurk99/cisco-iol:17.15.01
      startup-config: configs/r2.partial.cfg

    r3:
      kind: cisco_iol
      image: arthurk99/cisco-iol:17.15.01
      startup-config: configs/r3.partial.cfg

  links:
    - endpoints: ["r1:Ethernet0/1", "ovs:ovsp1"]
    - endpoints: ["r2:Ethernet0/1", "ovs:ovsp2"]
    - endpoints: ["r3:Ethernet0/1", "ovs:ovsp3"]
```

```bash
sudo containerlab deploy -t iol-ovs.clab.yml
```

```bash
❯ sudo ovs-vsctl show
[sudo] password for akhmad:
f07b0656-675a-42ac-9826-4deb43a7024f
    Bridge ovs
        Port eth5
            Interface eth5
        Port eth2
            Interface eth2
        Port eth4
            Interface eth4
        Port ovs
            Interface ovs
                type: internal
        Port eth3
            Interface eth3
        Port eth1
            Interface eth1
        Port eth12
            Interface eth12
        Port eth6
            Interface eth6
        Port eth11
            Interface eth11
```

# LACP for KVM

## Create OVS Bridge

```bash
sudo ovs-vsctl add-br palo1 
sudo ovs-vsctl add-br palo2
```

## KVM Ports Setting

```xml
<interface type="bridge">
  <mac address="52:54:00:30:71:82"/>
  <source bridge="palo1"/>
  <virtualport type="openvswitch"/>
  <model type="virtio"/>
  ...
</interface>

<interface type="bridge">
  <mac address="52:54:00:9f:2d:ea"/>
  <source bridge="palo2"/>
  <virtualport type="openvswitch"/>
  <model type="virtio"/>
  ...
</interface>
```

## Forward BPDU setting

```bash
sudo ovs-vsctl set Bridge palo1 other_config:forward-bpdu=true
sudo ovs-vsctl set Bridge palo2 other_config:forward-bpdu=true
```