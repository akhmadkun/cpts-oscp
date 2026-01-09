# Upgrade

```bash
curl -sL 'https://labhub.eu.org/api/raw/?path=/UNETLAB%20I/upgrades_pnetlab/bionic/install_pnetlab_latest_v5.sh' | sh
```

# ishare2

```bash
wget -O /usr/sbin/ishare2 https://raw.githubusercontent.com/ishare2-org/ishare2-cli/main/ishare2

chmod +x /usr/sbin/ishare2

ishare2
```

# linux tiny core
#ifconfig 
```
sudo ifconfig eth0 192.168.122.50 netmask 255.255.255.0 up
```

# Palo Alto fw

<mark style="background: #ABF7F7A6;">paloalto-10.0.4-Pre-Licensed-Eval</mark> is working as normal with below QEMU Options

```
-machine type=pc,accel=kvm -nographic -rtc base=utc -rtc base=2021-09-20
```


# Forti

```
FortiGate Evaluation License Expiry Solution

1. Wipe or reset to factory default 
2. Disconnect your Node the from Internet
3. Start the node and apply the below command

config system ntp
set ntpsync disable
end
```
