# Remote Image

```bash
incus remote list  
```
![](images/Pasted%20image%2020250925092421.png)

# Search Images

```bash
> incus image list images: debian
```

# Launch Images

## Container

```bash
> incus launch images:debian/13/amd64 deb13
Launching deb13
```

## VM

```bash
> incus launch images:debian/13/amd64 deb13 --vm
Launching deb13
```

# Delete Images

```bash
> incus delete local:deb13
```

# Start and Stop instances

```bash
> incus start deb12  
> incus list  
+---------+---------+-------------------+------+-----------+-----------+  
|  NAME   |  STATE  |       IPV4        | IPV6 |   TYPE    | SNAPSHOTS |  
+---------+---------+-------------------+------+-----------+-----------+  
| deb12   | RUNNING | 10.99.1.97 (eth0) |      | CONTAINER | 0         |  
+---------+---------+-------------------+------+-----------+-----------+  
| kali    | STOPPED |                   |      | CONTAINER | 0         |  
+---------+---------+-------------------+------+-----------+-----------+  
| myalma9 | STOPPED |                   |      | CONTAINER | 0         |  
+---------+---------+-------------------+------+-----------+-----------+  

> incus stop deb12  
> incus list
+---------+---------+------+------+-----------+-----------+  
|  NAME   |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |  
+---------+---------+------+------+-----------+-----------+  
| deb12   | STOPPED |      |      | CONTAINER | 0         |  
+---------+---------+------+------+-----------+-----------+  
| kali    | STOPPED |      |      | CONTAINER | 0         |  
+---------+---------+------+------+-----------+-----------+  
| myalma9 | STOPPED |      |      | CONTAINER | 0         |  
+---------+---------+------+------+-----------+-----------+
```
# Shell Access

```bash
> incus exec deb12 -- bash
root@deb12:~#
```

```bash
cd /tmp
git clone https://gitlab.com/parrotsec/project/installer-script
cd installer-script
chmod u+x install.sh
```

# Auto-start instance

```bash
> incus config set deb12 boot.autostart false

> incus config get deb12 boot.autostart  
false
```

# Rename Instance

```
> incus rename deb12 parrot12  
> incus list  
+----------+---------+------+------+-----------+-----------+  
|   NAME   |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |  
+----------+---------+------+------+-----------+-----------+  
| kali     | STOPPED |      |      | CONTAINER | 0         |  
+----------+---------+------+------+-----------+-----------+  
| myalma9  | STOPPED |      |      | CONTAINER | 0         |  
+----------+---------+------+------+-----------+-----------+  
| parrot12 | STOPPED |      |      | CONTAINER | 0         |  
+----------+---------+------+------+-----------+-----------+
```

# Add GUI

```bash
incus config device add kali wayland proxy \
  connect=unix:/run/user/1000/wayland-0 \
  listen=unix:/run/user/1000/wayland-0
```

```bash
incus exec kali -- bash
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/1000
firefox-esr &
```

# Import Offline Image

```bash
lxc image import ubuntu-template.tar.xz --alias ubuntu
```
# Set security.privileged

```bash
lxc init ubuntu alpineroot -c security.privileged=true
```

or

```bash
lxc config set alpineroot security.privileged true
lxc config show alpineroot
lxc restart alpineroot
```

# Mount host folder to instance

```shell
lxc config device add alpineroot host-root disk source=/ path=/mnt/root recursive=true
```
