# KVM Tweaks

```bash
echo 0 | sudo tee /sys/module/kvm/parameters/halt_poll_ns
```

`permanent solution`

```bash
echo "options kvm halt_poll_ns=0" | sudo tee /etc/modprobe.d/kvm.conf
```

# vJunos Router & Switch

```bash
sudo virt-edit -a vJunos-switch-25.4R1.12.qcow2 \
  /home/pfe/junos/start-junos.sh \
  -e 's#^CPU_FLAG=.*#CPU_FLAG=\$(cat /proc/cpuinfo | grep -ciE "vmx|svm")#'
```

## Verify

```bash
sudo virt-cat -a vJunos-router-25.4R1.12.qcow2 /home/pfe/junos/start-junos.sh
```

Must have the following lines

```bash
CPU_FLAG=$(cat /proc/cpuinfo | grep -ciE "vmx|svm")
```
# Administration

```
sudo virsh net-define /tmp/hostonly.xml
sudo virsh net-start hostonly
sudo virsh net-autostart hostonly
```

# PA-VM-KVM-10.0.4.qcow2

```xml
<qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
 <qemu:arg value='-rtc'/> 
 <qemu:arg value='base=2021-09-20'/>
</qemu:commandline>
```

## Qemu disk overlay

```
sudo qemu-img create -f qcow2 -F qcow2 -b ./PA-VM-KVM-10.0.4.qcow2 ./palo-lab01.qcow2
```

**Hasilnya:**

- File asli tetap bersih.
    
- File `palo-lab-01.qcow2` hanya akan berisi perubahan data saja (ukurannya mulai dari KB).
    
- Jika lab kamu rusak, tinggal hapus file `palo-lab-01.qcow2` dan buat lagi dari awal dalam hitungan detik.