
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