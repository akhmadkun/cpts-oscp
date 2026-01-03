n# Deployment

- Make sure to have 3 SATA disks
	- 1 for host
	- 1 for cvm
	- 1 or more for data
- Network
	- 1 NIC connected to virtual network default (NAT)
	- dev model e1000


IP Config Example :

```bash
Host: 192.168.122.200/24
CVM : 192.168.122.201/24
GW : 192.168.122.1
```

Make sure you can reach the cluster's subnet

# default credentials

1. AHV => root:nutanix/4u
2. CVM => nutanix:nutanix/4u
3. Prism Element => admin:nutanix/4u

# cluster deployment

Login to cvm via ssh <mark style="background: #BBFABBA6;">192.168.122.201</mark>, or console to ahv and ssh to cvm's internal ip (<mark style="background: #FFF3A3A6;">192.168.5.2</mark>)


```bash
# cluster -s <cvm_ip1,cvm_ip2> --redundancy_factor=1 create

cluster -s 192.168.122.201 --redundancy_factor=1 create

cluster status
```

```bash
nutanix@NTNX-9c7104c4-A-CVM:192.168.122.201:~$ ncli host ls

    Id                        : 00063d4f-65e0-14ea-028d-52540032f378::3
    Uuid                      : 02051760-6cda-417d-a6aa-b52ab04c100c
    Name                      : NTNX-9c7104c4-A
    IPMI Address              :
    Controller VM Address     : 192.168.122.201
    Controller VM NAT Address :
    Controller VM NAT PORT    :
    Hypervisor Address        : 192.168.122.200
    Hypervisor Version        : Nutanix 20230302.101026
    Host Status               : NORMAL
    Oplog Disk Size           : 53.91 GiB (57,887,060,016 bytes) (10.7%)
    Under Maintenance Mode    : null (-)
    Metadata store status     : Metadata store enabled on the node
    Node Position             : Node physical position cant be displayed for this model. Please refer to Prism UI for this information.
    Node Serial (UUID)        : 02051760-6cda-417d-a6aa-b52ab04c100c
    Block Serial (Model)      : 9c7104c4 (CommunityEdition)
```

# Cluster Virtual IP

- Login ke Prism Element (https://<CVM_IP>:9440).    
- Masuk ke **Settings** (ikon gear).    
- Cari menu **Cluster Details** → **Cluster Virtual IP**.    
- Masukkan **IP address** yang ada di subnet yang sama dengan CVM (misalnya CVM kamu 192.168.122.201, VIP juga harus di 192.168.122.x).    
- Simpan.    
- Sekarang akses Prism Element pakai VIP: `https://<VIP>:9440`.

