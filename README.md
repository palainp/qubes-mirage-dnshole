Qubes-Mirage-DNShole
====================

This repository takes its roots from [qubes-mirage-firewall], [qubes-miragevpn] and [mirage-hole]. All of them are licensed under BSD-2-Clause licence, therefore this unikernel has the same license.

This unikernel serves as an "in-chain" service virtual machine which:
  - load at startup a list of blocked domains
  - inspects packets that target the Qubes default resolver addresses (more precisely, it inspects packets that target the same addresses as its DNS resolver addresses taken from QubesDB, see notes below)
  - check it the DNS requested domain is present in the blocked list
  - reply with "localhost" if it's present
  - forward to uplink if not
  - every other packets are forwarded uplink


Building and running as Qubes AppVM
-----------------------------------
To build:
```
mirage configure -t xen
make depend
make build
```

To create a Qubes AppVM (this is similar to the procedure for qubes-mirage-firewall):
Run those commands in dom0 to create a `sys-mirage-dnshole` kernel and an AppVM using that kernel (replace the name of your AppVM where you build your unikernel `dev`, and the corresponding directory `sys-mirage-dnshole`):
```
mkdir -p /var/lib/qubes/vm-kernels/mirage-dnshole/
cd /var/lib/qubes/vm-kernels/mirage-dnshole/
qvm-run -p dev 'cat mirage-hole/dist/mirage-dnshole.xen' > vmlinuz
qvm-create \
  --property kernel=mirage-dnshole \
  --property kernelopts='' \
  --property memory=32 \
  --property maxmem=32 \
  --property netvm=sys-firewall \
  --property provides_network=True \
  --property vcpus=1 \
  --property virt_mode=pvh \
  --label=green \
  --class StandaloneVM \
  sys-mirage-dnshole
qvm-features sys-mirage-dnshole no-default-kernelopts 1
```

In order to use it, you will also need to download a blocking list (or create it by yourself), tar store it, as a tarball in the root volume of your unikernel VM:
```
qvm-run -p dev 'curl https://blocklistproject.github.io/Lists/tracking.txt -o tracking.txt && tar cvf tracking.tar tracking.txt && cat tracking.tar' > tracking.tar
qvm-volume import sys-mirage-dnshole:root tracking.tar
```
You also may want to name differently you blocking list, or store multiple different files in the same tarball. To change the file read in the tarball, you need to change the command line parameter of the unikernel:
```
qvm-prefs --set sys-mirage-dnshole -- kernelopts '--blocking-name=theotherlist.txt'
```

Various notes
-------------

Be aware that any DNS request that use other addresses than the one of the unikernel (e.g., 10.139.1.1 and 10.139.1.2) won't be inspected. It's definitely possible to inspect every first packet for every flows, but it will slow down the bandwidth and is not activated so far.

The current unikernel has some limitations such as:
  - the unikernel is very new and is not tested as what qubes-mirage-firewall is
  - the netvm property cannot be change on the fly, I'm trying to keep the code simple but I'll work on that at some point
  - the unikernel does not support commands, nor firewalling rules, you'll need to chain multiple unikernels

[qubes-mirage-firewall]: https://github.com/mirage/qubes-mirage-firewall
[qubes-miragevpn]: https://github.com/robur-coop/qubes-miragevpn
[mirage-hole]: https://github.com/jmid/mirage-hole

