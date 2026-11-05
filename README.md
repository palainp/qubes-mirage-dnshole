Qubes-Mirage-DNShole
====================

This repository takes its roots from [qubes-mirage-firewall], [qubes-miragevpn] and [mirage-hole]. All of them are licensed under BSD-2-Clause licence, therefore this unikernel has the same license.

This unikernel serves as an "in-chain" service virtual machine which:
  - load at startup a list of blocked domains
  - inspects packets that target the Qubes default resolver addresses (more precisely, it inspects packets that target the same addresses as its DNS resolver addresses taken from QubesDB, see notes below)
  - check it the DNS requested domain is present in the blocked list
  - reply with "localhost" if it's present and notify with a popup showing the blocked domain
  - forward to uplink if not
  - every other packets are forwarded uplink

The blocking list is loaded from a tar file dumped as the private disk of the AppVM, and is read-only. In order to update the list, you'll need to re-run the `qvm-volume import` command.

Building and running as Qubes AppVM
-----------------------------------
To build, you can either compile it with a configured opam environnement:
```bash
mirage configure -t xen
make depend
make build
```
Or using the docker/podman script, e.g. with podman:
```bash
sudo systemctl start podman
git clone https://github.com/palainp/qubes-mirage-dnshole.git
cd qubes-mirage-dnshole
./build-with.sh podman
```
And check the resulting hashsum.

To create a Qubes AppVM (this is similar to the procedure for qubes-mirage-firewall):
Run those commands in dom0 to create a `sys-mirage-dnshole` kernel and an AppVM using that kernel (replace the name of your AppVM where you build your unikernel `dev`, and the corresponding directory `sys-mirage-dnshole`):
```bash
mkdir -p /var/lib/qubes/vm-kernels/mirage-dnshole/
cd /var/lib/qubes/vm-kernels/mirage-dnshole/
qvm-run -p dev 'cat qubes-mirage-hole/dist/qubes-dnshole.xen' > vmlinuz
qvm-create \
  --property kernel=mirage-dnshole \
  --property kernelopts='' \
  --property memory=64 \
  --property maxmem=64 \
  --property netvm=sys-firewall \
  --property provides_network=True \
  --property vcpus=1 \
  --property virt_mode=pvh \
  --label=green \
  --class StandaloneVM \
  sys-mirage-dnshole
qvm-features sys-mirage-dnshole no-default-kernelopts 1
```

In order to use it, you will also need to download a blocking list (or create it by yourself), tar store it, as a tarball in the private volume of your unikernel VM:
```bash
qvm-run -p dev 'curl https://blocklistproject.github.io/Lists/tracking.txt -o tracking.txt && tar cvf tracking.tar tracking.txt && cat tracking.tar' > tracking.tar
qvm-volume import sys-mirage-dnshole:private tracking.tar
```
You also may want to name differently you blocking list, or store multiple different files in the same tarball. To change the file read in the tarball, you need to change the command line parameter of the unikernel:
```bash
qvm-prefs --set sys-mirage-dnshole -- kernelopts '--blocklist-name=theotherlistname.txt'
```

Qubes template package
----------------------

The repository can be built as a [qubes-builderv2] component producing a `qubes-template-mirage-dnshole` package. The package does not compile the unikernel: it fetches the released `qubes-dnshole.xen` for the version in the `version` file and checks it against `rpm_spec/qubes-dnshole-<version>.xen.sha256`.
The template root volume is a small ext2 image holding the unikernel and a `grub.cfg`, booted by `pvgrub2-pvh` (`kernel=''`).

In a Fedora qube, get qubes-builderv2 and its dependencies:
```bash
git clone https://github.com/QubesOS/qubes-builderv2.git
cd qubes-builderv2
git submodule update --init
sudo dnf install $(cat dependencies-fedora.txt)
```
Builds run in an executor, which needs a one-time setup described in the qubes-builderv2 README: either the `qubes` executor (a disposable template and a dom0 RPC policy, used by the configuration below) or a `docker`/`podman` image made with `tools/generate-container-image.sh`.

Copy `builder.yml` from this repository in the qubes-builderv2 directory (its `include` is relative to its own location), then build:
```bash
./qb -c mirage-dnshole -d host-fc41 package fetch prep build
```

Install the resulting rpm in dom0 and create the qube from the template:
```bash
qvm-template install --skip-start ./qubes-template-mirage-dnshole-*.noarch.rpm
qvm-create \
  --template mirage-dnshole \
  --property memory=64 \
  --property maxmem=64 \
  --property netvm=sys-firewall \
  --property provides_network=True \
  --property vcpus=1 \
  --label=green \
  sys-mirage-dnshole
qvm-volume import sys-mirage-dnshole:private tracking.tar
```
`--skip-start` avoids the post-install start of the template, which has no blocklist.

Unikernel arguments (e.g. `--blocklist-name`) are set in at build time: `kernelopts` are not passed to qubes without a dom0 kernel.

To release, add the entry in `CHANGES.md`, commit it, then run `./make-release.sh <version> podman`: it builds, updates the hashsums, `version`, `rel` and `rpm_spec/qubes-dnshole-<version>.xen.sha256`, commits and tags.

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
[qubes-builderv2]: https://github.com/QubesOS/qubes-builderv2
