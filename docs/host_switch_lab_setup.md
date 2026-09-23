# Requirements for a 2-host vMotion lab

Testing anything host-switch or vMotion related needs a vCenter with two
ESXi hosts in the same cluster, plus storage both hosts can see. See
`docs/encryption_lab_setup.md` for a single-host vCenter lab; this
document only covers what changes when a second host is added. The
environment-specific details (how the hosts or the shared storage were
provisioned) are intentionally left out, as they depend on the lab.

## 1. Shared storage

vMotion needs a datastore that both hosts can see. Any shared storage
works (NFS, iSCSI, vSAN, ...). For NFS, mounting the same
`remoteHost`/`remotePath` on both hosts through
`host.configManager.datastoreSystem.CreateNasDatastore()` makes vCenter
recognize it as a single shared datastore (same `vim.Datastore` moref on
both hosts).

## 2. Second host

Any ESXi host works. When it is itself a nested VM, nested
virtualization must be enabled on the underlying hypervisor (e.g.
`host-passthrough` CPU mode on libvirt/KVM).

Join it to the same cluster as the first one, using the same calls:
`AddStandaloneHost` followed by `MoveInto_Task` on the cluster. Both
hosts should end up `connected` in the same cluster.

## 3. Enable vMotion

For a flat single-subnet lab network, the simplest option is to enable
the vMotion service on each host's existing management VMkernel adapter
(`vmk0`) instead of creating a dedicated portgroup/vSwitch:

```python
host.configManager.virtualNicManager.SelectVnicForNicType("vmotion", "vmk0")
```

Production environments should separate vMotion traffic onto its own
VMkernel adapter/VLAN.

## 4. Verify vMotion

With a VM powered on, relocate it to the other host:

```python
vm.RelocateVM_Task(spec=vim.vm.RelocateSpec(host=<target>))
```

## Gotcha: NFC needs a snapshot for a running VM's disk on NFS

Not vMotion specific, but hit while building the host-switch test case:
opening a **running** VM's disk directly over NFC on an NFS datastore
failed (`NfcFssrvrOpen` permission-check `NFC_ERROR`) regardless of the
ticket type or which host served it. It works with the VM powered off,
or with the VM powered on but reading the **parent** disk after taking a
snapshot. See `docs/host_switch.md` for details, recorded there since
it's a protocol-level finding rather than a lab-setup one.
