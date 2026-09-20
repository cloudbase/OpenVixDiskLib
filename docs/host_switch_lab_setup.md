# Building a 2-host vMotion lab from a single bare ESXi host

Extends `docs/encryption_lab_setup.md`'s vCenter lab with a second
ESXi host and shared storage, needed to test anything host-switch or
vMotion related. Runnable scripts referenced here live in `.lab/`
(gitignored — see `.lab/README.md`).

## 0. Shared storage

vMotion needs a datastore both hosts can see. Rather than build
anything new, this lab reused an **already-running NFS server** on the
underlying Harvester cluster: a Helm deployment (`nfs-server-bci`,
`default` namespace) with `hostNetwork: true`, scheduled on one
Harvester node, exporting a hostPath directory wide open
(`ALLOWED_CLIENTS: '*'`, `rw,no_root_squash`). Worth checking whether
something similar already exists in any given lab before building new
storage infrastructure for this.

Mounted as an NFS datastore on both ESXi hosts via
`host.configManager.datastoreSystem.CreateNasDatastore()` — pointing
both hosts at the same `remoteHost`/`remotePath` makes vCenter
recognize it as one shared datastore automatically (same
`vim.Datastore` moref on both hosts). `.lab/mount_nfs_datastore.py`.

## 1. Build the second host

Same process as the first host in `docs/encryption_lab_setup.md`
(nested VM on the underlying hypervisor, `model: host-passthrough`
**required** for nested virtualization — don't default to
`host-model`), reusing the already-uploaded ESXi installer ISO rather
than sourcing new media.

**Kickstart automation did not work as planned.** ESXi's installer
supports a fully unattended install via a `ks=` boot argument (tried
`ks=nfs://<server>/<path>/ks.cfg`, kickstart file placed directly on
the same NFS server from step 0), injected by pressing **Shift+O** at
the very first boot-loader screen to edit kernel options. That window
is real but **very brief**, and driving it through a noVNC web
console via browser automation (screenshot → click round-trip) lost
the race every time — by the time the keypress landed, the installer
had already progressed past the point where boot options can be
edited. Ended up completing that one install interactively (manual
EULA/disk-select/password entry through the console) instead.

If automating this again, don't rely on live keypress timing — either
remaster the installer ISO's `boot.cfg`/`isolinux.cfg` to bake the
`ks=` argument in directly (no live interaction needed at boot at
all), or just budget for one interactive install.

**Also learned**: opening a VM's console **twice** (e.g. clicking
"Open in WebVNC" more than once) makes the two sessions fight and
repeatedly reconnect against each other — a known current Harvester
limitation. Keep exactly one console session open per VM. Browser
automation tooling that can't see/track console popup windows (they
open outside any tracked browser tab/window group) shouldn't be used
to drive a noVNC console beyond a single best-effort attempt; hand
keypress instructions to a human instead when timing matters.

## 2. Join the second host to the existing vCenter/cluster

Exactly the same two calls used to set up the first host — no changes
needed, just re-run pointed at the new host's IP:
`.lab/vc_setup.py` (`AddStandaloneHost`) then
`.lab/move_host_to_cluster.py` (`MoveInto_Task`). Confirmed both hosts
end up `connected` in the same cluster.

## 3. Enable vMotion

For a flat single-subnet lab network, the simplest path is enabling
the vMotion service directly on each host's existing management
VMkernel adapter (`vmk0`) rather than standing up a separate vMotion
portgroup/vSwitch:

```python
host.configManager.virtualNicManager.SelectVnicForNicType("vmotion", "vmk0")
```

(Production environments should separate vMotion traffic onto its own
VMkernel adapter/VLAN; not a concern for a throwaway lab.)

## 4. Verify vMotion actually works

`VirtualMachine.RelocateVM_Task(spec=vim.vm.RelocateSpec(host=<target>))`
with the VM already powered on. Worked cleanly between the two nested
hosts on the first try once steps 0–3 were in place.

## Gotcha: NFC needs a snapshot for a running VM's disk on NFS

Not a vMotion-specific issue, but hit while building the test case for
host-switch capture: opening a **running** VM's disk directly over NFC
on the new NFS datastore failed (`NfcFssrvrOpen` permission-check
`NFC_ERROR`) regardless of ticket type or which host served it;
working with the VM powered off, or with the VM powered on but reading
the **parent** disk after taking a snapshot. See `docs/host_switch.md`
for detail — recorded there since it's a protocol-level finding, not
purely a lab-setup one.
