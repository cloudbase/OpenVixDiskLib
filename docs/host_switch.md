# Host-switch (`NFC_AIO_SWITCH_HOST_*`)

This is not a reverse-engineered NFC feature, at least not for either
scenario tested. `strings` on `libvixDiskLib.so` shows this is VDDK's
mechanism for keeping an NFC/backup session alive across a **live
vMotion** of the VM being backed up — a `SWITCHHOST_VADP` string (VADP
being VMware's official backup-API framework) and a `PreSwitchHost
callback` string carrying a full new-host descriptor (`Server IP,
Port, Session ID, SSL Thumbprint, NFC Service Endpoint`). Testing it
needed a second ESXi host in the same cluster with shared storage — a
significant infra build, documented in `docs/host_switch_lab_setup.md`.

## Investigation 1: compute-only vMotion, shared storage

With two hosts sharing an NFS datastore, kept an NFC read session
alive (native VDDK, one-second-interval reads, under the same SSL-hook
technique as every other capture) while triggering a live vMotion of
the VM mid-session via `RelocateVM_Task` (compute only — the disk's
datastore didn't change). Result: **the session was completely
unaffected**. All 40 reads across the ~40-second test succeeded,
including the ones during and immediately after the migration, with
no visible interruption, no reconnect, and no error.

## Investigation 2: combined storage + compute vMotion

Repeated with a much more aggressive scenario, to try to force a real
switch: a VM with its disk on a **host-local** VMFS datastore (only
reachable by that one host, not the target), then a single
`RelocateVM_Task` moving **both** the VM's compute *and* its disk (to
the shared NFS datastore) to the other host simultaneously — the
kind of migration that should, in principle, strand an NFC session
that was talking to the original host, since after the move that host
has no path to the file's new location at all.

Result: **still completely unaffected**. All 90 reads succeeded
through the full migration (which took noticeably longer than the
compute-only case, as expected for a real data copy), including reads
issued after `RelocateVM_Task` had fully completed and the disk was
confirmed to be at its new location on the new datastore.

## Checked the wire, both times

In both investigations, the raw capture shows only **one TCP file
descriptor** used for the NFC connection (port 902) for the entire
session — before, during, and after the migration. Only one classic
NFC handshake sequence appears anywhere in either capture (searched
for a second `PlainText` handshake message, found only the original
one). No `NFC_AIO_SWITCH_HOST_*` traffic, no reconnect, nothing.

## Why this makes sense

NFC disk access is **datastore-based, not VM/host-based** — the
client opens a path like `[datastore] vm/vm.vmdk`, and the already-open
file handle from `OPEN_FILE` apparently stays valid even when the
underlying file relocates to a completely different datastore during
an active session. Whatever redirection is needed happens entirely
below the NFC layer, transparently, for both a VM's compute moving and
its storage moving — as long as everything stays inside the same
vCenter-managed environment with the migration completing normally.

This means `NFC_AIO_SWITCH_HOST_*` is likely reserved for a case
neither investigation could safely produce: the **originally-connected
host itself becoming unavailable** (entering maintenance mode,
disconnecting, or failing) independent of whether the VM ever
migrates — a scenario that would need to disrupt a real host serving
other things in the lab to test, and wasn't attempted.

## What this does not cover

- **Losing the connected host** (maintenance mode, host failure,
  disconnect) while an NFC session is active was not tested — the one
  remaining plausible trigger for this mechanism, and the only one
  left after both vMotion variants came back negative.
- Direct-ESXi (no vCenter) sessions were not tested for either
  scenario; everything above went through vCenter.

## Also found along the way: NFC needs a snapshot to open a *running* VM's disk, on any datastore

Discovered by accident while setting up these tests, not something the
`NFC_AIO_SWITCH_HOST_*` investigation was looking for, but real,
general, and worth recording carefully since an earlier draft of this
document mischaracterized it as NFS-specific — it is not.

Opening a **running** (powered-on) VM's base disk directly over NFC
fails with an `NFC_ERROR` reply (`NfcFssrvrOpen` permission check, per
the binary's own strings) — confirmed against **three separate VMs**,
on **both VMFS and NFS** datastores, on both hosts, with both
read-only and read-write tickets. The same operation against the same
VM **powered off** works immediately. Taking a snapshot first
(redirecting live writes to a delta file) and opening the **parent**
disk — the same pattern already used elsewhere in this project for
reading a snapshot's parent VMDK — also works immediately, with the VM
still powered on.

This project's other integration tests have never actually hit this,
purely by accident: the shared `lab` pytest fixture creates its
temporary VM but never powers it on, so every prior capture in this
whole project (against `SLES16`, `ovdl-crypto-test`, and the fixture's
own temp VMs) was reading a disk belonging to a **powered-off** VM
without realizing that was load-bearing. Confirmed directly: powering
on `SLES16` (an otherwise ordinary, long-lived lab VM on VMFS) and
attempting the exact same read that works fine while it's off
reproduces the identical `NFC_ERROR`.

Worth remembering for any future capture, on any datastore type: if
VDDK/`openvixdisklib` returns a generic `"Unknown error"` / opaque
`NFC_ERROR` opening a disk that otherwise looks correct, check whether
the VM is powered on and whether a snapshot is needed first.
