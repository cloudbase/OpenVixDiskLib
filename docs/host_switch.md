# Host-switch (`NFC_AIO_SWITCH_HOST_*`)

This is not a reverse-engineered NFC feature, at least not for the
scenario tested. `strings` on `libvixDiskLib.so` shows this is VDDK's
mechanism for keeping an NFC/backup session alive across a **live
vMotion** of the VM being backed up — a `SWITCHHOST_VADP` string (VADP
being VMware's official backup-API framework) and a `PreSwitchHost
callback` string carrying a full new-host descriptor (`Server IP,
Port, Session ID, SSL Thumbprint, NFC Service Endpoint`). Testing it
needed a second ESXi host in the same cluster with shared storage — a
significant infra build, documented in `docs/host_switch_lab_setup.md`.

## Investigation

With two hosts sharing an NFS datastore, kept an NFC read session
alive (native VDDK, one-second-interval reads, under the same SSL-hook
technique as every other capture) while triggering a live vMotion of
the VM mid-session via `RelocateVM_Task`. Result: **the session was
completely unaffected**. All 40 reads across the ~40-second test
succeeded, including the ones during and immediately after the
migration, with no visible interruption, no reconnect, and no error.

Checked the raw wire capture for any sign of a switch happening
invisibly underneath the Python-level success: only **one TCP file
descriptor** was used for the NFC connection (port 902) for the entire
session, before, during, and after the vMotion. No second TLS/TCP
handshake, no `NFC_AIO_SWITCH_HOST_*` traffic, nothing.

## Why this makes sense

NFC disk access is **datastore-based, not VM/host-based** — the
client opens a path like `[datastore] vm/vm.vmdk`, not "the disk
currently attached to running VM X on host Y". As long as the ESXi
host the NFC session is talking to still has access to that datastore
(true here: both hosts mount the same shared NFS export), there is
nothing that needs to change when the VM's *compute* moves to a
different host. The file didn't move; the host serving the NFC
connection doesn't need to either.

This suggests `NFC_AIO_SWITCH_HOST_*` exists for a narrower case than
"any vMotion" — most plausibly a **Storage vMotion** (the disk's
*datastore* changes, which could genuinely strand an NFC session on a
host that no longer has a path to the file), or a scenario where the
originally-connected host itself becomes unavailable (enters
maintenance mode, disconnects, etc.) independent of the VM's own
migration. Neither of those was tested.

## What this does not cover

- **Storage vMotion** (the disk file itself relocating to a different
  datastore mid-session) was not tested — this is the most likely
  actual trigger for `NFC_AIO_SWITCH_HOST_*` and would need a genuinely
  different experiment (migrate the *disk*, not just the VM's compute).
- **Losing the connected host** (maintenance mode, host failure,
  disconnect) while an NFC session is active was not tested — could
  independently trigger the same mechanism regardless of whether the
  VM itself ever moves.
- Direct-ESXi (no vCenter) sessions were not tested for this scenario;
  everything above went through vCenter.

## Also found along the way: NFC needs a snapshot for a running VM's disk on NFS

Discovered by accident while setting up this test, not something the
`NFC_AIO_SWITCH_HOST_*` investigation was looking for, but real and
worth recording: opening a **running** VM's base disk directly over
NFC failed with an `NFC_ERROR` reply (`NfcFssrvrOpen` permission
check, per the binary's own strings) on an **NFS** datastore — both
read-only and read-write tickets, on both hosts, regardless of which
host. The same operation against the same VM **powered off** worked
immediately. Taking a snapshot first (redirecting live writes to a
delta file) and opening the **parent** disk — the same pattern already
used elsewhere in this project for reading a snapshot's parent VMDK —
also worked immediately, with the VM still powered on.

This project's other captures have all used **VMFS** datastores, where
opening a running VM's live disk directly over NFC has never needed a
snapshot. NFS evidently enforces this requirement where VMFS doesn't —
plausibly a difference in how each locks a file that's simultaneously
open for guest I/O and for NFC. Not otherwise investigated (a single
repro was enough to find the workaround), but worth remembering if a
future capture against an NFS-backed disk hits the same generic
"`Unknown error`"/opaque `NFC_ERROR` from VDDK: check whether the VM is
powered on and whether a snapshot is needed first.
