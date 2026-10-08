# Changed Block Tracking (CBT)

This is not a reverse-engineered NFC feature. VixDiskLib does not expose
CBT itself: `VixDiskLib_QueryAllocatedBlocks` (implemented separately;
see `docs/nfc_read.md`) reports which blocks are *allocated*
(non-sparse) within a single NFC-opened disk, not which byte ranges
*changed* between two points in time. Real backup tools
get changed-range information from vSphere's public
`VirtualMachine.QueryChangedDiskAreas` VIM call instead, used alongside
VDDK/NFC reads for the actual bytes. `openvixdisklib.nfc_auth` wraps
that public pyVmomi call directly — no capture, no wire format to
document, per the project rule to reuse pyVmomi for anything it already
exposes.

## Workflow

1. `nfc_auth.enable_change_tracking(vm)` — sets
   `VirtualMachineConfigSpec.changeTrackingEnabled = True` via
   `ReconfigVM_Task`. Takes effect for writes from that point forward;
   it does not retroactively track earlier changes.
2. Take a snapshot (or power-cycle the VM). A disk's `changeId` is
   empty until this happens.
3. `nfc_auth.disk_change_id(vm, device_key)` — reads the current
   `changeId` off `VirtualDisk.backing.changeId` (for example
   `"52 f3 b6 37 30 8d ea 3e-58 70 c0 fd 61 44 26 62/2"`).
4. Do backup work (VDDK/NFC reads of the disk at that point).
5. Later, take another snapshot.
6. `nfc_auth.query_changed_disk_areas(vm, new_snapshot, device_key,
   change_id_from_step_3)` — returns the byte ranges written between
   the two snapshots.
7. Read only those ranges via VDDK/NFC on the new snapshot's disk
   chain for an incremental backup.

For an initial full backup, pass `change_id="*"` in step 6 without a
prior snapshot. **Correction from an earlier draft of this doc:**
this does *not* report the entire disk as one changed extent — see
"Wildcard `changeId='*'` reports allocated regions, not the whole
disk" below.

## Validated in this lab

Confirmed end-to-end against a temporary VM on the standalone ESXi
8.0.3 lab host (no vCenter): enabled CBT, snapshotted, wrote one
sector via `openvixdisklib.openvixdisklib` at a known offset,
snapshotted again, and called `query_changed_disk_areas` with the
first snapshot's `changeId`. The single reported extent
(`start=3932160, length=65536`, i.e. sectors 7680–7807) correctly
covered the written sector (7777). Extents were 64 KiB-aligned in this
lab's observations; that granularity is server-defined, not part of
the function's contract.

### Wildcard `changeId="*"` reports allocated regions, not the whole disk

Tested `query_changed_disk_areas(vm, snapshot, device_key, "*")` (the
initial-full-backup path, no prior snapshot needed) against a fresh
10 GiB thin-provisioned temp-VM disk. `result.length` correctly
reports the full declared virtual capacity (10737418240 bytes), but
`result.changed_areas` only covered **1 MiB** total — not the whole
disk. For a thin-provisioned disk, `"*"` reports the regions that are
actually *allocated* (backed by real data on the datastore), not the
full sparse virtual capacity; unwritten/unallocated regions have
nothing to back up regardless. A backup tool doing an initial full
backup with `"*"` should read exactly the reported extents, not assume
it needs to read `result.length` bytes.

### One large contiguous write is one extent; scattered writes are not

Wrote a single 4 MiB contiguous region plus three separate one-sector
writes at scattered offsets (same disk, one CBT interval), then
queried changed areas:

```
4 extents reported:
  start=    196608 length=     65536 (64 KiB)
  start=  51183616 length=   4259840 (4160 KiB)  <-- covers the whole 4 MiB write as ONE extent
  start= 460783616 length=     65536 (64 KiB)
  start= 921567232 length=     65536 (64 KiB)
```

The 4 MiB write came back as a single extent (padded slightly beyond
4 MiB — 4259840 bytes vs. the exact 4194304 written — to the 64 KiB
tail-end granularity). Each scattered single-sector write produced its
own separate 64 KiB extent. **The extent list scales with the number
of discontiguous changed regions, not with the total volume of changed
data.** A multi-hundred-GB sequential write is still one small extent
record; thousands of scattered small writes (e.g. a busy database VM
doing random I/O across a large disk) produce thousands of extent
records in one `QueryChangedDiskAreas` response, since the API has no
pagination. Real backup tools facing that scenario typically chunk the
query with `start_offset` over fixed-size windows rather than querying
the whole disk in one call — `query_changed_disk_areas`'s
`start_offset` parameter exists for this, but nothing in this module
does the chunking loop itself; that is caller responsibility.

Disk-size scaling itself (e.g., whether extent granularity increases
for very large disks) was not tested — only reasoned about above as an
open question, not verified against a large ESXi 8 disk.

## What this does not cover

- `VixDiskLib_QueryAllocatedBlocks` (NFC-level allocated-block bitmap
  within a single disk, useful for skipping sparse regions inside a
  delta disk) — implemented separately, see `docs/nfc_read.md`. Pairs
  naturally with CBT: `query_changed_disk_areas` says which byte
  ranges changed, `query_allocated_blocks` says which parts of a
  snapshot's delta disk are actually worth reading. Note its "same
  still-open write handle" staleness gotcha in `docs/nfc_read.md` if
  chaining a CBT-driven write with an allocation check.
- `DDB_GET` fields (`biosGeo`, `adapterType`, `uuid`) — also
  implemented, see `docs/nfc_open.md`.
