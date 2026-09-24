# SAN transport

OpenVixDiskLib can read and write a VMDK from a locally visible VMFS
LUN: the same SCSI disk ESXi uses for the datastore. This is not an
NFC protocol. pyVmomi is used only for inventory (datastore NAA / VMFS
UUID). I/O is `pread` / `pwrite` on `/dev/sdX` after a minimal VMFS6
lookup of the flat extent.

NBD and NBDSSL remain the default. `transport_modes=None` is still
`nbdssl`. `san` is advertised when `/sys/class/scsi_disk` (or
`scsi_host`) exists, and selected from a colon list such as
`file:san:hotadd:nbdssl:nbd`. `"san"` alone on a host with no SCSI
sysfs raises `NotImplementedError`.

## Mapping from VDDK

| VDDK behaviour | OpenVixDiskLib |
| -------------- | -------------- |
| Physical proxy that sees the VMFS LUN | Same. Match by NAA (`VmfsDatastoreInfo.extent.diskName` → `/dev/disk/by-id/wwn-*`). |
| Advanced transport plugin (`libdiskLibPlugin.so`) | Not used. VMFS mapping is in `openvixdisklib/san.py`. |
| Open the LUN `O_DIRECT` | `pread` / `pwrite` on the whole disk (same surface as HotAdd). |
| VMFS driver maps guest sector → file block | GPT VMFS partition, LVM/FS magics, VMDK descriptor scan, file-descriptor pointer walk (SFB/LFB). |
| Snapshot / SESPARSE chains | Not implemented. Powered-off persistent FlatVer2 only. |
| NFS / missing LUN | `RuntimeError`. No silent fallback to NBD. |

Colon lists pick the first **usable** mode. On this Linux SCSI host that
is `san`. Inside a VMware guest without a shared LUN it is `hotadd`.
Default `None` is still `nbdssl`.

## Matching and I/O

1. Resolve `[datastore] path.vmdk`. The datastore must be VMFS
   (`VmfsDatastoreInfo`). NFS is rejected.
2. Read the first extent's `canonicalName` (NAA) and the VMFS UUID.
3. Open the local disk whose `/dev/disk/by-id/wwn-0x…` matches that NAA.
4. Parse GPT for the VMFS type GUID
   (`2ae031aa-0f40-db11-9590-000c2911d1b8`; ESXi stores RFC UUID bytes
   on disk).
5. Check LVM magic `0xC001D00D` at partition + 1 MiB and FS magic
   `0x2fabf15e` (version 24) at partition + 2 MiB or + 19 MiB.
6. Scan allocated 1 MiB LUN chunks for `# Disk DescriptorFile` and the
   `RW … VMFS "…-flat.vmdk"` extent.
7. Find the VMFS6 regular-file descriptor (`fdmd`) whose
   `fileLength` matches that capacity. Pointers are 64-bit, aligned to
   the end of the file descriptor (two metadata blocks). Direct SFB/LFB
   or one pointer-block level is followed. SFB volume offset is
   `((cluster * resourcesPerCluster) + resource) << fileBlockShift`
   relative to file-block 0 (after the LVM label and 16 heartbeat
   slots). Holes (address 0) read as zeros. Writes need an allocated file
   block; SAN does not allocate.

FastLZ open flags raise `NotImplementedError`. `readinto` returns a
`ReadResult` with empty `fragments`.

ESXi keeps a VMFS cache of a mounted datastore. Writes from this
initiator are visible to a later SAN open (after the block-device
cache is dropped). They are not visible to `nbdssl` on the same
session. Cross-check nbdssl writes, then SAN reads.

Implementation: `openvixdisklib.san`.

## Lab

Live tests present a 20 GiB sparse file through in-kernel LIO (iblock
on a loop device) so ESXi can create a unique VMFS datastore
`ovdl-iscsi-<id>`. The pytest runner logs in with `iscsiadm` and sees
the same NAA. Configure an optional portal in `.test_config.yaml`:

```yaml
iscsi_san:
  portal: 192.0.2.10   # default: IPv4 of the default route
```

Tests skip when passwordless sudo, TCP 3260, or software iSCSI is
missing. They do not create VMkernel NICs from scratch. The
session-wide `lab` VM stays on the YAML `datastore`.
