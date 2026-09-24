# HotAdd transport

OpenVixDiskLib can SCSI-HotAdd a VMDK onto the Linux guest that is
running the library, then read and write it as a local block device.
This is not an NFC protocol: it uses public VIM `ReconfigureVM` plus
guest SCSI I/O. There is no VixTransport linked clone and no VMDK
parser; ESXi presents a single SCSI LUN.

NBD and NBDSSL remain the default. `transport_modes=None` is still
`nbdssl`. `hotadd` is advertised and selected only when the process is
a VMware guest (`/sys/class/dmi/id/sys_vendor`).

## Mapping from VDDK

| VDDK behaviour | OpenVixDiskLib |
| -------------- | -------------- |
| Run inside a proxy VM | Same. DMI UUID is matched to `config.uuid`. |
| SCSI HotAdd of the source VMDK | `ReconfigureVM` add of an existing backing onto a **SCSI** controller on the proxy |
| Linked clone via VixTransport | Not implemented. The snapshot or base VMDK is attached directly. |
| Open as a whole-disk VMDK | Open `/dev/sdX` with `pread` / `pwrite` |
| IDE disks | Not supported (same as VDDK) |
| NVMe / SATA source disks | Supported. The backing file is attached onto proxy SCSI; the guest sees `/dev/sdX`, not `/dev/nvme*`. |
| HotAdd onto a proxy NVMe controller | Not implemented |

Colon lists such as `file:san:hotadd:nbdssl:nbd` pick the first **usable**
mode. On a bare-metal host that is `nbdssl`. Inside a guest it is
`hotadd`. `"hotadd"` alone on bare metal raises `NotImplementedError`.

## Attach and detach

1. Find this guest in vCenter (`SearchIndex.FindByUuid`).
2. Resolve `disk_path` on the source VM. SCSI, NVMe
   (`VirtualNVMEController`), and SATA (`VirtualAHCIController`) are
   accepted. IDE and RDM are rejected. A powered-on source VM requires
   `snapshot_ref`; a powered-off VM may attach the base disk.
3. Add the existing VMDK to a free SCSI unit on the proxy (unit 7 is
   skipped). If every unit is taken, a PVSCSI controller is added.
   Read-only opens use `independent_nonpersistent` (redo log, source
   stays clean). Writable opens use `persistent`.
4. Rescan SCSI hosts and wait for the device. Matching prefers sysfs
   `bus:0:unit:0`, then `*:0:unit:0` when `unit != 0`.
5. `close` detaches with `Operation.remove` and **no** `fileOperation`.
   The source VMDK must not be deleted. Leftover attachments of the
   same backing are detached before a new open.

Never HotAdd the proxy's own boot disk. Never use “newest `sdX`” as the
only match when a unique SCSI address exists.

Do not remove the source VM or its snapshot while the disk is still
attached. Independent-nonpersistent attaches create a redo log on the
source datastore; detach is what cleans it up.

## API

`VixDiskLibHandle.connect(..., transport_modes="hotadd")` then
`open` / `read` / `write` / `close` as for NBD. Compression open flags
and NFC `skip_decompression` do not apply; FastLZ flags on a HotAdd
open raise `NotImplementedError`. `readinto` returns a `ReadResult`
with empty `fragments`.

Implementation: `openvixdisklib.hotadd`.

## Lab

Live tests SSH into a Linux proxy that shares the lab datastore and
run `tests/integration/hotadd_remote.py` there. Configure
`.test_config.yaml`:

```yaml
hotadd_proxy:
  host: hotadd-proxy.example.com
  user: root
  # identity_file: /home/user/.ssh/id_ed25519
```

Tests skip when SSH is unavailable. The session lab VM (PVSCSI) and a
function-scoped NVMe VM are HotAdded onto the proxy, written, and
checked again over `nbdssl` from the runner. `tox -e perf` times the
same transfer sizes over HotAdd (plain I/O; FastLZ and NFC AIO do not
apply). Dependencies on the proxy are installed into
`/tmp/openvixdisklib-hotadd/.venv`, not the system Python.
