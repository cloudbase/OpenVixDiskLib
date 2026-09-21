# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Linux SAN transport: open a VMDK from a locally visible VMFS LUN.

The backup host must see the same SCSI LUN ESXi uses for the datastore
(matched by NAA). This is not NFC: inventory uses pyVmomi, I/O is
``pread`` / ``pwrite`` on the local disk after a minimal VMFS6 read of
the flat extent. Snapshot chains and VMFS allocation on write are not
implemented; holes read as zeros and writes need an existing file block.
"""

from __future__ import annotations

import fcntl
import logging
import os
import re
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from pyVmomi import vim

from openvixdisklib.nfc_open import ReadResult

LOG = logging.getLogger(__name__)

SECTOR_SIZE = 512
FILE_BLOCK_SIZE = 1024 * 1024
SCSI_DISK_DIR = "/sys/class/scsi_disk"
DISK_BY_ID = "/dev/disk/by-id"
LVM_MAGIC = 0xC001D00D
FS_MAGIC = 0x2FABF15E
FS_MAGIC_L = 0x2FABF15F
LVM_OFFSET = 0x100000
HEARTBEAT_COUNT = 16
FS_HEADER_OFFSETS = (0x200000, 0x1300000)
FDMD_MAGIC = 0x66646D64
RFMD_MAGIC = 0x72666D64
GPT_SIG = b"EFI PART"
# GPT type GUID as stored by ESXi (RFC UUID bytes, not mixed-endian).
# Same GUID as 2ae031aa-0f40-db11-9590-000c2911d1b8 / AA31E02A-400F-11DB-...
VMFS_TYPE_GUIDS = (
    bytes.fromhex("2ae031aa0f40db119590000c2911d1b8"),
    bytes.fromhex("aa31e02a400f11db9590000c2911d1b8"),
)
DESCRIPTOR_NEEDLE = b"# Disk DescriptorFile"
SCAN_LIMIT = 20 * 1024 * 1024 * 1024
BLKFLSBUF = 0x1261
ADDR_SFB = 0x1
ADDR_SB = 0x2
ADDR_LFB = 0x7
ZLA_FILE_BLOCK = 0x1
ZLA_SUB_BLOCK = 0x2
ZLA_POINTER_BLOCK = 0x3
ZLA_POINTER2_BLOCK = 0x5
DESC_REGFILE = 3


@dataclass(frozen=True)
class Extent:
    """Map ``length`` bytes of a VMFS file onto a LUN offset."""

    file_offset: int
    lun_offset: int
    length: int


@dataclass(frozen=True)
class GptPartition:
    """A GPT partition used as a VMFS extent."""

    start_lba: int
    end_lba: int

    @property
    def start_bytes(self) -> int:
        """Byte offset of the partition on the LUN."""
        return self.start_lba * SECTOR_SIZE


@dataclass(frozen=True)
class FsInfo:
    """Subset of the VMFS6 filesystem descriptor needed for SAN I/O."""

    offset: int
    uuid: str
    file_block_size: int
    md_alignment: int
    sfb_to_lfb_shift: int
    ptr_block_shift: int
    major_version: int


@dataclass(frozen=True)
class FileMeta:
    """VMFS file-descriptor metadata for a regular file."""

    fd_offset: int
    file_length: int
    block_size: int
    zla: int
    num_blocks: int
    pointers: tuple[int, ...]


def is_available() -> bool:
    """Return True when this Linux host can see SCSI disks."""
    return os.path.isdir(SCSI_DISK_DIR) or os.path.isdir("/sys/class/scsi_host")


def parse_datastore_path(disk_path: str) -> tuple[str, str]:
    """Split ``[datastore] rel/path.vmdk`` into name and relative path.

    Args:
        disk_path: Datastore path of the VMDK descriptor.
    """
    match = re.match(r"^\[([^\]]+)\]\s*(.*)$", disk_path.strip())
    if not match or not match.group(1) or not match.group(2):
        raise ValueError(f"unsupported disk path: {disk_path!r}")
    return match.group(1), match.group(2).replace("\\", "/")


def flat_extent_name(descriptor_relpath: str) -> str:
    """Return the sibling ``-flat.vmdk`` basename for ``descriptor_relpath``."""
    base = os.path.basename(descriptor_relpath)
    if base.endswith("-flat.vmdk"):
        return base
    if base.endswith(".vmdk"):
        return base[:-5] + "-flat.vmdk"
    return base


def normalize_naa(value: str) -> str:
    """Return a canonical ``naa.<hex>`` string."""
    text = value.lower().strip()
    if text.startswith("wwn-0x"):
        text = text[6:]
    elif text.startswith("0x"):
        text = text[2:]
    elif text.startswith("scsi-3"):
        text = text[6:]
    elif text.startswith("naa."):
        text = text[4:]
    hexpart = "".join(ch for ch in text if ch in "0123456789abcdef")
    if not hexpart:
        raise ValueError(f"cannot parse NAA from {value!r}")
    return "naa." + hexpart


def find_local_device(naa: str) -> str:
    """Return the local block device whose WWN matches ``naa``.

    Args:
        naa: Canonical name such as ``naa.6001405...``.
    """
    hexpart = normalize_naa(naa)[4:]
    if os.path.isdir(DISK_BY_ID):
        for name in sorted(os.listdir(DISK_BY_ID)):
            if "-part" in name:
                continue
            lower = name.lower()
            if lower.startswith("wwn-0x") and lower[6:] == hexpart:
                return os.path.realpath(os.path.join(DISK_BY_ID, name))
            if lower.startswith("scsi-3") and lower[6:] == hexpart:
                return os.path.realpath(os.path.join(DISK_BY_ID, name))
    raise RuntimeError(f"no local SCSI disk matching {naa}")


def vmfs_extent_naa(datastore: vim.Datastore) -> str:
    """Return the NAA of the first VMFS extent of ``datastore``."""
    info = datastore.info
    if not isinstance(info, vim.host.VmfsDatastoreInfo) or info.vmfs is None:
        raise RuntimeError(f"datastore {datastore.name!r} is not VMFS")
    extents = list(info.vmfs.extent or [])
    if not extents:
        raise RuntimeError(f"VMFS datastore {datastore.name!r} has no extents")
    return normalize_naa(str(extents[0].diskName))


def vmfs_uuid(datastore: vim.Datastore) -> str:
    """Return the VMFS UUID string from pyVmomi."""
    info = datastore.info
    if not isinstance(info, vim.host.VmfsDatastoreInfo) or info.vmfs is None:
        raise RuntimeError(f"datastore {datastore.name!r} is not VMFS")
    uuid = getattr(info.vmfs, "uuid", None)
    if not uuid:
        raise RuntimeError(f"VMFS datastore {datastore.name!r} has no UUID")
    return str(uuid).lower()


def parse_gpt_vmfs(fd: int) -> GptPartition:
    """Return the first GPT partition with the VMFS type GUID."""
    header = os.pread(fd, 512, 512)
    if header[:8] != GPT_SIG:
        raise RuntimeError("LUN has no GPT header")
    (part_lba,) = struct.unpack_from("<Q", header, 72)
    (num,) = struct.unpack_from("<I", header, 80)
    (esz,) = struct.unpack_from("<I", header, 84)
    table = os.pread(fd, num * esz, part_lba * SECTOR_SIZE)
    for i in range(num):
        entry = table[i * esz : (i + 1) * esz]
        if entry[:16] not in VMFS_TYPE_GUIDS:
            continue
        start, end = struct.unpack_from("<QQ", entry, 32)
        if start:
            return GptPartition(start_lba=start, end_lba=end)
    raise RuntimeError("GPT has no VMFS partition")


def _addr_type(address: int) -> int:
    return address & 0x7


def parse_sfb(address: int) -> tuple[int, int]:
    """Return ``(cluster, resource)`` from a VMFS6 small-file-block address."""
    cluster = (address >> 15) & 0x7FFFFFFF
    resource = (address >> 51) & 0x1FFF
    return cluster, resource


def parse_lfb(address: int) -> int:
    """Return the block number from a VMFS6 large-file-block address."""
    return (address >> 15) & 0x7FFFFFFF


def sfb_volume_offset(
    address: int, resources_per_cluster: int, file_block_shift: int
) -> int:
    """Return the volume byte offset of a VMFS6 SFB address."""
    cluster, resource = parse_sfb(address)
    return ((cluster * resources_per_cluster) + resource) << file_block_shift


def lfb_volume_offset(
    address: int, file_block_shift: int, sfb_to_lfb_shift: int
) -> int:
    """Return the volume byte offset of a VMFS6 LFB address."""
    return parse_lfb(address) << (file_block_shift + sfb_to_lfb_shift)


def _file_block_shift(file_block_size: int) -> int:
    if file_block_size <= 0 or file_block_size & (file_block_size - 1):
        raise RuntimeError(f"fileBlockSize {file_block_size} is not a power of two")
    return file_block_size.bit_length() - 1


def _default_sfb_rpc(file_block_size: int) -> int:
    return min(0x2000, 0x20000000 // max(file_block_size, 1))


def parse_vmdk_descriptor(text: str) -> tuple[int, str]:
    """Return ``(capacity_sectors, flat_basename)`` from a VMDK descriptor.

    Args:
        text: Descriptor file contents.
    """
    extent_re = re.compile(
        r'^\s*RW\s+(\d+)\s+VMFS\s+"([^"]+)"\s*$', re.MULTILINE | re.IGNORECASE
    )
    match = extent_re.search(text)
    if not match:
        raise RuntimeError("VMDK descriptor has no RW VMFS extent")
    return int(match.group(1)), match.group(2)


def _flush_block_device(fd: int) -> None:
    """Drop kernel buffer cache for ``fd`` so initiator reads see target writes."""
    try:
        fcntl.ioctl(fd, BLKFLSBUF)
    except OSError:
        LOG.debug("BLKFLSBUF failed", exc_info=True)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except OSError:
        LOG.debug("posix_fadvise DONTNEED failed", exc_info=True)


def _iter_allocated_mbs(fd: int, limit: int) -> Iterable[int]:
    size = os.lseek(fd, 0, os.SEEK_END)
    end = min(size, limit)
    off = 0
    while off < end:
        for sample in range(0, FILE_BLOCK_SIZE, 64 * 1024):
            head = os.pread(fd, 16, off + sample)
            if head and max(head) != 0:
                yield off
                break
        off += FILE_BLOCK_SIZE


def find_vmdk_descriptor(
    fd: int, relpath: str, limit: int = SCAN_LIMIT
) -> tuple[int, str]:
    """Scan allocated LUN blocks for the VMDK descriptor of ``relpath``."""
    base = os.path.basename(relpath)
    flat = flat_extent_name(relpath)
    found: tuple[int, str] | None = None
    for off in _iter_allocated_mbs(fd, limit):
        chunk = os.pread(fd, FILE_BLOCK_SIZE, off)
        pos = 0
        while True:
            idx = chunk.find(DESCRIPTOR_NEEDLE, pos)
            if idx < 0:
                break
            text = (
                chunk[idx : idx + 4096].split(b"\x00", 1)[0].decode("utf-8", "replace")
            )
            if base in text or flat in text:
                return off + idx, text
            if found is None:
                found = (off + idx, text)
            pos = idx + 1
    if found is not None:
        return found
    raise RuntimeError(f"VMDK descriptor for {relpath!r} not found on the LUN")


def _uuid_from_fs(raw: bytes) -> str:
    time_lo, time_hi = struct.unpack_from("<II", raw, 0)
    (rand,) = struct.unpack_from("<H", raw, 8)
    mac = raw[10:16]
    return (
        f"{time_lo:08x}-{time_hi:08x}-{rand:04x}-"
        f"{mac[0]:02x}{mac[1]:02x}-{mac[2:].hex()}"
    )


def read_fs_info(fd: int, part: GptPartition) -> FsInfo:
    """Read the VMFS6 filesystem descriptor from the partition."""
    for rel in FS_HEADER_OFFSETS:
        offset = part.start_bytes + rel
        blob = os.pread(fd, 0x180, offset)
        (magic,) = struct.unpack_from("<I", blob, 0)
        if magic not in (FS_MAGIC, FS_MAGIC_L):
            continue
        (major,) = struct.unpack_from("<I", blob, 4)
        uuid = _uuid_from_fs(blob[0x09:0x19])
        (file_block_size,) = struct.unpack_from("<Q", blob, 0xA1)
        (md_alignment,) = struct.unpack_from("<I", blob, 0x134)
        (sfb_to_lfb_shift,) = struct.unpack_from("<H", blob, 0x138)
        (ptr_block_shift,) = struct.unpack_from("<H", blob, 0x13E)
        if file_block_size == 0:
            file_block_size = FILE_BLOCK_SIZE
        if md_alignment == 0:
            md_alignment = 4096
        return FsInfo(
            offset=offset,
            uuid=uuid.lower(),
            file_block_size=int(file_block_size),
            md_alignment=int(md_alignment),
            sfb_to_lfb_shift=int(sfb_to_lfb_shift),
            ptr_block_shift=int(ptr_block_shift),
            major_version=int(major),
        )
    raise RuntimeError("VMFS filesystem descriptor not found on the LUN")


def _fd_layout(md_alignment: int) -> tuple[int, int, int]:
    """Return ``(fd_size, data_addrs_offset, data_addrs_size)`` for VMFS6."""
    fd_size = 2 * md_alignment
    if md_alignment <= 0x1000:
        data_addrs_size = 2560
    else:
        data_addrs_size = md_alignment >> 1
    return fd_size, fd_size - data_addrs_size, data_addrs_size


def _unpack_u64s(data: bytes) -> list[int]:
    count = len(data) // 8
    return list(struct.unpack_from(f"<{count}Q", data, 0)) if count else []


def _find_fbb_rpc(fd: int, part: GptPartition, fs: FsInfo, limit: int) -> int:
    """Return ``resourcesPerCluster`` from an FBB RFMD header, if present."""
    del part
    default = _default_sfb_rpc(fs.file_block_size)
    needle = struct.pack("<I", RFMD_MAGIC)
    for off in _iter_allocated_mbs(fd, min(limit, 64 * FILE_BLOCK_SIZE)):
        chunk = os.pread(fd, FILE_BLOCK_SIZE, off)
        idx = 0
        while True:
            pos = chunk.find(needle, idx)
            if pos < 0:
                break
            # FS3_ResFileMetadata.signature is at 0x20; resourceSize at 0x0c.
            if pos >= 0x20:
                hdr = chunk[pos - 0x20 : pos - 0x20 + 0x30]
                if len(hdr) >= 0x24:
                    (rpc,) = struct.unpack_from("<I", hdr, 0)
                    (resource_size,) = struct.unpack_from("<I", hdr, 0x0C)
                    if rpc and resource_size in (fs.file_block_size, FILE_BLOCK_SIZE):
                        return int(rpc)
            idx = pos + 1
    return default


def _read_file_meta(fd: int, fd_offset: int, fs: FsInfo) -> FileMeta | None:
    fd_size, addrs_off, addrs_size = _fd_layout(fs.md_alignment)
    raw = os.pread(fd, fd_size, fd_offset)
    if len(raw) < fd_size:
        return None
    meta = raw[fs.md_alignment :]
    if len(meta) < 0x68:
        return None
    (magic,) = struct.unpack_from("<I", meta, 0x64)
    if magic != FDMD_MAGIC:
        return None
    (desc_type,) = struct.unpack_from("<I", meta, 0x0C)
    if desc_type != DESC_REGFILE:
        return None
    (file_length,) = struct.unpack_from("<Q", meta, 0x14)
    (block_size,) = struct.unpack_from("<Q", meta, 0x1C)
    (num_blocks,) = struct.unpack_from("<Q", meta, 0x24)
    (zla,) = struct.unpack_from("<I", meta, 0x44)
    pointers = tuple(_unpack_u64s(raw[addrs_off : addrs_off + addrs_size]))
    return FileMeta(
        fd_offset=fd_offset,
        file_length=int(file_length),
        block_size=int(block_size) or fs.file_block_size,
        zla=int(zla),
        num_blocks=int(num_blocks),
        pointers=pointers,
    )


def find_regfile_meta(
    fd: int, fs: FsInfo, part: GptPartition, file_length: int, limit: int = SCAN_LIMIT
) -> FileMeta:
    """Find a regular-file descriptor whose length matches ``file_length``."""
    needle = struct.pack("<I", FDMD_MAGIC)
    matches: list[FileMeta] = []
    for off in _iter_allocated_mbs(fd, limit):
        chunk = os.pread(fd, FILE_BLOCK_SIZE, off)
        idx = 0
        while True:
            pos = chunk.find(needle, idx)
            if pos < 0:
                break
            if pos >= 0x64:
                fd_off = off + pos - 0x64 - fs.md_alignment
                if fd_off < 0:
                    idx = pos + 1
                    continue
                meta = _read_file_meta(fd, fd_off, fs)
                if meta is not None and meta.file_length == file_length:
                    matches.append(meta)
            idx = pos + 1
    if not matches:
        raise RuntimeError(
            f"no VMFS regular file of length {file_length} found on the LUN"
        )
    if len(matches) > 1:
        LOG.warning(
            "multiple VMFS files of length %s; using offset %#x",
            file_length,
            matches[0].fd_offset,
        )
    return matches[0]


def _file_block_base(part: GptPartition, file_block_size: int) -> int:
    """Return the LUN offset of small-file-block 0.

    File blocks start after the GPT partition header, the 1 MiB LVM
    label, and 16 × 1 MiB heartbeat slots.
    """
    return part.start_bytes + LVM_OFFSET + HEARTBEAT_COUNT * file_block_size


def _block_lun_offset(
    address: int,
    part: GptPartition,
    fs: FsInfo,
    sfb_rpc: int,
) -> int | None:
    kind = _addr_type(address)
    shift = _file_block_shift(fs.file_block_size)
    base = _file_block_base(part, fs.file_block_size)
    if kind == ADDR_SFB:
        return base + sfb_volume_offset(address, sfb_rpc, shift)
    if kind == ADDR_LFB:
        lfb_shift = fs.sfb_to_lfb_shift or 9
        return base + lfb_volume_offset(address, shift, lfb_shift)
    return None


def _read_pointer_array(fd: int, lun_offset: int, count: int) -> list[int]:
    data = os.pread(fd, count * 8, lun_offset)
    return _unpack_u64s(data)[:count]


def _is_data_block_addr(address: int) -> bool:
    return address != 0 and _addr_type(address) in (ADDR_SFB, ADDR_LFB)


def _scan_pointer_block_array(fd: int, nblocks: int, limit: int) -> list[int]:
    """Find a uint64 SFB/LFB pointer array when inode pointers are sub-blocks."""
    slot = 65536
    slots: list[tuple[int, list[int]]] = []
    for off in _iter_allocated_mbs(fd, limit):
        chunk = os.pread(fd, FILE_BLOCK_SIZE, off)
        for start in range(0, FILE_BLOCK_SIZE, slot):
            vals = _unpack_u64s(chunk[start : start + slot])
            score = sum(1 for val in vals if _is_data_block_addr(val))
            if score >= 512:
                slots.append((off + start, vals))
    if not slots:
        return []
    slots.sort(key=lambda item: item[0])
    best: list[int] = []
    run: list[int] = []
    run_off: int | None = None
    for off, vals in slots:
        if run_off is not None and off != run_off + slot:
            if len(run) > len(best):
                best = run
            run = []
        run.extend(vals)
        run_off = off
    if len(run) > len(best):
        best = run
    while best and not _is_data_block_addr(best[0]):
        best.pop(0)
    if sum(1 for val in best[:nblocks] if _is_data_block_addr(val)) < min(nblocks, 2):
        return []
    if len(best) < nblocks:
        best.extend([0] * (nblocks - len(best)))
    return best[:nblocks]


def _expand_pointers(
    fd: int,
    meta: FileMeta,
    part: GptPartition,
    fs: FsInfo,
    sfb_rpc: int,
) -> list[int]:
    """Return per-file-block addresses (SFB/LFB), following one pointer level."""
    block_size = meta.block_size or fs.file_block_size
    nblocks = max(meta.num_blocks, (meta.file_length + block_size - 1) // block_size)
    ptrs = list(meta.pointers)
    if meta.zla in (ZLA_FILE_BLOCK, ZLA_SUB_BLOCK, 0):
        return ptrs[:nblocks]
    if meta.zla in (ZLA_POINTER_BLOCK, ZLA_POINTER2_BLOCK):
        if any(_addr_type(ptr) == ADDR_SB for ptr in ptrs if ptr):
            scanned = _scan_pointer_block_array(fd, nblocks, SCAN_LIMIT)
            if scanned:
                return scanned
        expanded: list[int] = []
        remaining = nblocks
        for ptr in ptrs:
            if remaining <= 0:
                break
            if ptr == 0:
                expanded.extend([0] * min(remaining, 8192))
                remaining -= min(remaining, 8192)
                continue
            lun = _block_lun_offset(ptr, part, fs, sfb_rpc)
            if lun is None:
                LOG.debug("SAN pointer %#x is not an SFB/LFB; stopping expand", ptr)
                break
            chunk = _read_pointer_array(
                fd, lun, min(remaining, fs.file_block_size // 8)
            )
            expanded.extend(chunk)
            remaining -= len(chunk)
        if sum(1 for addr in expanded if addr) >= min(nblocks, 2):
            return expanded[:nblocks]
        scanned = _scan_pointer_block_array(fd, nblocks, SCAN_LIMIT)
        if scanned:
            return scanned
        return expanded[:nblocks]
    return ptrs[:nblocks]


def extents_from_file_meta(
    fd: int,
    meta: FileMeta,
    part: GptPartition,
    fs: FsInfo,
    sfb_rpc: int,
) -> list[Extent]:
    """Build a file-offset map from a VMFS file descriptor."""
    block_size = meta.block_size or fs.file_block_size
    addresses = _expand_pointers(fd, meta, part, fs, sfb_rpc)
    extents: list[Extent] = []
    for index, address in enumerate(addresses):
        if not address:
            continue
        lun = _block_lun_offset(address, part, fs, sfb_rpc)
        if lun is None:
            continue
        file_off = index * block_size
        if file_off >= meta.file_length:
            break
        length = min(block_size, meta.file_length - file_off)
        extents.append(Extent(file_offset=file_off, lun_offset=lun, length=length))
    return _coalesce_extents(extents, meta.file_length)


def _coalesce_extents(extents: list[Extent], capacity_bytes: int) -> list[Extent]:
    clipped: list[Extent] = []
    for extent in extents:
        if extent.file_offset >= capacity_bytes:
            continue
        length = min(extent.length, capacity_bytes - extent.file_offset)
        if not clipped:
            clipped.append(Extent(extent.file_offset, extent.lun_offset, length))
            continue
        prev = clipped[-1]
        if (
            prev.file_offset + prev.length == extent.file_offset
            and prev.lun_offset + prev.length == extent.lun_offset
        ):
            clipped[-1] = Extent(
                prev.file_offset, prev.lun_offset, prev.length + length
            )
        else:
            clipped.append(Extent(extent.file_offset, extent.lun_offset, length))
    return clipped


def map_file_range(
    extents: Iterable[Extent], file_offset: int, length: int
) -> list[Extent]:
    """Clip ``extents`` to the file range ``[file_offset, file_offset+length)``."""
    end = file_offset + length
    hits: list[Extent] = []
    for extent in extents:
        ext_end = extent.file_offset + extent.length
        if ext_end <= file_offset or extent.file_offset >= end:
            continue
        start = max(file_offset, extent.file_offset)
        stop = min(end, ext_end)
        shift = start - extent.file_offset
        hits.append(
            Extent(
                file_offset=start,
                lun_offset=extent.lun_offset + shift,
                length=stop - start,
            )
        )
    return hits


def _pread_all(fd: int, size: int, offset: int) -> bytes:
    chunks = bytearray()
    remaining = size
    pos = offset
    while remaining:
        data = os.pread(fd, remaining, pos)
        if not data:
            raise OSError(f"short read at offset {pos}: got {len(chunks)} of {size}")
        chunks.extend(data)
        remaining -= len(data)
        pos += len(data)
    return bytes(chunks)


def _pwrite_all(fd: int, data: bytes, offset: int) -> None:
    remaining = memoryview(data)
    pos = offset
    while remaining:
        written = os.pwrite(fd, remaining, pos)
        if written <= 0:
            raise OSError(f"short write at offset {pos}")
        remaining = remaining[written:]
        pos += written


class SanDisk:
    """A VMDK opened as VMFS file extents on a local SCSI disk."""

    def __init__(
        self,
        fd: int,
        dev_path: str,
        extents: list[Extent],
        capacity_bytes: int,
        sector_size: int = SECTOR_SIZE,
    ) -> None:
        """Wrap an open LUN fd and a VMFS file extent map.

        Args:
            fd: File descriptor for the whole SCSI disk.
            dev_path: Local path such as ``/dev/sdb``.
            extents: Allocated VMFS file-block map.
            capacity_bytes: Virtual size of the VMDK.
            sector_size: Sector size in bytes (VDDK uses 512).
        """
        self._fd = fd
        self.dev_path = dev_path
        self.extents = extents
        self.capacity_bytes = capacity_bytes
        self.sector_size = sector_size
        self._closed = False

    def readinto(
        self,
        start_sector: int,
        num_sectors: int,
        buf: bytearray | memoryview,
        skip_decompression: bool = False,
    ) -> ReadResult:
        """Read ``num_sectors`` into ``buf`` starting at ``start_sector``.

        Unmapped VMFS file blocks are returned as zeros. ``fragments`` is
        always empty.

        Args:
            start_sector: Sector offset from the start of the virtual disk.
            num_sectors: Number of sectors to read.
            buf: Destination buffer.
            skip_decompression: Ignored; accepted for API compatibility.
        """
        del skip_decompression
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        length = num_sectors * self.sector_size
        view = buf if isinstance(buf, memoryview) else memoryview(buf)
        if view.readonly:
            raise TypeError("read buffer is read-only")
        raw = view.cast("B") if view.format != "B" else view
        if len(raw) < length:
            raise RuntimeError(f"read buffer is {len(raw)} bytes, need {length}")
        file_off = start_sector * self.sector_size
        raw[:length] = b"\x00" * length
        for extent in map_file_range(self.extents, file_off, length):
            data = _pread_all(self._fd, extent.length, extent.lun_offset)
            dest = extent.file_offset - file_off
            raw[dest : dest + extent.length] = data
        return ReadResult(
            uncompressed_length=length, compressed_length=length, fragments=()
        )

    def write(self, start_sector: int, num_sectors: int, data: bytes) -> None:
        """Write ``num_sectors`` starting at ``start_sector``.

        Args:
            start_sector: Sector offset from the start of the virtual disk.
            num_sectors: Number of sectors to write.
            data: Bytes to write; length must be ``num_sectors * sector_size``.
        """
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        length = num_sectors * self.sector_size
        if len(data) != length:
            raise ValueError(f"write data is {len(data)} bytes, need {length}")
        file_off = start_sector * self.sector_size
        mapped = map_file_range(self.extents, file_off, length)
        covered = sum(extent.length for extent in mapped)
        if covered != length:
            raise RuntimeError(
                "SAN write needs allocated VMFS file blocks for the whole "
                f"range (mapped {covered} of {length} bytes)"
            )
        payload = memoryview(data)
        for extent in mapped:
            src = extent.file_offset - file_off
            _pwrite_all(
                self._fd,
                payload[src : src + extent.length].tobytes(),
                extent.lun_offset,
            )
        os.fsync(self._fd)

    def close(self) -> None:
        """Close the LUN file descriptor."""
        if self._closed:
            return
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._closed = True

    def __enter__(self) -> SanDisk:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _find_datastore(si: vim.ServiceInstance, name: str) -> vim.Datastore:
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.Datastore], True
    )
    try:
        for datastore in container.view:
            if datastore.name == name:
                return datastore
    finally:
        container.Destroy()
    raise RuntimeError(f"datastore {name!r} not found")


def _disk_on_vm(source_vm: vim.VirtualMachine, disk_path: str) -> None:
    devices = source_vm.config.hardware.device if source_vm.config else []
    for device in devices:
        backing = getattr(device, "backing", None)
        if backing is not None and getattr(backing, "fileName", None) == disk_path:
            return
    raise RuntimeError(f"{disk_path} is not a virtual disk of {source_vm._moId}")


def open_disk(
    si: vim.ServiceInstance,
    source_vm: vim.VirtualMachine,
    disk_path: str,
    snapshot_ref: str | None = None,
    read_only: bool = True,
) -> SanDisk:
    """Open ``disk_path`` from a locally visible VMFS LUN.

    Args:
        si: Logged-in VIM session.
        source_vm: VM that owns ``disk_path``.
        disk_path: Datastore path of the VMDK descriptor.
        snapshot_ref: Unused; snapshot chains are not implemented.
        read_only: Open the LUN read-only when True.
    """
    del snapshot_ref
    if not is_available():
        raise RuntimeError("SAN transport requires a Linux host with SCSI disks")
    ds_name, relpath = parse_datastore_path(disk_path)
    datastore = _find_datastore(si, ds_name)
    naa = vmfs_extent_naa(datastore)
    expected_uuid = vmfs_uuid(datastore)
    _disk_on_vm(source_vm, disk_path)
    dev_path = find_local_device(naa)
    flags = os.O_RDONLY if read_only else os.O_RDWR
    fd = os.open(dev_path, flags)
    try:
        _flush_block_device(fd)
        part = parse_gpt_vmfs(fd)
        lvm = os.pread(fd, 4, part.start_bytes + LVM_OFFSET)
        (lvm_magic,) = struct.unpack_from("<I", lvm, 0)
        if lvm_magic != LVM_MAGIC:
            raise RuntimeError(f"VMFS LVM magic mismatch: {lvm_magic:#x}")
        fs = read_fs_info(fd, part)
        if fs.uuid.replace("-", "") not in expected_uuid.replace("-", ""):
            LOG.warning(
                "VMFS UUID %s does not contain vCenter uuid %s", fs.uuid, expected_uuid
            )
        _descr_off, descr_text = find_vmdk_descriptor(fd, relpath)
        capacity_sectors, _flat = parse_vmdk_descriptor(descr_text)
        capacity_bytes = capacity_sectors * SECTOR_SIZE
        sfb_rpc = _find_fbb_rpc(fd, part, fs, SCAN_LIMIT)
        meta = find_regfile_meta(fd, fs, part, capacity_bytes)
        extents = extents_from_file_meta(fd, meta, part, fs, sfb_rpc)
        LOG.info(
            "SAN open %s on %s naa=%s uuid=%s extents=%s capacity=%s zla=%s",
            disk_path,
            dev_path,
            naa,
            fs.uuid,
            len(extents),
            capacity_bytes,
            meta.zla,
        )
        return SanDisk(fd, dev_path, extents, capacity_bytes)
    except Exception:
        os.close(fd)
        raise
