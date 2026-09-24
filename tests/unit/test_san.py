# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Unit tests for SAN LUN matching, VMDK naming, and extent-map I/O."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from openvixdisklib.openvixdisklib import (
    VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ,
    VixDiskLibHandle,
    _available_transports,
    _select_transport,
)
from openvixdisklib.san import (
    FILE_BLOCK_SIZE,
    SECTOR_SIZE,
    Extent,
    SanDisk,
    flat_extent_name,
    lfb_volume_offset,
    map_file_range,
    normalize_naa,
    parse_datastore_path,
    parse_lfb,
    parse_sfb,
    parse_vmdk_descriptor,
    sfb_volume_offset,
)

SECTOR_AT_1GB = (1024 * 1024 * 1024) // SECTOR_SIZE


def test_normalize_naa_from_wwn() -> None:
    """WWN and SCSI-3 names collapse to ``naa.<hex>``."""
    assert normalize_naa("wwn-0x6001405abc") == "naa.6001405abc"
    assert normalize_naa("scsi-36001405abc") == "naa.6001405abc"
    assert normalize_naa("NAA.6001405ABC") == "naa.6001405abc"


def test_parse_datastore_path() -> None:
    """Split a datastore path into name and relative path."""
    assert parse_datastore_path("[ds0] vm/vm.vmdk") == ("ds0", "vm/vm.vmdk")
    with pytest.raises(ValueError, match="unsupported disk path"):
        parse_datastore_path("vm/vm.vmdk")


def test_flat_extent_name() -> None:
    """Descriptor basename maps to the sibling ``-flat.vmdk``."""
    assert flat_extent_name("vm/disk.vmdk") == "disk-flat.vmdk"
    assert flat_extent_name("disk-flat.vmdk") == "disk-flat.vmdk"


def test_parse_vmdk_descriptor() -> None:
    """Read capacity and the VMFS extent name from a descriptor."""
    text = (
        '# Disk DescriptorFile\ncreateType="vmfs"\nRW 20971520 VMFS "disk-flat.vmdk"\n'
    )
    sectors, name = parse_vmdk_descriptor(text)
    assert sectors == 20971520
    assert name == "disk-flat.vmdk"


def test_file_block_base_after_lvm_and_heartbeats() -> None:
    """SFB 0 starts after the GPT partition, LVM label, and 16 heartbeats."""
    from openvixdisklib.san import GptPartition, _file_block_base

    part = GptPartition(start_lba=2048, end_lba=1000)
    assert _file_block_base(part, FILE_BLOCK_SIZE) == 18 * FILE_BLOCK_SIZE


def test_sfb_and_lfb_offsets() -> None:
    """VMFS6 SFB/LFB addresses decode to volume offsets."""
    cluster, resource = 33, 210
    addr = 0x1 | (cluster << 15) | (resource << 51)
    assert parse_sfb(addr) == (cluster, resource)
    assert sfb_volume_offset(addr, 512, 20) == ((33 * 512) + 210) << 20
    lfb = 0x7 | (4 << 15)
    assert parse_lfb(lfb) == 4
    assert lfb_volume_offset(lfb, 20, 9) == 4 << (20 + 9)


def test_map_file_range_clips_extents() -> None:
    """Only the overlapping part of an extent is returned."""
    extents = [
        Extent(0, 2 * FILE_BLOCK_SIZE, FILE_BLOCK_SIZE),
        Extent(FILE_BLOCK_SIZE, 5 * FILE_BLOCK_SIZE, FILE_BLOCK_SIZE),
    ]
    hits = map_file_range(extents, 512, 1024)
    assert hits == [Extent(512, 2 * FILE_BLOCK_SIZE + 512, 1024)]


def test_sandisk_pread_pwrite(tmp_path: Path) -> None:
    """SanDisk I/O uses the extent map; holes read as zeros."""
    lun_path = tmp_path / "lun.bin"
    lun_path.write_bytes(b"\x00" * (4 * FILE_BLOCK_SIZE))
    fd = os.open(lun_path, os.O_RDWR)
    extents = [Extent(0, 2 * FILE_BLOCK_SIZE, FILE_BLOCK_SIZE)]
    disk = SanDisk(fd, str(lun_path), extents, 10 * 1024 * 1024 * 1024)
    pattern = b"A" * SECTOR_SIZE
    disk.write(0, 1, pattern)
    buf = bytearray(SECTOR_SIZE)
    result = disk.readinto(0, 1, buf, skip_decompression=True)
    assert bytes(buf) == pattern
    assert result.uncompressed_length == SECTOR_SIZE
    assert result.fragments == ()
    hole = bytearray(b"\xa5" * SECTOR_SIZE)
    disk.readinto(SECTOR_AT_1GB, 1, hole)
    assert bytes(hole) == b"\x00" * SECTOR_SIZE
    with pytest.raises(RuntimeError, match="allocated VMFS"):
        disk.write(SECTOR_AT_1GB, 1, b"B" * SECTOR_SIZE)
    disk.close()
    disk.close()


class TestSelectTransportSan:
    @mock.patch(
        "openvixdisklib.openvixdisklib.hotadd.is_vmware_guest", return_value=False
    )
    @mock.patch("openvixdisklib.openvixdisklib.san.is_available", return_value=True)
    def test_colon_list_selects_san(
        self, mock_san: mock.MagicMock, mock_guest: mock.MagicMock
    ) -> None:
        """A host with SCSI disks uses san when it is first in the colon list."""
        del mock_san, mock_guest
        assert _select_transport("file:san:hotadd:nbdssl:nbd") == "san"
        assert _available_transports() == ["nbdssl", "nbd", "san"]

    @mock.patch(
        "openvixdisklib.openvixdisklib.hotadd.is_vmware_guest", return_value=False
    )
    @mock.patch("openvixdisklib.openvixdisklib.san.is_available", return_value=False)
    def test_san_alone_raises_when_unavailable(
        self, mock_san: mock.MagicMock, mock_guest: mock.MagicMock
    ) -> None:
        """``san`` alone raises when the host has no SCSI sysfs."""
        del mock_san, mock_guest
        with pytest.raises(NotImplementedError, match="san"):
            _select_transport("san")

    def test_default_is_nbdssl(self) -> None:
        """None still defaults to nbdssl when SAN is available."""
        assert _select_transport(None) == "nbdssl"


@mock.patch("openvixdisklib.openvixdisklib.vim.VirtualMachine")
def test_fastlz_open_flag_rejected_for_san(mock_vm: mock.MagicMock) -> None:
    """FastLZ open flags are rejected the same way as HotAdd."""
    del mock_vm
    handle = VixDiskLibHandle()
    conn = mock.Mock()
    conn.transport_mode = "san"
    conn.read_only = False
    conn.vm_moref = "vm-1"
    conn.si = mock.Mock()
    conn.snapshot_ref = None
    with (
        pytest.raises(NotImplementedError, match="san"),
        handle.open(
            conn, "[ds] vm/vm.vmdk", flags=VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ
        ),
    ):
        pass
