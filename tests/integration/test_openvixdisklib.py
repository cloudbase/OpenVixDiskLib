# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise the VDDK-compatible openvixdisklib handle against the lab."""

import zlib
from typing import Any

import pytest
from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import fastlz, nfc_open
from openvixdisklib import openvixdisklib as vixdisklib
from openvixdisklib.openvixdisklib import ReadResult
from tests.integration.base import (
    _DISK_CAPACITY_KB,
    SECTOR_AT_1GB,
    SECTOR_SIZE,
    LabEnv,
    _connect_vim,
    _wait_for_task,
    pattern_bytes,
    sparse_bytes,
)


def _virtual_disk_backing(
    vm: vim.VirtualMachine,
) -> vim.vm.device.VirtualDevice.BackingInfo:
    """Return the lab VM's first virtual disk backing."""
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualDisk):
            return device.backing
    raise AssertionError(f"{vm._moId} has no virtual disk")


_2MIB = 2 * 1024 * 1024


def _rebuild_skip(buf: Any, result: ReadResult) -> bytes:
    """Decompress packed skip-decompression extras into uncompressed bytes."""
    view = buf.raw if hasattr(buf, "raw") else buf
    out = bytearray(result.uncompressed_length)
    packed = 0
    for frag in result.fragments:
        extra = bytes(view[frag.offset : frag.offset + frag.length])
        packed += frag.length
        if frag.compression_type == nfc_open.NFC_COMPRESSION_FASTLZ:
            chunk = fastlz.decompress(extra, frag.uncompressed_length)
        elif frag.compression_type == nfc_open.NFC_COMPRESSION_ZLIB:
            chunk = zlib.decompress(extra)
        elif frag.compression_type == nfc_open.NFC_COMPRESSION_SKIPZ:
            chunk = nfc_open._skipz_decompress(extra, frag.uncompressed_length)
        elif frag.compression_type == nfc_open.NFC_COMPRESSION_NONE:
            chunk = extra
        else:
            raise AssertionError(f"unexpected compression_type {frag.compression_type}")
        assert len(chunk) == frag.uncompressed_length
        out[frag.dest : frag.dest + frag.uncompressed_length] = chunk
    assert packed == result.compressed_length
    return bytes(out)


class TestOpenvixdisklib:
    @pytest.mark.parametrize("transport_mode", ["nbdssl", "nbd"])
    @pytest.mark.parametrize(
        "open_flags",
        [
            0,
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ,
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB,
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ,
        ],
        ids=["plain", "fastlz", "zlib", "skipz"],
    )
    def test_write_and_read_sector_zero_and_one_gib(
        self, lab: LabEnv, transport_mode: str, open_flags: int
    ) -> None:
        """Write then read sector 0 and the sector at a 1 GiB offset."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        connect_kwargs = lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": lab.allow_untrusted,
                "transport_modes": transport_mode,
            }
        )
        patterns = {
            0: pattern_bytes(SECTOR_SIZE, b"OVDL-S0"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"OVDL-1GB"),
        }
        assert handle.get_transport_modes() == ["nbdssl", "nbd"]
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(conn, lab.disk_path, flags=open_flags) as disk,
        ):
            assert handle.get_transport_mode(disk) == transport_mode
            for start, expected in patterns.items():
                write_buf[:SECTOR_SIZE] = expected
                handle.write(disk, start, 1, write_buf)
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, start, 1, read_buf)
                assert read_buf.raw[:SECTOR_SIZE] == expected

    def test_get_info(self, lab: LabEnv) -> None:
        """get_info returns the lab VM's known disk capacity and geometry."""
        handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
        connect_kwargs = lab.vixdisklib_connect_kwargs(
            {"allow_untrusted": lab.allow_untrusted, "read_only": True}
        )
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(
                conn, lab.disk_path, flags=vixdisklib.VIXDISKLIB_FLAG_OPEN_READ_ONLY
            ) as disk,
        ):
            info = handle.get_info(disk)
            assert info.capacity_sectors == _DISK_CAPACITY_KB * 1024 // SECTOR_SIZE
            assert info.phys_geo.cylinders > 0
            assert info.phys_geo.heads > 0
            assert info.phys_geo.sectors > 0
            # bios_geo is DDB-derived and unset (all zero) on a disk with
            # no snapshots yet, matching VDDK's own default for a missing key.
            assert info.bios_geo == vixdisklib.DiskGeometry(
                cylinders=0, heads=0, sectors=0
            )
            assert info.adapter_type  # non-empty DDB string, e.g. "lsilogic"
            assert info.uuid  # non-empty DDB string

    def test_query_allocated_blocks(self, lab: LabEnv) -> None:
        """A written sector's chunk shows up as an allocated run."""
        handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
        chunk_size_sectors = 128
        # Chunk-aligned offset away from what other tests in this shared
        # session-scoped VM write to (sector 0, SECTOR_AT_1GB, ...).
        write_sector = 300 * chunk_size_sectors
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        write_buf[:SECTOR_SIZE] = pattern_bytes(SECTOR_SIZE, b"OVDL-QAB")
        connect_kwargs = lab.vixdisklib_connect_kwargs(
            {"allow_untrusted": lab.allow_untrusted}
        )
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(conn, lab.disk_path, flags=0) as disk,
        ):
            handle.write(disk, write_sector, 1, write_buf)
            blocks = handle.query_allocated_blocks(
                disk,
                start_sector=(write_sector // chunk_size_sectors) * chunk_size_sectors,
                num_sectors=chunk_size_sectors,
                chunk_size_sectors=chunk_size_sectors,
            )
            assert any(
                b.offset <= write_sector < b.offset + b.length for b in blocks
            ), f"written sector {write_sector} not covered by {blocks}"

    def test_read_only_open_snapshot_parent(self, lab: LabEnv) -> None:
        """Read-only Open uses NfcGetVmFiles, including a snapshot parent path.

        After a snapshot the attached leaf is a new delta (``…-000001.vmdk``)
        while backup tools open the parent file. That path is not
        ``device.backing.fileName``; VDDK still opens it with a VM-only
        ticket and NFC ``OPEN_FILE``.
        """
        handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
        expected = pattern_bytes(SECTOR_SIZE, b"OVDL-RO")
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        write_buf[:SECTOR_SIZE] = expected
        write_kwargs = lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": lab.allow_untrusted,
            }
        )
        read_kwargs = lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": lab.allow_untrusted,
                "read_only": True,
            }
        )
        read_flags = vixdisklib.VIXDISKLIB_FLAG_OPEN_READ_ONLY

        def read_sector(path: str) -> bytes:
            with (
                handle.connect(**read_kwargs) as conn,
                handle.open(conn, path, flags=read_flags) as disk,
            ):
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, 0, 1, read_buf)
            return read_buf.raw[:SECTOR_SIZE]

        with (
            handle.connect(**write_kwargs) as conn,
            handle.open(conn, lab.disk_path, flags=0) as disk,
        ):
            handle.write(disk, 0, 1, write_buf)

        assert read_sector(lab.disk_path) == expected

        si = _connect_vim(
            lab.host,
            lab.username,
            lab.password,
            lab.port,
            lab.thumbprint,
            lab.allow_untrusted,
        )
        try:
            vm = vim.VirtualMachine(lab.vm_moref, si._stub)
            _wait_for_task(vm.CreateSnapshot_Task("ovdl-readonly", "", False, False))
            backing = _virtual_disk_backing(vm)
            parent = getattr(backing, "parent", None)
            assert parent is not None
            assert parent.fileName == lab.disk_path
            assert backing.fileName != parent.fileName
            assert read_sector(parent.fileName) == expected
        finally:
            try:
                vm = vim.VirtualMachine(lab.vm_moref, si._stub)
                if vm.snapshot is not None:
                    _wait_for_task(vm.RemoveAllSnapshots_Task())
            finally:
                Disconnect(si)

    def test_write_and_query_allocated_blocks_on_delta_disk(self, lab: LabEnv) -> None:
        """Read/write/query all work directly on a post-snapshot delta file.

        ``NFC_DELTA_DISK`` (an alternate OPEN_FILE file-type value,
        per ``strings`` on ``libvixDiskLib.so``) turned out to be an
        optional VMFS-only VDDK client optimization, not needed for
        correctness — this exercises the plain ``NFC_DISK`` path
        against an actual delta file. See
        ``docs/reverse_engineering_procedure.md``.

        Also covers the gotcha documented in ``docs/nfc_read.md``:
        querying allocated blocks on the *same still-open* handle a
        write just went through can see stale (pre-write) data: the
        write below is done in its own ``with`` block, closed, before
        the separate query.
        """
        handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
        chunk_size_sectors = 128
        write_sector = 400 * chunk_size_sectors
        expected = pattern_bytes(SECTOR_SIZE, b"OVDL-DELTA")
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        write_buf[:SECTOR_SIZE] = expected
        connect_kwargs = lab.vixdisklib_connect_kwargs(
            {"allow_untrusted": lab.allow_untrusted}
        )
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)

        si = _connect_vim(
            lab.host,
            lab.username,
            lab.password,
            lab.port,
            lab.thumbprint,
            lab.allow_untrusted,
        )
        try:
            vm = vim.VirtualMachine(lab.vm_moref, si._stub)
            _wait_for_task(vm.CreateSnapshot_Task("ovdl-delta", "", False, False))
            delta_path = _virtual_disk_backing(vm).fileName
            assert delta_path != lab.disk_path

            with (
                handle.connect(**connect_kwargs) as conn,
                handle.open(conn, delta_path, flags=0) as disk,
            ):
                handle.write(disk, write_sector, 1, write_buf)

            # Fresh handle after close, per the gotcha above.
            with (
                handle.connect(**connect_kwargs) as conn,
                handle.open(conn, delta_path, flags=0) as disk,
            ):
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, write_sector, 1, read_buf)
                assert read_buf.raw[:SECTOR_SIZE] == expected

                blocks = handle.query_allocated_blocks(
                    disk,
                    start_sector=(write_sector // chunk_size_sectors)
                    * chunk_size_sectors,
                    num_sectors=chunk_size_sectors,
                    chunk_size_sectors=chunk_size_sectors,
                )
                assert any(
                    b.offset <= write_sector < b.offset + b.length for b in blocks
                ), (
                    f"written sector {write_sector} on delta file not covered by {blocks}"
                )
        finally:
            try:
                vm = vim.VirtualMachine(lab.vm_moref, si._stub)
                if vm.snapshot is not None:
                    _wait_for_task(vm.RemoveAllSnapshots_Task())
            finally:
                Disconnect(si)

    @pytest.mark.parametrize(
        "open_flags",
        [
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ,
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB,
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ,
        ],
        ids=["fastlz", "zlib", "skipz"],
    )
    @pytest.mark.parametrize(
        "aio_buffer_size, n_sectors, n_fragments",
        [
            (nfc_open.NFC_AIO_BUFFER_SIZE, 128, 1),
            (nfc_open.NFC_AIO_BUFFER_SIZE, 129, 2),
            (_2MIB, 129, 1),
        ],
        ids=["64kib-128s", "64kib-129s", "2mib-129s"],
    )
    def test_skip_decompression(
        self,
        lab: LabEnv,
        open_flags: int,
        aio_buffer_size: int,
        n_sectors: int,
        n_fragments: int,
    ) -> None:
        """Pack compressed extras and rebuild the same bytes as a normal read."""
        length = n_sectors * SECTOR_SIZE
        if open_flags == vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ:
            expected = sparse_bytes(length, b"OVDL-SKIPZ-")
        else:
            expected = pattern_bytes(length, b"OVDL-SKIP-")
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        write_buf = vixdisklib.get_buffer(length)
        plain_buf = vixdisklib.get_buffer(length)
        skip_buf = vixdisklib.get_buffer(length)
        write_buf[:length] = expected
        connect_kwargs = lab.vixdisklib_connect_kwargs(
            {"allow_untrusted": lab.allow_untrusted, "transport_modes": "nbd"}
        )
        expected_ctype = {
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ: (
                nfc_open.NFC_COMPRESSION_FASTLZ
            ),
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB: (
                nfc_open.NFC_COMPRESSION_ZLIB
            ),
            vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ: (
                nfc_open.NFC_COMPRESSION_SKIPZ
            ),
        }[open_flags]
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(
                conn,
                lab.disk_path,
                flags=open_flags,
                aio_buffer_size=aio_buffer_size,
                aio_buffer_count=1,
            ) as disk,
        ):
            handle.write(disk, 0, n_sectors, write_buf)
            plain = handle.read(disk, 0, n_sectors, plain_buf)
            skip = handle.read(disk, 0, n_sectors, skip_buf, skip_decompression=True)
        assert isinstance(plain, ReadResult)
        assert plain.fragments == ()
        assert plain.uncompressed_length == length
        assert plain.compressed_length <= length
        assert skip.uncompressed_length == length
        assert skip.compressed_length <= length
        assert skip.compressed_length == plain.compressed_length
        assert len(skip.fragments) == n_fragments
        dests = {frag.dest for frag in skip.fragments}
        if n_fragments == 1:
            assert dests == {0}
        else:
            assert dests == {0, nfc_open.NFC_AIO_BUFFER_SIZE}
        assert any(
            frag.compression_type == expected_ctype for frag in skip.fragments
        ), f"expected a {expected_ctype} fragment, got {skip.fragments}"
        assert plain_buf.raw[:length] == expected
        assert _rebuild_skip(skip_buf, skip) == expected
