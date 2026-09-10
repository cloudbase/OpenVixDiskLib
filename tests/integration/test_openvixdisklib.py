# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise the VDDK-compatible openvixdisklib handle against the lab."""

from typing import Any

import pytest
from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import fastlz, nfc_open
from openvixdisklib import openvixdisklib as vixdisklib
from openvixdisklib.openvixdisklib import ReadResult
from tests.integration.base import (
    SECTOR_AT_1GB,
    SECTOR_SIZE,
    LabEnv,
    _connect_vim,
    _wait_for_task,
    pattern_bytes,
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
        [0, vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
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

    @pytest.mark.parametrize(
        "aio_buffer_size, n_sectors, n_fragments",
        [
            (nfc_open.NFC_AIO_BUFFER_SIZE, 128, 1),
            (nfc_open.NFC_AIO_BUFFER_SIZE, 129, 2),
            (_2MIB, 129, 1),
        ],
        ids=["64kib-128s", "64kib-129s", "2mib-129s"],
    )
    def test_skip_decompression_fastlz(
        self,
        lab: LabEnv,
        aio_buffer_size: int,
        n_sectors: int,
        n_fragments: int,
    ) -> None:
        """Pack FastLZ extras and rebuild the same bytes as a normal read."""
        length = n_sectors * SECTOR_SIZE
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
        flags = vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(
                conn,
                lab.disk_path,
                flags=flags,
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
        assert plain_buf.raw[:length] == expected
        assert _rebuild_skip(skip_buf, skip) == expected
