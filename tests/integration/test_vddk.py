# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise native VDDK via tests.integration.vixdisklib against the lab."""

from tests.integration import vixdisklib
from tests.integration.base import SECTOR_SIZE, LabEnv, pattern_bytes


class TestVddk:
    def test_write_and_read_first_sector(self, lab: LabEnv, vddk: None) -> None:
        """Open the temp VMDK with VDDK, write sector 0, and read it back."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        expected = pattern_bytes(SECTOR_SIZE, b"VDDK-S0")
        write_buf[:SECTOR_SIZE] = expected
        with (
            handle.connect(**lab.vixdisklib_connect_kwargs()) as conn,
            handle.open(conn, lab.disk_path, flags=0) as disk,
        ):
            handle.write(disk, 0, 1, write_buf)
            read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
            handle.read(disk, 0, 1, read_buf)
            assert read_buf.raw[:SECTOR_SIZE] == expected
