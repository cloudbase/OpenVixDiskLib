# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise the VDDK-compatible openvixdisklib handle against the lab."""

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import (
    LabEnv, SECTOR_AT_1GB, SECTOR_SIZE, pattern_bytes)


class TestOpenvixdisklib:
    def test_write_and_read_sector_zero_and_one_gib(self, lab: LabEnv) -> None:
        """Write then read sector 0 and the sector at a 1 GiB offset."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path=None)
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        connect_kwargs = lab.vixdisklib_connect_kwargs({
            "allow_untrusted": lab.allow_untrusted,
        })
        patterns = {
            0: pattern_bytes(SECTOR_SIZE, b"OVDL-S0"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"OVDL-1GB"),
        }
        with handle.connect(**connect_kwargs) as conn:
            with handle.open(conn, lab.disk_path, flags=0) as disk:
                for start, expected in patterns.items():
                    write_buf[:SECTOR_SIZE] = expected
                    handle.write(disk, start, 1, write_buf)
                    read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                    handle.read(disk, start, 1, read_buf)
                    assert read_buf.raw[:SECTOR_SIZE] == expected
