# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise the VDDK-compatible openvixdisklib handle against the lab."""

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import TestBase


class OpenVixDiskLibTest(TestBase):
    def test_write_and_read_sector_zero_and_one_gib(self) -> None:
        """Write then read sector 0 and the sector at a 1 GiB offset."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path=None)
        write_buf = vixdisklib.get_buffer(self.SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(self.SECTOR_SIZE)
        connect_kwargs = self.vixdisklib_connect_kwargs({
            "allow_untrusted": self.ALLOW_UNTRUSTED,
        })
        patterns = {
            0: self.pattern_bytes(self.SECTOR_SIZE, b"OVDL-S0"),
            self.SECTOR_AT_1GB: self.pattern_bytes(
                self.SECTOR_SIZE, b"OVDL-1GB"),
        }
        with handle.connect(**connect_kwargs) as conn:
            with handle.open(conn, self.DISK_PATH, flags=0) as disk:
                for start, expected in patterns.items():
                    write_buf[:self.SECTOR_SIZE] = expected
                    handle.write(disk, start, 1, write_buf)
                    read_buf[:self.SECTOR_SIZE] = b"\xa5" * self.SECTOR_SIZE
                    handle.read(disk, start, 1, read_buf)
                    self.assertEqual(read_buf.raw[:self.SECTOR_SIZE], expected)
