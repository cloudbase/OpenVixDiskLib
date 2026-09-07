# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise native VDDK via tests.integration.vixdisklib against the lab."""

from tests.integration import vixdisklib
from tests.integration.base import TestBase


class VddkTest(TestBase):
    @classmethod
    def setUpClass(cls) -> None:
        """Skip when the bundled VDDK shared library is not present."""
        cls.require_vddk()
        super().setUpClass()

    def test_write_and_read_first_sector(self) -> None:
        """Open the temp VMDK with VDDK, write sector 0, and read it back."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path=None)
        write_buf = vixdisklib.get_buffer(self.SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(self.SECTOR_SIZE)
        expected = self.pattern_bytes(self.SECTOR_SIZE, b"VDDK-S0")
        write_buf[:self.SECTOR_SIZE] = expected
        with handle.connect(**self.vixdisklib_connect_kwargs()) as conn:
            with handle.open(conn, self.DISK_PATH, flags=0) as disk:
                handle.write(disk, 0, 1, write_buf)
                read_buf[:self.SECTOR_SIZE] = b"\xa5" * self.SECTOR_SIZE
                handle.read(disk, 0, 1, read_buf)
                self.assertEqual(read_buf.raw[:self.SECTOR_SIZE], expected)
