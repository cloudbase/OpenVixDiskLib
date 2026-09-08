#!/usr/bin/env python3
"""One-off: VDDK write with verbose NFC logs. Not part of the library."""

import os
import sys
import unittest

sys.path.insert(0, "/home/ubuntu/workspace/vmware_nbd_tests")
os.environ.pop("LD_PRELOAD", None)
os.environ["LD_LIBRARY_PATH"] = (
    "/home/ubuntu/workspace/vmware_nbd_tests/.vddk:"
    + os.environ.get("LD_LIBRARY_PATH", ""))

from tests.integration.base import TestBase
from tests.integration import vixdisklib


class _T(TestBase):
    @classmethod
    def setUpClass(cls):
        cls.require_vddk()
        super().setUpClass()

    def test_write(self):
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path="/tmp/vddk_nfc.conf")
        buf = vixdisklib.get_buffer(self.SECTOR_SIZE)
        expected = self.pattern_bytes(self.SECTOR_SIZE, b"TRACE-S0")
        buf[:self.SECTOR_SIZE] = expected
        with handle.connect(**self.vixdisklib_connect_kwargs()) as conn:
            with handle.open(conn, self.DISK_PATH, flags=0) as disk:
                handle.write(disk, 0, 1, buf)
                handle.read(disk, 0, 1, buf)
        print("DISK_PATH", self.DISK_PATH, "ok", buf.raw[:8])


if __name__ == "__main__":
    unittest.main()
