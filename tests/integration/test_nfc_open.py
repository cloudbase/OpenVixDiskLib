# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise NFC disk open and a one-sector write/read against the lab."""

from openvixdisklib import nfc_open
from tests.integration.base import TestBase


class NfcOpenTest(TestBase):
    def test_open_disk_and_read_first_sector(self) -> None:
        """Open the temp VMDK, write sector 0, and read it back."""
        expected = self.pattern_bytes(self.SECTOR_SIZE, b"NFC-OPEN-S0")
        with self.authenticate(read_only=False) as session:
            with nfc_open.open_disk(
                    session, self.DISK_PATH, read_only=False) as disk:
                self.assertEqual(disk.path, self.DISK_PATH)
                self.assertGreater(disk.handle, 0)
                self.assertEqual(disk.sector_size, self.SECTOR_SIZE)
                disk.write(0, 1, expected)
                got = disk.read(0, 1)
                self.assertIsNot(got, expected)
                self.assertEqual(got, expected)
