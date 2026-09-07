# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise NFC sector writes and reads against the lab vCenter."""

from openvixdisklib import nfc_open
from tests.integration.base import TestBase


class NfcReadWriteTest(TestBase):
    def test_sector_writes_and_reads(self) -> None:
        """Write known patterns and read them back at several ranges."""
        ranges = [
            (0, 1),
            (0, 2),
            (1, 1),
            (8, 8),
            (0, 128),
            (0, 129),
            (256, 64),
        ]
        with self.authenticate(read_only=False) as session:
            with nfc_open.open_disk(
                    session, self.DISK_PATH, read_only=False) as disk:
                for start, n_sectors in ranges:
                    length = n_sectors * self.SECTOR_SIZE
                    seed = f"NFC-R{start}:{n_sectors}-".encode()
                    to_write = self.pattern_bytes(length, seed)
                    disk.write(start, n_sectors, to_write)
                    got = disk.read(start, n_sectors)
                    self.assertIsNot(got, to_write)
                    self.assertEqual(len(got), length)
                    self.assertEqual(got, to_write)

                two_seed = b"NFC-TWO-SECTOR"
                two_to_write = self.pattern_bytes(
                    2 * self.SECTOR_SIZE, two_seed)
                disk.write(0, 2, two_to_write)
                two_got = disk.read(0, 2)
                self.assertIsNot(two_got, two_to_write)
                self.assertEqual(two_got, two_to_write)
                self.assertEqual(
                    disk.read(1, 1), two_to_write[self.SECTOR_SIZE:])

                big_seed = b"NFC-129-SECTOR-WRITE"
                big_to_write = self.pattern_bytes(
                    129 * self.SECTOR_SIZE, big_seed)
                disk.write(0, 129, big_to_write)
                big_got = disk.read(0, 129)
                self.assertIsNot(big_got, big_to_write)
                self.assertEqual(big_got, big_to_write)
                self.assertEqual(
                    big_got[self.SECTOR_SIZE:2 * self.SECTOR_SIZE],
                    big_to_write[self.SECTOR_SIZE:2 * self.SECTOR_SIZE])
