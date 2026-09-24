# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise NFC disk open and a one-sector write/read against the lab."""

import pytest

from openvixdisklib import nfc_open
from tests.integration.base import _DISK_CAPACITY_KB, SECTOR_SIZE, LabEnv, pattern_bytes


class TestNfcOpen:
    @pytest.mark.parametrize("nfc_ssl", [True, False], ids=["nbdssl", "nbd"])
    @pytest.mark.parametrize(
        "compression",
        [
            nfc_open.NFC_COMPRESSION_NONE,
            nfc_open.NFC_COMPRESSION_FASTLZ,
            nfc_open.NFC_COMPRESSION_ZLIB,
            nfc_open.NFC_COMPRESSION_SKIPZ,
        ],
        ids=["plain", "fastlz", "zlib", "skipz"],
    )
    def test_open_disk_and_read_first_sector(
        self, lab: LabEnv, nfc_ssl: bool, compression: int
    ) -> None:
        """Open the temp VMDK, write sector 0, and read it back."""
        expected = pattern_bytes(SECTOR_SIZE, b"NFC-OPEN-S0")
        with (
            lab.authenticate(read_only=False, nfc_ssl=nfc_ssl) as session,
            nfc_open.open_disk(
                session, lab.disk_path, read_only=False, compression=compression
            ) as disk,
        ):
            assert disk.path == lab.disk_path
            assert disk.handle > 0
            assert disk.sector_size == SECTOR_SIZE
            disk.write(0, 1, expected)
            got = disk.read(0, 1)
            assert got is not expected
            assert got == expected

    def test_open_disk_reports_capacity_and_geometry(self, lab: LabEnv) -> None:
        """OPEN_FILE's reply carries capacity and physical geometry (GetInfo)."""
        with (
            lab.authenticate() as session,
            nfc_open.open_disk(session, lab.disk_path) as disk,
        ):
            assert disk.info is not None
            assert disk.info.capacity_sectors == (
                _DISK_CAPACITY_KB * 1024 // SECTOR_SIZE
            )
            geo = disk.info.phys_geo
            assert geo.cylinders > 0
            assert geo.heads > 0
            assert geo.sectors > 0
