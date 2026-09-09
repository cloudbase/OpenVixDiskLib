# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise NFC disk open and a one-sector write/read against the lab."""

import pytest

from openvixdisklib import nfc_open
from tests.integration.base import SECTOR_SIZE, LabEnv, pattern_bytes


class TestNfcOpen:
    @pytest.mark.parametrize("nfc_ssl", [True, False], ids=["nbdssl", "nbd"])
    @pytest.mark.parametrize(
        "compression",
        [nfc_open.NFC_COMPRESSION_NONE, nfc_open.NFC_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
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
