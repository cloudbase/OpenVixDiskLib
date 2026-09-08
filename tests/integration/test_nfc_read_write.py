# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise NFC sector writes and reads against the lab vCenter."""

import os

import pytest

from openvixdisklib import nfc_open
from tests.integration.base import SECTOR_SIZE, LabEnv, pattern_bytes

_32MIB = 32 * 1024 * 1024


class TestNfcReadWrite:
    @pytest.mark.parametrize(
        "compression",
        [nfc_open.NFC_COMPRESSION_NONE, nfc_open.NFC_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
    )
    def test_sector_writes_and_reads(self, lab: LabEnv, compression: int) -> None:
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
        with lab.authenticate(read_only=False) as session:
            with nfc_open.open_disk(
                session, lab.disk_path, read_only=False, compression=compression
            ) as disk:
                for start, n_sectors in ranges:
                    length = n_sectors * SECTOR_SIZE
                    seed = f"NFC-R{start}:{n_sectors}-".encode()
                    to_write = pattern_bytes(length, seed)
                    disk.write(start, n_sectors, to_write)
                    got = disk.read(start, n_sectors)
                    assert got is not to_write
                    assert len(got) == length
                    assert got == to_write

                two_seed = b"NFC-TWO-SECTOR"
                two_to_write = pattern_bytes(2 * SECTOR_SIZE, two_seed)
                disk.write(0, 2, two_to_write)
                two_got = disk.read(0, 2)
                assert two_got is not two_to_write
                assert two_got == two_to_write
                assert disk.read(1, 1) == two_to_write[SECTOR_SIZE:]

                big_seed = b"NFC-129-SECTOR-WRITE"
                big_to_write = pattern_bytes(129 * SECTOR_SIZE, big_seed)
                disk.write(0, 129, big_to_write)
                big_got = disk.read(0, 129)
                assert big_got is not big_to_write
                assert big_got == big_to_write
                assert (
                    big_got[SECTOR_SIZE : 2 * SECTOR_SIZE]
                    == big_to_write[SECTOR_SIZE : 2 * SECTOR_SIZE]
                )

    @pytest.mark.parametrize(
        "compression",
        [nfc_open.NFC_COMPRESSION_NONE, nfc_open.NFC_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
    )
    def test_write_and_read_32mb(self, lab: LabEnv, compression: int) -> None:
        """Write 32 MiB (512 AIO chunks) and read it back in one request."""
        n_sectors = _32MIB // SECTOR_SIZE
        to_write = os.urandom(_32MIB)
        with lab.authenticate(read_only=False) as session:
            with nfc_open.open_disk(
                session, lab.disk_path, read_only=False, compression=compression
            ) as disk:
                disk.write(0, n_sectors, to_write)
                got = disk.read(0, n_sectors)
                assert got is not to_write
                assert len(got) == _32MIB
                assert got == to_write
