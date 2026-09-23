# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Unit tests for the OPEN_FILE reply parsing in ``nfc_open``."""

import pytest

from openvixdisklib import nfc_open


class TestDecodeAllocatedBitmap:
    def test_merges_contiguous_runs(self) -> None:
        """Contiguous set bits become one run; gaps split into separate ones."""
        # chunks: 1,1,1,1,0,0,0,0,1,1 (10 chunks -> 2 bytes, LSB-first)
        bitmap = bytes([0b00001111, 0b00000011])
        blocks = nfc_open._decode_allocated_bitmap(
            bitmap, chunk_count=10, start_sector=1000, chunk_size_sectors=128
        )
        assert blocks == (
            nfc_open.AllocatedBlock(offset=1000, length=4 * 128),
            nfc_open.AllocatedBlock(offset=1000 + 8 * 128, length=2 * 128),
        )

    def test_all_zero_bitmap_returns_no_blocks(self) -> None:
        """A bitmap with no set bits produces an empty result."""
        blocks = nfc_open._decode_allocated_bitmap(
            bytes(4), chunk_count=16, start_sector=0, chunk_size_sectors=128
        )
        assert blocks == ()

    def test_run_extending_to_the_end_is_closed(self) -> None:
        """A run of set bits reaching the last chunk is still reported."""
        # chunks: 0,1,1,1 (4 chunks, 1 byte; only lower nibble meaningful)
        bitmap = bytes([0b00001110])
        blocks = nfc_open._decode_allocated_bitmap(
            bitmap, chunk_count=4, start_sector=0, chunk_size_sectors=1
        )
        assert blocks == (nfc_open.AllocatedBlock(offset=1, length=3),)

    def test_ignores_bits_beyond_chunk_count(self) -> None:
        """Padding bits past chunk_count (from 4-byte reply alignment) are unused."""
        # 2 real chunks (both set) + 2 padding bytes with garbage bits set.
        bitmap = bytes([0b00000011, 0xFF, 0xFF, 0xFF])
        blocks = nfc_open._decode_allocated_bitmap(
            bitmap, chunk_count=2, start_sector=0, chunk_size_sectors=128
        )
        assert blocks == (nfc_open.AllocatedBlock(offset=0, length=256),)


class TestQueryAllocatedBlocksValidation:
    def _disk(self) -> nfc_open.NfcDisk:
        return nfc_open.NfcDisk(
            sock=None, path="[ds] a.vmdk", handle=1, sector_size=512
        )

    def test_num_sectors_not_a_multiple_raises(self) -> None:
        with pytest.raises(ValueError, match="num_sectors must be a multiple"):
            self._disk().query_allocated_blocks(0, 100, chunk_size_sectors=128)

    def test_start_sector_not_a_multiple_raises(self) -> None:
        with pytest.raises(ValueError, match="start_sector must be a multiple"):
            self._disk().query_allocated_blocks(100, 128, chunk_size_sectors=128)
