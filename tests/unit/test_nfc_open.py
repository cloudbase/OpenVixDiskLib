# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Unit tests for the OPEN_FILE reply parsing in ``nfc_open``."""

import struct

import pytest

from openvixdisklib import nfc_open


class _FakeSocket:
    """A minimal socket stand-in that replays scripted bytes for recv_into."""

    def __init__(self, replies: bytes) -> None:
        self._replies = replies
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv_into(self, buffer: memoryview, nbytes: int = 0, flags: int = 0) -> int:
        del nbytes, flags
        n = min(len(buffer), len(self._replies))
        buffer[:n] = self._replies[:n]
        self._replies = self._replies[n:]
        return n

    def close(self) -> None:
        pass


def _open_reply_body(
    handle: int = 0x1234,
    file_type: int = nfc_open.NFC_DISK,
    flags: int = nfc_open.NFC_OPEN_FLAGS_READ_ONLY,
    capacity_bytes: int = 17179869184,
    sector_size: int = 512,
    cylinders: int = 2088,
    heads: int = 255,
    sectors: int = 63,
) -> bytes:
    """Build a synthetic 60-byte OPEN_FILE reply payload."""
    body = bytearray(60)
    struct.pack_into("<QII", body, 8, handle, file_type, flags)
    struct.pack_into("<Q", body, 28, capacity_bytes)
    struct.pack_into("<I", body, 36, sector_size)
    struct.pack_into("<III", body, 40, cylinders, heads, sectors)
    return bytes(body)


def _ddb_get_reply(op_id: int, value: bytes | None) -> bytes:
    """Build a scripted DDB_GET reply: header + 16-byte body + value extra."""
    value_length = len(value) if value is not None else 0
    body = bytes(12) + struct.pack("<I", value_length)
    return (
        nfc_open._pack_aio_hdr(nfc_open.NFC_AIO_MSG_DDB_GET, 16, op_id)
        + body
        + (value or b"")
    )


class TestDdbGet:
    def _disk(self, replies: bytes) -> nfc_open.NfcDisk:
        return nfc_open.NfcDisk(
            sock=_FakeSocket(replies),
            path="[ds] a.vmdk",
            handle=0x1234,
            sector_size=512,
        )

    def test_found_key_returns_decoded_value(self) -> None:
        disk = self._disk(_ddb_get_reply(op_id=0, value=b"lsilogic"))
        assert disk.ddb_get("adapterType") == "lsilogic"

    def test_missing_key_returns_none(self) -> None:
        disk = self._disk(_ddb_get_reply(op_id=0, value=None))
        assert disk.ddb_get("resumeConsolidateSector") is None

    def test_sends_handle_and_key_length_in_request(self) -> None:
        sock = _FakeSocket(_ddb_get_reply(op_id=0, value=b"63"))
        disk = nfc_open.NfcDisk(
            sock=sock, path="[ds] a.vmdk", handle=0x1234, sector_size=512
        )
        disk.ddb_get("geometry.sectors")
        (sent,) = sock.sent
        # header(16) + handle(8) + key_len(4) + reserved(4) + key bytes
        handle, key_len, reserved = struct.unpack_from("<QII", sent, 16)
        assert handle == 0x1234
        assert key_len == len("geometry.sectors")
        assert reserved == 0
        assert sent[16 + 16 :] == b"geometry.sectors"


class TestQueryFullInfo:
    def _disk_with_replies(self, values: dict[str, bytes | None]) -> nfc_open.NfcDisk:
        # query_full_info calls ddb_get for biosCylinders, biosHeads,
        # biosSectors, adapterType, uuid, in that order.
        keys = [
            "geometry.biosCylinders",
            "geometry.biosHeads",
            "geometry.biosSectors",
            "adapterType",
            "uuid",
        ]
        replies = b"".join(
            _ddb_get_reply(op_id=i, value=values.get(k)) for i, k in enumerate(keys)
        )
        disk = nfc_open.NfcDisk(
            sock=_FakeSocket(replies), path="[ds] a.vmdk", handle=1, sector_size=512
        )
        disk.info = nfc_open.DiskInfo(
            capacity_sectors=1024,
            phys_geo=nfc_open.DiskGeometry(cylinders=10, heads=20, sectors=30),
        )
        return disk

    def test_combines_open_file_info_with_ddb_values(self) -> None:
        disk = self._disk_with_replies(
            {
                "geometry.biosCylinders": b"100",
                "geometry.biosHeads": b"200",
                "geometry.biosSectors": b"63",
                "adapterType": b"lsilogic",
                "uuid": b"some-uuid",
            }
        )
        info = disk.query_full_info()
        assert info.capacity_sectors == 1024
        assert info.phys_geo == nfc_open.DiskGeometry(
            cylinders=10, heads=20, sectors=30
        )
        assert info.bios_geo == nfc_open.DiskGeometry(
            cylinders=100, heads=200, sectors=63
        )
        assert info.adapter_type == "lsilogic"
        assert info.uuid == "some-uuid"

    def test_missing_ddb_keys_fall_back_to_defaults(self) -> None:
        disk = self._disk_with_replies({})
        info = disk.query_full_info()
        assert info.bios_geo == nfc_open.DiskGeometry(cylinders=0, heads=0, sectors=0)
        assert info.adapter_type is None
        assert info.uuid is None


class TestParseOpenReply:
    def test_parses_handle_capacity_and_geometry(self) -> None:
        """Capacity (offset 28, bytes) and physGeo (40/44/48) are extracted."""
        body = _open_reply_body()
        handle, sector_size, info = nfc_open._parse_open_reply(body)
        assert handle == 0x1234
        assert sector_size == 512
        assert info.capacity_sectors == 17179869184 // 512
        assert info.phys_geo == nfc_open.DiskGeometry(
            cylinders=2088, heads=255, sectors=63
        )

    def test_zero_sector_size_falls_back_and_still_divides_capacity(self) -> None:
        """A zero sector_size falls back to NFC_SECTOR_SIZE for both uses."""
        body = _open_reply_body(sector_size=0, capacity_bytes=1024 * 512)
        _handle, sector_size, info = nfc_open._parse_open_reply(body)
        assert sector_size == nfc_open.NFC_SECTOR_SIZE
        assert info.capacity_sectors == (1024 * 512) // nfc_open.NFC_SECTOR_SIZE

    def test_wrong_file_type_raises(self) -> None:
        """A non-NFC_DISK file type is rejected."""
        body = _open_reply_body(file_type=99)
        with pytest.raises(nfc_open.NfcProtocolError, match="file type 99"):
            nfc_open._parse_open_reply(body)

    def test_short_body_raises(self) -> None:
        """A reply shorter than the physGeo fields is rejected."""
        with pytest.raises(nfc_open.NfcProtocolError, match="too short"):
            nfc_open._parse_open_reply(bytes(40))
