# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Compare writes and reads from VDDK with openvixdisklib."""

from __future__ import annotations

import os
from typing import Any

import pytest

from openvixdisklib import openvixdisklib as open_vix
from tests.integration import vixdisklib
from tests.integration.base import (
    SECTOR_AT_1GB,
    SECTOR_AT_5GB,
    SECTOR_SIZE,
    LabEnv,
    pattern_bytes,
)

_64MIB = 64 * 1024 * 1024
_5GIB = SECTOR_AT_5GB * SECTOR_SIZE


def _connect_extra(lab: LabEnv, module: Any) -> dict[str, Any] | None:
    """Return extra ``connect`` kwargs needed by ``module``."""
    if module is open_vix:
        return {"allow_untrusted": lab.allow_untrusted}
    return None


def _write_sectors(
    lab: LabEnv, module: Any, payloads: dict[int, bytes], flags: int = 0
) -> None:
    """Write one sector at each index using a vixdisklib-compatible module."""
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=None
    )
    buf = module.get_buffer(SECTOR_SIZE)
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module))
    with (
        handle.connect(**kwargs) as conn,
        handle.open(conn, lab.disk_path, flags=flags) as disk,
    ):
        for start, data in payloads.items():
            buf[:SECTOR_SIZE] = data
            handle.write(disk, start, 1, buf)


def _read_sectors(
    lab: LabEnv, module: Any, sectors: tuple[int, ...], flags: int = 0
) -> dict[int, bytes]:
    """Read one sector at each index using a vixdisklib-compatible module."""
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=None
    )
    buf = module.get_buffer(SECTOR_SIZE)
    result: dict[int, bytes] = {}
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module))
    with (
        handle.connect(**kwargs) as conn,
        handle.open(conn, lab.disk_path, flags=flags) as disk,
    ):
        for start in sectors:
            buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
            handle.read(disk, start, 1, buf)
            result[start] = buf.raw[:SECTOR_SIZE]
    return result


def _assert_both_read(
    lab: LabEnv, sectors: tuple[int, ...], expected: dict[int, bytes], flags: int = 0
) -> None:
    vddk_data = _read_sectors(lab, vixdisklib, sectors, flags=flags)
    replacement = _read_sectors(lab, open_vix, sectors, flags=flags)
    for start in sectors:
        assert vddk_data[start] == expected[start], f"VDDK mismatch at sector {start}"
        assert replacement[start] == expected[start], (
            f"openvixdisklib mismatch at sector {start}"
        )


def _write_bytes(
    lab: LabEnv, module: Any, start_byte: int, data: bytes, flags: int = 0
) -> None:
    """Write ``data`` starting at ``start_byte`` using ``module``."""
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=None
    )
    buf = module.get_buffer(len(data))
    buf[: len(data)] = data
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module))
    with (
        handle.connect(**kwargs) as conn,
        handle.open(conn, lab.disk_path, flags=flags) as disk,
    ):
        handle.write(disk, start_byte // SECTOR_SIZE, len(data) // SECTOR_SIZE, buf)


def _read_bytes(
    lab: LabEnv, module: Any, start_byte: int, nbytes: int, flags: int = 0
) -> bytes:
    """Read ``nbytes`` starting at ``start_byte`` using ``module``."""
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=None
    )
    buf = module.get_buffer(nbytes)
    buf[:nbytes] = b"\xa5" * nbytes
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module))
    with (
        handle.connect(**kwargs) as conn,
        handle.open(conn, lab.disk_path, flags=flags) as disk,
    ):
        handle.read(disk, start_byte // SECTOR_SIZE, nbytes // SECTOR_SIZE, buf)
    return buf.raw[:nbytes]


def _assert_both_read_bytes(
    lab: LabEnv, start_byte: int, expected: bytes, flags: int = 0
) -> None:
    vddk_data = _read_bytes(lab, vixdisklib, start_byte, len(expected), flags=flags)
    replacement = _read_bytes(lab, open_vix, start_byte, len(expected), flags=flags)
    assert vddk_data == expected, f"VDDK mismatch at byte offset {start_byte}"
    assert replacement == expected, (
        f"openvixdisklib mismatch at byte offset {start_byte}"
    )


class TestCrosscheck:
    @pytest.mark.parametrize(
        "open_flags",
        [0, vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
    )
    def test_openvixdisklib_matches_vddk_sectors(
        self, lab: LabEnv, vddk: None, open_flags: int
    ) -> None:
        """Writes from either library must be visible to both readers."""
        sectors = (0, 1, SECTOR_AT_1GB, SECTOR_AT_5GB)
        vddk_payloads = {
            0: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-S0"),
            1: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-S1"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-1G"),
            SECTOR_AT_5GB: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-5G"),
        }
        _write_sectors(lab, vixdisklib, vddk_payloads, flags=open_flags)
        _assert_both_read(lab, sectors, vddk_payloads, flags=open_flags)

        ovdl_payloads = {
            0: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-S0"),
            1: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-S1"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-1G"),
            SECTOR_AT_5GB: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-5G"),
        }
        _write_sectors(lab, open_vix, ovdl_payloads, flags=open_flags)
        _assert_both_read(lab, sectors, ovdl_payloads, flags=open_flags)

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "open_flags",
        [0, vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ],
        ids=["plain", "fastlz"],
    )
    def test_openvixdisklib_matches_vddk_64mib_at_5gib(
        self, lab: LabEnv, vddk: None, open_flags: int
    ) -> None:
        """Write 64 MiB of random data at a 5 GiB offset and compare both libraries.

        The 5 GiB start is past the 4 GiB (2**32) byte boundary, so a
        32-bit disk offset would wrap and fail the comparison.
        """
        vddk_payload = os.urandom(_64MIB)
        _write_bytes(lab, vixdisklib, _5GIB, vddk_payload, flags=open_flags)
        _assert_both_read_bytes(lab, _5GIB, vddk_payload, flags=open_flags)

        ovdl_payload = os.urandom(_64MIB)
        _write_bytes(lab, open_vix, _5GIB, ovdl_payload, flags=open_flags)
        _assert_both_read_bytes(lab, _5GIB, ovdl_payload, flags=open_flags)
