# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Compare writes and reads from VDDK with openvixdisklib."""

from typing import Any, Optional

import pytest

from openvixdisklib import openvixdisklib as open_vix
from tests.integration import vixdisklib
from tests.integration.base import SECTOR_AT_1GB, SECTOR_SIZE, LabEnv, pattern_bytes


def _connect_extra(lab: LabEnv, module: Any) -> Optional[dict[str, Any]]:
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
    with handle.connect(**kwargs) as conn:
        with handle.open(conn, lab.disk_path, flags=flags) as disk:
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
    with handle.connect(**kwargs) as conn:
        with handle.open(conn, lab.disk_path, flags=flags) as disk:
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
        sectors = (0, 1, SECTOR_AT_1GB)
        vddk_payloads = {
            0: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-S0"),
            1: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-S1"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"XCHK-VDDK-1G"),
        }
        _write_sectors(lab, vixdisklib, vddk_payloads, flags=open_flags)
        _assert_both_read(lab, sectors, vddk_payloads, flags=open_flags)

        ovdl_payloads = {
            0: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-S0"),
            1: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-S1"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"XCHK-OVDL-1G"),
        }
        _write_sectors(lab, open_vix, ovdl_payloads, flags=open_flags)
        _assert_both_read(lab, sectors, ovdl_payloads, flags=open_flags)
