# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Compare writes and reads from VDDK with openvixdisklib."""

from typing import Any, Optional

from openvixdisklib import openvixdisklib as open_vix
from tests.integration import vixdisklib
from tests.integration.base import TestBase


class CrosscheckTest(TestBase):
    @classmethod
    def setUpClass(cls) -> None:
        """Skip when the bundled VDDK shared library is not present."""
        cls.require_vddk()
        super().setUpClass()

    def _connect_extra(self, module: Any) -> Optional[dict[str, Any]]:
        """Return extra ``connect`` kwargs needed by ``module``."""
        if module is open_vix:
            return {"allow_untrusted": self.ALLOW_UNTRUSTED}
        return None

    def _write_sectors(
            self,
            module: Any,
            payloads: dict[int, bytes]) -> None:
        """Write one sector at each index using a vixdisklib-compatible module."""
        handle = module.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path=None)
        buf = module.get_buffer(self.SECTOR_SIZE)
        kwargs = self.vixdisklib_connect_kwargs(self._connect_extra(module))
        with handle.connect(**kwargs) as conn:
            with handle.open(conn, self.DISK_PATH, flags=0) as disk:
                for start, data in payloads.items():
                    buf[:self.SECTOR_SIZE] = data
                    handle.write(disk, start, 1, buf)

    def _read_sectors(
            self,
            module: Any,
            sectors: tuple[int, ...]) -> dict[int, bytes]:
        """Read one sector at each index using a vixdisklib-compatible module."""
        handle = module.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0",
            config_path=None)
        buf = module.get_buffer(self.SECTOR_SIZE)
        result: dict[int, bytes] = {}
        kwargs = self.vixdisklib_connect_kwargs(self._connect_extra(module))
        with handle.connect(**kwargs) as conn:
            with handle.open(conn, self.DISK_PATH, flags=0) as disk:
                for start in sectors:
                    buf[:self.SECTOR_SIZE] = b"\xa5" * self.SECTOR_SIZE
                    handle.read(disk, start, 1, buf)
                    result[start] = buf.raw[:self.SECTOR_SIZE]
        return result

    def _assert_both_read(
            self,
            sectors: tuple[int, ...],
            expected: dict[int, bytes]) -> None:
        vddk = self._read_sectors(vixdisklib, sectors)
        replacement = self._read_sectors(open_vix, sectors)
        for start in sectors:
            self.assertEqual(
                vddk[start], expected[start],
                f"VDDK mismatch at sector {start}")
            self.assertEqual(
                replacement[start], expected[start],
                f"openvixdisklib mismatch at sector {start}")

    def test_openvixdisklib_matches_vddk_sectors(self) -> None:
        """Writes from either library must be visible to both readers."""
        sectors = (0, 1, self.SECTOR_AT_1GB)
        vddk_payloads = {
            0: self.pattern_bytes(self.SECTOR_SIZE, b"XCHK-VDDK-S0"),
            1: self.pattern_bytes(self.SECTOR_SIZE, b"XCHK-VDDK-S1"),
            self.SECTOR_AT_1GB: self.pattern_bytes(
                self.SECTOR_SIZE, b"XCHK-VDDK-1G"),
        }
        self._write_sectors(vixdisklib, vddk_payloads)
        self._assert_both_read(sectors, vddk_payloads)

        ovdl_payloads = {
            0: self.pattern_bytes(self.SECTOR_SIZE, b"XCHK-OVDL-S0"),
            1: self.pattern_bytes(self.SECTOR_SIZE, b"XCHK-OVDL-S1"),
            self.SECTOR_AT_1GB: self.pattern_bytes(
                self.SECTOR_SIZE, b"XCHK-OVDL-1G"),
        }
        self._write_sectors(open_vix, ovdl_payloads)
        self._assert_both_read(sectors, ovdl_payloads)
