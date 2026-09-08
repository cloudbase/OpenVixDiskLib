# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Compare openvixdisklib and native VDDK I/O throughput against the lab."""

from __future__ import annotations

import time
from typing import Any

from openvixdisklib import openvixdisklib as open_vix
from tests.integration import vixdisklib
from tests.integration.base import SECTOR_SIZE, LabEnv, pattern_bytes

_SIZES = (
    ("64KiB", 64 * 1024),
    ("129 sectors", 129 * SECTOR_SIZE),
    ("32MiB", 32 * 1024 * 1024),
)


def _connect_extra(lab: LabEnv, module: Any, transport_mode: str) -> dict[str, Any]:
    """Return extra ``connect`` kwargs needed by ``module``."""
    extra: dict[str, Any] = {"transport_modes": transport_mode}
    if module is open_vix:
        extra["allow_untrusted"] = lab.allow_untrusted
    return extra


def _time_write_read(
    lab: LabEnv,
    module: Any,
    payload: bytes,
    flags: int = 0,
    transport_mode: str = "nbdssl",
) -> tuple[float, float]:
    """Write ``payload`` at sector 0, read it back, and return durations."""
    n_sectors = len(payload) // SECTOR_SIZE
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=None
    )
    write_buf = module.get_buffer(len(payload))
    read_buf = module.get_buffer(len(payload))
    write_buf[: len(payload)] = payload
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module, transport_mode))
    with handle.connect(**kwargs) as conn:
        with handle.open(conn, lab.disk_path, flags=flags) as disk:
            started = time.perf_counter()
            handle.write(disk, 0, n_sectors, write_buf)
            write_s = time.perf_counter() - started
            read_buf[: len(payload)] = b"\xa5" * len(payload)
            started = time.perf_counter()
            handle.read(disk, 0, n_sectors, read_buf)
            read_s = time.perf_counter() - started
    assert read_buf.raw[: len(payload)] == payload
    return write_s, read_s


def _mib_per_s(nbytes: int, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return (nbytes / (1024 * 1024)) / seconds


class TestCompare:
    def test_write_read_throughput(self, lab: LabEnv, vddk: None) -> None:
        """Time matching write/read sizes on VDDK and openvixdisklib."""
        libraries = (
            ("vddk", vixdisklib),
            ("openvixdisklib", open_vix),
        )
        transports = ("nbdssl", "nbd")
        open_modes = (
            ("plain", 0),
            ("fastlz", vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ),
        )
        rows: list[tuple[str, str, str, str, float, float, float, float]] = []
        for label, nbytes in _SIZES:
            payload = pattern_bytes(nbytes, f"PERF-{label}-".encode())
            for transport_mode in transports:
                for mode_name, flags in open_modes:
                    for name, module in libraries:
                        write_s, read_s = _time_write_read(
                            lab,
                            module,
                            payload,
                            flags=flags,
                            transport_mode=transport_mode,
                        )
                        rows.append(
                            (
                                label,
                                transport_mode,
                                mode_name,
                                name,
                                write_s,
                                read_s,
                                _mib_per_s(nbytes, write_s),
                                _mib_per_s(nbytes, read_s),
                            )
                        )
        print()
        print(
            f"{'size':<14} {'transport':<10} {'flags':<8} {'library':<16} "
            f"{'write_s':>10} {'read_s':>10} "
            f"{'write_MiB/s':>12} {'read_MiB/s':>12}"
        )
        for (
            label,
            transport_mode,
            mode_name,
            name,
            write_s,
            read_s,
            write_r,
            read_r,
        ) in rows:
            print(
                f"{label:<14} {transport_mode:<10} {mode_name:<8} {name:<16} "
                f"{write_s:10.3f} {read_s:10.3f} "
                f"{write_r:12.1f} {read_r:12.1f}"
            )
