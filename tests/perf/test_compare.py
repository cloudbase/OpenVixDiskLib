# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Compare openvixdisklib and native VDDK I/O throughput against the lab."""

from __future__ import annotations

import json
import os
import pickle
import subprocess
import sys
import tempfile
import time
from typing import Any

from openvixdisklib import nfc_open
from openvixdisklib import openvixdisklib as open_vix
from tests.integration import vixdisklib
from tests.integration.base import (
    SECTOR_SIZE,
    LabEnv,
    ensure_vddk_library_path,
    pattern_bytes,
)

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
_SIZES = (
    ("64KiB", 64 * 1024),
    ("129 sectors", 129 * SECTOR_SIZE),
    ("32MiB", 32 * 1024 * 1024),
)
_1MIB = 1024 * 1024
_2MIB = 2 * 1024 * 1024
# ESXi 8 accepts 64 KiB, 1 MiB, and 2 MiB extras. 16 MiB and 32 MiB
# OPEN_SESSION are rejected (AIO error). Broadcom's 16 MiB cap is
# size×count session memory, not a larger extra; VDDK's per-buffer max
# is 2 MiB (``BufSizeIn64KB=16`` is 1 MiB).
_AIO_SESSIONS = (
    (nfc_open.NFC_AIO_BUFFER_COUNT, nfc_open.NFC_AIO_BUFFER_SIZE),
    (1, _1MIB),
    (1, _2MIB),
    (4, _2MIB),
)
_64KIB = 64 * 1024


def _aio_size_label(nbytes: int) -> str:
    """Return a short label for an AIO extra size."""
    if nbytes % (1024 * 1024) == 0:
        return f"{nbytes // (1024 * 1024)}MiB"
    if nbytes % 1024 == 0:
        return f"{nbytes // 1024}KiB"
    return str(nbytes)


def _vddk_aio_config(
    directory: str, aio_buffer_size: int, aio_buffer_count: int
) -> str:
    """Write a temp VDDK config for ``BufSizeIn64KB`` and ``BufCount``."""
    if aio_buffer_size % _64KIB:
        raise ValueError(
            f"VDDK BufSizeIn64KB needs a 64 KiB multiple, got {aio_buffer_size}"
        )
    path = os.path.join(directory, "vddk.config")
    with open(path, "w", encoding="utf-8") as config:
        config.write(f"tmpDirectory={directory}\n")
        config.write(
            f"vixDiskLib.nfcAio.Session.BufSizeIn64KB={aio_buffer_size // _64KIB}\n"
        )
        config.write(f"vixDiskLib.nfcAio.Session.BufCount={aio_buffer_count}\n")
    return path


def _connect_extra(lab: LabEnv, module: Any, transport_mode: str) -> dict[str, Any]:
    """Return extra ``connect`` kwargs needed by ``module``."""
    extra: dict[str, Any] = {"transport_modes": transport_mode}
    if module is open_vix:
        extra["allow_untrusted"] = lab.allow_untrusted
    return extra


def _time_write_read_once(
    lab: LabEnv,
    module: Any,
    payload: bytes,
    flags: int = 0,
    transport_mode: str = "nbdssl",
    aio_buffer_size: int = nfc_open.NFC_AIO_BUFFER_SIZE,
    aio_buffer_count: int = nfc_open.NFC_AIO_BUFFER_COUNT,
    config_dir: str | None = None,
    skip_decompression: bool = False,
) -> tuple[float, float]:
    """Write ``payload`` at sector 0, read it back, and return durations.

    Does not call ``VixDiskLib_Exit``. Native VDDK double-frees if
    ``InitEx``/``Exit`` are paired more than once in the same process.
    ``skip_decompression`` is OpenVixDiskLib FastLZ skip; ``buf`` then
    holds packed extras, not sector bytes.
    """
    n_sectors = len(payload) // SECTOR_SIZE
    config_path = None
    if module is vixdisklib:
        if config_dir is None:
            raise ValueError("VDDK timings need a config_dir")
        config_path = _vddk_aio_config(config_dir, aio_buffer_size, aio_buffer_count)
    handle = module.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=config_path
    )
    write_buf = module.get_buffer(len(payload))
    read_buf = module.get_buffer(len(payload))
    write_buf[: len(payload)] = payload
    kwargs = lab.vixdisklib_connect_kwargs(_connect_extra(lab, module, transport_mode))
    open_kwargs: dict[str, Any] = {"flags": flags}
    if module is open_vix:
        open_kwargs["aio_buffer_size"] = aio_buffer_size
        open_kwargs["aio_buffer_count"] = aio_buffer_count
    with (
        handle.connect(**kwargs) as conn,
        handle.open(conn, lab.disk_path, **open_kwargs) as disk,
    ):
        started = time.perf_counter()
        handle.write(disk, 0, n_sectors, write_buf)
        write_s = time.perf_counter() - started
        read_buf[: len(payload)] = b"\xa5" * len(payload)
        read_kwargs: dict[str, Any] = {}
        if skip_decompression:
            read_kwargs["skip_decompression"] = True
        started = time.perf_counter()
        result = handle.read(disk, 0, n_sectors, read_buf, **read_kwargs)
        read_s = time.perf_counter() - started
    if skip_decompression:
        assert result.uncompressed_length == len(payload)
        assert result.compressed_length <= len(payload)
        assert result.fragments
    else:
        assert read_buf.raw[: len(payload)] == payload
    return write_s, read_s


def _run_vddk_worker(lab_pkl: str, job_pkl: str, work_dir: str) -> None:
    """InitEx once in this process, time one write/read, write result.json."""
    os.environ.pop("LD_PRELOAD", None)
    ensure_vddk_library_path()
    with open(lab_pkl, "rb") as pickle_file:
        lab = pickle.load(pickle_file)
    with open(job_pkl, "rb") as pickle_file:
        job = pickle.load(pickle_file)
    payload = pattern_bytes(job["nbytes"], f"PERF-{job['label']}-".encode())
    write_s, read_s = _time_write_read_once(
        lab,
        vixdisklib,
        payload,
        flags=job["flags"],
        transport_mode=job["transport_mode"],
        aio_buffer_size=job["aio_buffer_size"],
        aio_buffer_count=job["aio_buffer_count"],
        config_dir=work_dir,
    )
    result_path = os.path.join(work_dir, "result.json")
    with open(result_path, "w", encoding="utf-8") as result_file:
        json.dump({"write_s": write_s, "read_s": read_s}, result_file)


def _time_vddk_subprocess(
    lab: LabEnv,
    label: str,
    nbytes: int,
    flags: int,
    transport_mode: str,
    aio_buffer_size: int,
    aio_buffer_count: int,
) -> tuple[float, float]:
    """Time native VDDK in a child process so InitEx sees this AIO config."""
    with tempfile.TemporaryDirectory(prefix="vddk-perf-") as work_dir:
        lab_pkl = os.path.join(work_dir, "lab.pkl")
        job_pkl = os.path.join(work_dir, "job.pkl")
        result_path = os.path.join(work_dir, "result.json")
        with open(lab_pkl, "wb") as pickle_file:
            pickle.dump(lab, pickle_file)
        with open(job_pkl, "wb") as pickle_file:
            pickle.dump(
                {
                    "label": label,
                    "nbytes": nbytes,
                    "flags": flags,
                    "transport_mode": transport_mode,
                    "aio_buffer_size": aio_buffer_size,
                    "aio_buffer_count": aio_buffer_count,
                },
                pickle_file,
            )
        env = os.environ.copy()
        env.pop("LD_PRELOAD", None)
        pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = _REPO if not pythonpath else f"{_REPO}:{pythonpath}"
        proc = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--vddk-worker",
                lab_pkl,
                job_pkl,
                work_dir,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            cwd=_REPO,
        )
        if proc.returncode != 0 or not os.path.exists(result_path):
            raise RuntimeError(
                "VDDK perf worker failed "
                f"(exit {proc.returncode}): {proc.stderr}\n{proc.stdout}"
            )
        with open(result_path, encoding="utf-8") as result_file:
            result = json.load(result_file)
        return float(result["write_s"]), float(result["read_s"])


def _time_write_read(
    lab: LabEnv,
    module: Any,
    label: str,
    nbytes: int,
    flags: int = 0,
    transport_mode: str = "nbdssl",
    aio_buffer_size: int = nfc_open.NFC_AIO_BUFFER_SIZE,
    aio_buffer_count: int = nfc_open.NFC_AIO_BUFFER_COUNT,
    skip_decompression: bool = False,
) -> tuple[float, float]:
    """Time one write/read; native VDDK runs in a subprocess."""
    if skip_decompression and module is vixdisklib:
        raise ValueError("skip_decompression is OpenVixDiskLib-only")
    if module is vixdisklib:
        return _time_vddk_subprocess(
            lab,
            label,
            nbytes,
            flags,
            transport_mode,
            aio_buffer_size,
            aio_buffer_count,
        )
    payload = pattern_bytes(nbytes, f"PERF-{label}-".encode())
    return _time_write_read_once(
        lab,
        module,
        payload,
        flags=flags,
        transport_mode=transport_mode,
        aio_buffer_size=aio_buffer_size,
        aio_buffer_count=aio_buffer_count,
        skip_decompression=skip_decompression,
    )


def _mib_per_s(nbytes: int, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return (nbytes / (1024 * 1024)) / seconds


class TestCompare:
    def test_write_read_throughput(self, lab: LabEnv, vddk: None) -> None:
        """Time matching write/read sizes on VDDK and openvixdisklib.

        Prints ``aio_size`` / ``aio_count`` for each OPEN_SESSION
        (64 KiB×1, 1 MiB×1, 2 MiB×1, 2 MiB×4). VDDK gets those via
        ``vixDiskLib.nfcAio.Session.BufSizeIn64KB`` / ``BufCount`` in a
        fresh process per row (``VixDiskLib_Exit`` is not loop-safe).
        ``fastlz-skip`` is OpenVixDiskLib ``skip_decompression`` (packed
        extras, no FastLZ decode); VDDK has no equivalent.
        """
        libraries = (
            ("vddk", vixdisklib),
            ("openvixdisklib", open_vix),
        )
        transports = ("nbdssl", "nbd")
        open_modes = (
            ("plain", 0, False),
            ("fastlz", vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ, False),
            (
                "fastlz-skip",
                vixdisklib.VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ,
                True,
            ),
        )
        rows: list[tuple[str, str, int, str, str, str, float, float, float, float]] = []
        for label, nbytes in _SIZES:
            for aio_buffer_count, aio_buffer_size in _AIO_SESSIONS:
                aio_label = _aio_size_label(aio_buffer_size)
                for transport_mode in transports:
                    for mode_name, flags, skip_decompression in open_modes:
                        for name, module in libraries:
                            if skip_decompression and module is vixdisklib:
                                continue
                            write_s, read_s = _time_write_read(
                                lab,
                                module,
                                label,
                                nbytes,
                                flags=flags,
                                transport_mode=transport_mode,
                                aio_buffer_size=aio_buffer_size,
                                aio_buffer_count=aio_buffer_count,
                                skip_decompression=skip_decompression,
                            )
                            rows.append(
                                (
                                    label,
                                    aio_label,
                                    aio_buffer_count,
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
            f"{'size':<14} {'aio_size':<8} {'aio_count':>9} "
            f"{'transport':<10} {'flags':<12} {'library':<16} "
            f"{'write_s':>10} {'read_s':>10} "
            f"{'write_MiB/s':>12} {'read_MiB/s':>12}"
        )
        for (
            label,
            aio_label,
            aio_buffer_count,
            transport_mode,
            mode_name,
            name,
            write_s,
            read_s,
            write_r,
            read_r,
        ) in rows:
            print(
                f"{label:<14} {aio_label:<8} {aio_buffer_count:>9} "
                f"{transport_mode:<10} {mode_name:<12} {name:<16} "
                f"{write_s:10.3f} {read_s:10.3f} "
                f"{write_r:12.1f} {read_r:12.1f}"
            )


if __name__ == "__main__":
    if sys.argv[1:2] == ["--vddk-worker"]:
        _, _, lab_pkl, job_pkl, work_dir = sys.argv
        _run_vddk_worker(lab_pkl, job_pkl, work_dir)
    else:
        raise SystemExit("usage: test_compare.py --vddk-worker LAB JOB DIR")
