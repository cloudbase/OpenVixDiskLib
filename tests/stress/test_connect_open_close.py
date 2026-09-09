# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Repeat connect/open/close against the lab to catch leaked sockets."""

from __future__ import annotations

import gc
import os

import pytest

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import SECTOR_SIZE, LabEnv, pattern_bytes

# Sequential ConnectEx + Open, as when migrating many VMs in one process.
_ITERATIONS = 200
# Noise from pytest/OpenSSL; one leaked socket per iteration is 200.
_FD_SLACK = 8


def _fd_count() -> int:
    """Return the number of open file descriptors in this process."""
    return len(os.listdir("/proc/self/fd"))


@pytest.mark.skipif(
    not os.path.isdir("/proc/self/fd"),
    reason="fd leak check needs /proc/self/fd",
)
class TestConnectOpenReadWriteClose:
    def test_repeated_connect_open_read_write_close_does_not_leak_fds(
        self,
        lab: LabEnv,
    ) -> None:
        """Connect, open, write/read one sector, and close ``_ITERATIONS`` times.

        Each cycle is a full ``VixDiskLib_ConnectEx`` / ``Open`` /
        ``Close`` / ``Disconnect`` for the lab VM (ticket, authd, NFC).
        After the loop the process fd count must not have grown by more
        than ``_FD_SLACK``.
        """
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        kwargs = lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": lab.allow_untrusted,
                "transport_modes": "nbdssl",
            }
        )
        gc.collect()
        fds_before = _fd_count()
        for i in range(_ITERATIONS):
            expected = pattern_bytes(SECTOR_SIZE, f"STRESS-{i}-".encode())
            write_buf[:SECTOR_SIZE] = expected
            with (
                handle.connect(**kwargs) as conn,
                handle.open(conn, lab.disk_path, flags=0) as disk,
            ):
                handle.write(disk, 0, 1, write_buf)
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, 0, 1, read_buf)
            assert read_buf.raw[:SECTOR_SIZE] == expected
        gc.collect()
        fds_after = _fd_count()
        assert fds_after <= fds_before + _FD_SLACK, (
            f"open fds grew from {fds_before} to {fds_after} after "
            f"{_ITERATIONS} connect/open/close cycles"
        )
