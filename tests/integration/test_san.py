# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""SAN transport against a file-backed iSCSI VMFS LUN.

Skipped when the runner cannot present a LIO target or ESXi cannot
mount it. The session-wide ``lab`` VM stays on the YAML datastore.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import (
    SECTOR_AT_1GB,
    SECTOR_SIZE,
    LabEnv,
    create_lab_vm,
    destroy_lab_vm,
    pattern_bytes,
)
from tests.integration.iscsi_lab import (
    IscsiSanLab,
    setup_iscsi_san_lab,
    teardown_iscsi_san_lab,
)


@pytest.fixture(scope="module")
def iscsi_lab() -> Iterator[IscsiSanLab]:
    """Bring up a loop-backed iSCSI VMFS datastore, or skip."""
    try:
        lab = setup_iscsi_san_lab()
    except (RuntimeError, TimeoutError, OSError) as exc:
        pytest.skip(f"iSCSI SAN lab unavailable: {exc}")
    try:
        yield lab
    finally:
        teardown_iscsi_san_lab(lab)


@pytest.fixture
def san_lab(iscsi_lab: IscsiSanLab) -> Iterator[LabEnv]:
    """Powered-off 10 GiB VM on the iSCSI datastore (not the session lab)."""
    env = create_lab_vm(datastore=iscsi_lab.datastore_name, thin_provisioned=False)
    try:
        yield env
    finally:
        destroy_lab_vm(env)


class TestSanTransport:
    def test_write_and_read_sector_zero_and_one_gib(self, san_lab: LabEnv) -> None:
        """SAN write/read of sector 0 and 1 GiB; nbdssl write is visible to SAN.

        ESXi keeps a VMFS cache of the mounted datastore, so nbdssl does not
        observe SAN writes from this initiator. The reverse does: nbdssl
        writes hit the LUN, SAN open flushes the initiator cache, then reads.
        """
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        modes = handle.get_transport_modes()
        if "san" not in modes:
            pytest.skip(f"san not advertised: {modes}")
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        patterns = {
            0: pattern_bytes(SECTOR_SIZE, b"SAN-S0"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"SAN-1GB"),
        }
        connect_kwargs = san_lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": san_lab.allow_untrusted,
                "transport_modes": "san",
            }
        )
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(conn, san_lab.disk_path, flags=0) as disk,
        ):
            assert handle.get_transport_mode(disk) == "san"
            for start, expected in patterns.items():
                write_buf[:SECTOR_SIZE] = expected
                handle.write(disk, start, 1, write_buf)
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, start, 1, read_buf)
                assert read_buf.raw[:SECTOR_SIZE] == expected

        nbd_patterns = {
            0: pattern_bytes(SECTOR_SIZE, b"NBD-S0"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"NBD-1GB"),
        }
        nbd_kwargs = san_lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": san_lab.allow_untrusted,
                "transport_modes": "nbdssl",
            }
        )
        with (
            handle.connect(**nbd_kwargs) as conn,
            handle.open(conn, san_lab.disk_path, flags=0) as disk,
        ):
            assert handle.get_transport_mode(disk) == "nbdssl"
            for start, expected in nbd_patterns.items():
                write_buf[:SECTOR_SIZE] = expected
                handle.write(disk, start, 1, write_buf)

        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(conn, san_lab.disk_path, flags=0) as disk,
        ):
            for start, expected in nbd_patterns.items():
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, start, 1, read_buf)
                assert read_buf.raw[:SECTOR_SIZE] == expected
