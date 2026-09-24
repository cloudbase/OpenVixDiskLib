# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise HotAdd from the Linux proxy guest over SSH."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import pytest
from pyVmomi import vim

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import (
    SECTOR_AT_1GB,
    SECTOR_SIZE,
    LabEnv,
    _connect_vim,
    create_lab_vm,
    destroy_lab_vm,
    load_hotadd_proxy_config,
    pattern_bytes,
)
from tests.integration.hotadd_proxy import (
    REMOTE_DIR,
    REMOTE_PYTHON,
    prepare_hotadd_proxy,
    ssh_proxy,
)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture(scope="session")
def hotadd_proxy() -> dict[str, str]:
    """SSH settings for the Linux HotAdd proxy, or skip."""
    remote_py = os.path.join(_REPO_ROOT, "tests", "integration", "hotadd_remote.py")
    try:
        return prepare_hotadd_proxy({"hotadd_remote.py": remote_py})
    except RuntimeError as exc:
        pytest.skip(str(exc))


@pytest.fixture
def nvme_lab() -> Iterator[LabEnv]:
    """Powered-off lab VM whose disk is on an NVMe controller."""
    env = create_lab_vm(disk_controller="nvme")
    try:
        yield env
    finally:
        destroy_lab_vm(env)


def _proxy_extra_disk_count(lab: LabEnv) -> int:
    """Count non-boot virtual disks on the HotAdd proxy VM."""
    proxy_cfg = load_hotadd_proxy_config()
    if proxy_cfg is None:
        return 0
    si = _connect_vim(
        lab.host,
        lab.username,
        lab.password,
        lab.port,
        lab.thumbprint,
        lab.allow_untrusted,
    )
    try:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        try:
            for vm in container.view:
                ips: list[str] = []
                if vm.guest and vm.guest.net:
                    for nic in vm.guest.net:
                        ips.extend(nic.ipAddress or [])
                if proxy_cfg["host"] in ips:
                    disks = [
                        device
                        for device in vm.config.hardware.device
                        if isinstance(device, vim.vm.device.VirtualDisk)
                    ]
                    return max(0, len(disks) - 1)
        finally:
            container.Destroy()
    finally:
        from pyVim.connect import Disconnect

        Disconnect(si)
    return 0


def _run_hotadd_remote(proxy: dict[str, str], lab: LabEnv) -> dict[str, Any]:
    patterns = {
        "0": pattern_bytes(SECTOR_SIZE, b"OVDL-HA0").hex(),
        str(SECTOR_AT_1GB): pattern_bytes(SECTOR_SIZE, b"OVDL-HA1").hex(),
    }
    payload = json.dumps(
        {
            "server_name": lab.host,
            "thumbprint": lab.thumbprint,
            "username": lab.username,
            "password": lab.password,
            "port": lab.port,
            "allow_untrusted": lab.allow_untrusted,
            "vmx_spec": lab.vmx_spec,
            "disk_path": lab.disk_path,
            "sector_size": SECTOR_SIZE,
            "patterns": patterns,
        }
    ).encode()
    result = ssh_proxy(
        proxy,
        f"cd {REMOTE_DIR} && PYTHONPATH={REMOTE_DIR} {REMOTE_PYTHON} hotadd_remote.py",
        stdin=payload,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"hotadd_remote failed rc={result.returncode} "
            f"stdout={result.stdout.decode(errors='replace')!r} "
            f"stderr={result.stderr.decode(errors='replace')!r}"
        )
    report = json.loads(result.stdout.decode())
    assert report.get("ok") is True, report
    return report


def _assert_nbdssl_matches(lab: LabEnv, patterns: dict[int, bytes]) -> None:
    handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
    read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
    kwargs = lab.vixdisklib_connect_kwargs(
        {
            "allow_untrusted": lab.allow_untrusted,
            "transport_modes": "nbdssl",
            "read_only": True,
        }
    )
    with (
        handle.connect(**kwargs) as conn,
        handle.open(
            conn, lab.disk_path, flags=vixdisklib.VIXDISKLIB_FLAG_OPEN_READ_ONLY
        ) as disk,
    ):
        for start, expected in patterns.items():
            read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
            handle.read(disk, start, 1, read_buf)
            assert read_buf.raw[:SECTOR_SIZE] == expected


class TestHotAdd:
    def test_pvscsi_write_read(self, lab: LabEnv, hotadd_proxy: dict[str, str]) -> None:
        """HotAdd a PVSCSI lab disk on the proxy and verify via nbdssl."""
        extra_before = _proxy_extra_disk_count(lab)
        report = _run_hotadd_remote(hotadd_proxy, lab)
        assert report["mode"] == "hotadd"
        assert report["extra_disks_after_close"] == extra_before
        assert _proxy_extra_disk_count(lab) == extra_before
        _assert_nbdssl_matches(
            lab,
            {
                0: pattern_bytes(SECTOR_SIZE, b"OVDL-HA0"),
                SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"OVDL-HA1"),
            },
        )

    def test_nvme_source_write_read(
        self, nvme_lab: LabEnv, hotadd_proxy: dict[str, str]
    ) -> None:
        """HotAdd an NVMe-backed VMDK onto the proxy's SCSI controller."""
        extra_before = _proxy_extra_disk_count(nvme_lab)
        report = _run_hotadd_remote(hotadd_proxy, nvme_lab)
        assert report["mode"] == "hotadd"
        assert report["extra_disks_after_close"] == extra_before
        _assert_nbdssl_matches(
            nvme_lab,
            {
                0: pattern_bytes(SECTOR_SIZE, b"OVDL-HA0"),
                SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"OVDL-HA1"),
            },
        )
