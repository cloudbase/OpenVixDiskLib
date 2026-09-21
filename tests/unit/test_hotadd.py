# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Unit tests for HotAdd attach specs and local block I/O."""

from __future__ import annotations

import os
from unittest import mock

import pytest
from pyVmomi import vim

from openvixdisklib.hotadd import (
    AttachPlan,
    HotAddDisk,
    _byteswap_uuid,
    _offline_scsi_unit,
    build_attach_spec,
    build_detach_spec,
    find_scsi_block_device,
    find_source_disk,
    pick_scsi_slot,
    wait_scsi_device_gone,
)
from openvixdisklib.openvixdisklib import (
    _available_transports,
    _select_transport,
)


def _scsi(key: int = 1000, bus: int = 0) -> vim.vm.device.ParaVirtualSCSIController:
    controller = vim.vm.device.ParaVirtualSCSIController()
    controller.key = key
    controller.busNumber = bus
    return controller


def _lsi(key: int = 1000, bus: int = 0) -> vim.vm.device.VirtualLsiLogicController:
    controller = vim.vm.device.VirtualLsiLogicController()
    controller.key = key
    controller.busNumber = bus
    return controller


def _disk(
    key: int,
    controller_key: int,
    unit: int,
    file_name: str,
) -> vim.vm.device.VirtualDisk:
    disk = vim.vm.device.VirtualDisk()
    disk.key = key
    disk.controllerKey = controller_key
    disk.unitNumber = unit
    backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    backing.fileName = file_name
    disk.backing = backing
    disk.capacityInKB = 1024
    return disk


class TestFindSourceDisk:
    def test_nvme_source_is_accepted(self) -> None:
        """NVMe-backed VMDKs are valid HotAdd sources."""
        nvme = vim.vm.device.VirtualNVMEController()
        nvme.key = 31000
        nvme.busNumber = 0
        path = "[datastore0] nvme/nvme.vmdk"
        disk = _disk(32000, 31000, 0, path)
        assert find_source_disk([nvme, disk], path) is disk

    def test_sata_source_is_accepted(self) -> None:
        """SATA-backed VMDKs are valid HotAdd sources."""
        sata = vim.vm.device.VirtualAHCIController()
        sata.key = 15000
        sata.busNumber = 0
        path = "[datastore0] sata/sata.vmdk"
        disk = _disk(16000, 15000, 0, path)
        assert find_source_disk([sata, disk], path) is disk

    def test_ide_source_is_rejected(self) -> None:
        """IDE disks cannot be HotAdded."""
        ide = vim.vm.device.VirtualIDEController()
        ide.key = 200
        ide.busNumber = 0
        path = "[datastore0] ide/ide.vmdk"
        disk = _disk(201, 200, 0, path)
        with pytest.raises(NotImplementedError, match="IDE"):
            find_source_disk([ide, disk], path)

    def test_missing_path_raises(self) -> None:
        """Unknown backing paths raise FileNotFoundError."""
        scsi = _scsi()
        disk = _disk(2000, 1000, 0, "[datastore0] vm/vm.vmdk")
        with pytest.raises(FileNotFoundError):
            find_source_disk([scsi, disk], "[datastore0] other/other.vmdk")


class TestAttachSpec:
    def test_uses_free_unit_one_on_existing_scsi(self) -> None:
        """A proxy with a boot disk at unit 0 HotAdds at unit 1."""
        devices = [
            _lsi(),
            _disk(2000, 1000, 0, "[datastore0] proxy/boot.vmdk"),
        ]
        source = "[datastore0] src/src.vmdk"
        plan = build_attach_spec(devices, source, read_only=True, capacity_kb=2048)
        assert isinstance(plan, AttachPlan)
        assert plan.bus_number == 0
        assert plan.unit_number == 1
        assert len(plan.spec.deviceChange) == 1
        change = plan.spec.deviceChange[0]
        assert change.operation == vim.vm.device.VirtualDeviceSpec.Operation.add
        assert change.fileOperation is None
        disk = change.device
        assert isinstance(disk, vim.vm.device.VirtualDisk)
        assert disk.controllerKey == 1000
        assert disk.unitNumber == 1
        assert disk.backing.fileName == source
        assert disk.backing.diskMode == "independent_nonpersistent"
        assert disk.capacityInKB == 2048

    def test_writable_open_uses_persistent_mode(self) -> None:
        """Restore / write HotAdd attaches the VMDK persistently."""
        devices = [_scsi(), _disk(2000, 1000, 0, "[datastore0] proxy/boot.vmdk")]
        plan = build_attach_spec(devices, "[datastore0] src/src.vmdk", read_only=False)
        disk = plan.spec.deviceChange[0].device
        assert disk.backing.diskMode == "persistent"

    def test_nvme_source_still_targets_proxy_scsi(self) -> None:
        """NVMe sources are attached onto the proxy SCSI controller."""
        proxy = [_lsi(), _disk(2000, 1000, 0, "[datastore0] proxy/boot.vmdk")]
        plan = build_attach_spec(proxy, "[datastore0] nvme/nvme.vmdk", read_only=True)
        disk = plan.spec.deviceChange[0].device
        assert disk.controllerKey == 1000
        assert not isinstance(disk, vim.vm.device.VirtualNVMEController)

    def test_full_bus_adds_pvscsi_controller(self) -> None:
        """A new PVSCSI controller is added when every SCSI unit is taken."""
        devices: list[vim.vm.device.VirtualDevice] = [_scsi()]
        key = 2000
        for unit in range(16):
            if unit == 7:
                continue
            devices.append(_disk(key, 1000, unit, f"[datastore0] proxy/d{unit}.vmdk"))
            key += 1
        plan = build_attach_spec(devices, "[datastore0] src/src.vmdk", read_only=True)
        assert plan.bus_number == 1
        assert plan.unit_number == 0
        assert len(plan.spec.deviceChange) == 2
        ctrl_change, disk_change = plan.spec.deviceChange
        assert ctrl_change.fileOperation is None
        assert isinstance(ctrl_change.device, vim.vm.device.ParaVirtualSCSIController)
        assert ctrl_change.device.busNumber == 1
        assert disk_change.fileOperation is None
        assert disk_change.device.controllerKey == ctrl_change.device.key
        assert disk_change.device.unitNumber == 0

    def test_pick_scsi_slot_skips_reserved_unit_seven(self) -> None:
        """SCSI unit 7 stays unused."""
        devices = [
            _scsi(),
            _disk(2000, 1000, 0, "[datastore0] proxy/boot.vmdk"),
        ]
        controller, bus, unit = pick_scsi_slot(devices)
        assert controller is not None
        assert bus == 0
        assert unit == 1
        assert unit != 7

    def test_detach_does_not_set_file_operation(self) -> None:
        """Detach must never delete the source VMDK."""
        disk = _disk(2001, 1000, 1, "[datastore0] src/src.vmdk")
        spec = build_detach_spec(disk)
        change = spec.deviceChange[0]
        assert change.operation == vim.vm.device.VirtualDeviceSpec.Operation.remove
        assert change.fileOperation is None
        assert change.device is disk


class TestScsiSysfs:
    def test_finds_device_when_linux_host_differs_from_vmware_bus(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VMware bus 0 can appear as Linux SCSI host 2."""
        block = tmp_path / "2:0:1:0" / "block" / "sdb"
        block.mkdir(parents=True)
        monkeypatch.setattr("openvixdisklib.hotadd.SCSI_DEVICE_DIR", str(tmp_path))
        assert find_scsi_block_device(0, 1) == "/dev/sdb"

    def test_offline_scsi_unit_writes_delete(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Linux keeps the LUN until sysfs delete is written."""
        device = tmp_path / "2:0:1:0"
        (device / "block" / "sdb").mkdir(parents=True)
        monkeypatch.setattr("openvixdisklib.hotadd.SCSI_DEVICE_DIR", str(tmp_path))
        _offline_scsi_unit(1)
        assert (device / "delete").read_text(encoding="ascii") == "1\n"

    def test_wait_scsi_device_gone_returns_when_sysfs_empty(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Close succeeds after the SCSI sysfs node disappears."""
        monkeypatch.setattr("openvixdisklib.hotadd.SCSI_DEVICE_DIR", str(tmp_path))
        monkeypatch.setattr("openvixdisklib.hotadd.DEVICE_POLL_S", 0.01)
        wait_scsi_device_gone(0, 1, timeout_s=1)

    def test_wait_scsi_device_gone_times_out(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Close fails if the LUN stays in sysfs after detach."""
        (tmp_path / "2:0:1:0" / "block" / "sdb").mkdir(parents=True)
        monkeypatch.setattr("openvixdisklib.hotadd.SCSI_DEVICE_DIR", str(tmp_path))
        monkeypatch.setattr("openvixdisklib.hotadd.DEVICE_POLL_S", 0.01)
        with pytest.raises(TimeoutError, match="still present"):
            wait_scsi_device_gone(0, 1, timeout_s=0.05)


class TestHotAddDiskIO:
    def test_read_write_sectors(self, tmp_path) -> None:
        """pread/pwrite round-trip 512-byte sectors on a local file."""
        path = tmp_path / "disk.img"
        path.write_bytes(b"\x00" * 1024)
        fd = os.open(path, os.O_RDWR)
        detached: list[bool] = []
        disk = HotAddDisk(fd, str(path), 0, 1, lambda: detached.append(True))
        pattern = b"OVDL-HA" * (512 // 7) + b"OVDL-HA"[: 512 % 7]
        disk.write(1, 1, pattern)
        buf = bytearray(512)
        result = disk.readinto(1, 1, buf, skip_decompression=True)
        assert bytes(buf) == pattern
        assert result.uncompressed_length == 512
        assert result.fragments == ()
        disk.close()
        assert detached == [True]
        disk.close()
        assert detached == [True]


class TestSelectTransport:
    @mock.patch("openvixdisklib.openvixdisklib.san.is_available", return_value=False)
    @mock.patch(
        "openvixdisklib.openvixdisklib.hotadd.is_vmware_guest", return_value=False
    )
    def test_colon_list_skips_hotadd_on_bare_metal(
        self, mock_guest: mock.MagicMock, mock_san: mock.MagicMock
    ) -> None:
        """Bare metal without SAN skips hotadd and uses the next usable mode."""
        del mock_guest, mock_san
        assert _select_transport("file:san:hotadd:nbdssl:nbd") == "nbdssl"
        assert _available_transports() == ["nbdssl", "nbd"]
        with pytest.raises(NotImplementedError, match="hotadd"):
            _select_transport("hotadd")

    @mock.patch("openvixdisklib.openvixdisklib.san.is_available", return_value=False)
    @mock.patch(
        "openvixdisklib.openvixdisklib.hotadd.is_vmware_guest", return_value=True
    )
    def test_colon_list_selects_hotadd_in_guest(
        self, mock_guest: mock.MagicMock, mock_san: mock.MagicMock
    ) -> None:
        """A VMware guest uses hotadd when it is first in the colon list."""
        del mock_guest, mock_san
        assert _select_transport("file:san:hotadd:nbdssl") == "hotadd"
        assert _available_transports() == ["nbdssl", "nbd", "hotadd"]

    def test_default_is_nbdssl(self) -> None:
        """None still defaults to nbdssl, even in a guest."""
        assert _select_transport(None) == "nbdssl"


def test_byteswap_uuid_matches_vmware_bios_uuid() -> None:
    """Linux DMI UUID is byte-swapped relative to vim.vm.ConfigInfo.uuid."""
    dmi = "8ac43342-7478-0792-f6c6-131b895335ba"
    bios = "4233c48a-7874-9207-f6c6-131b895335ba"
    assert _byteswap_uuid(dmi).lower() == bios
