# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Unit tests for the CBT helpers in ``nfc_auth``."""

from unittest import mock

import pytest
from pyVmomi import vim

from openvixdisklib import nfc_auth


def _virtual_disk(key: int, change_id: str | None = None) -> vim.vm.device.VirtualDisk:
    disk = vim.vm.device.VirtualDisk()
    disk.key = key
    backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    if change_id is not None:
        backing.changeId = change_id
    disk.backing = backing
    return disk


def _fake_vm(devices: list) -> mock.Mock:
    vm = mock.Mock(_moId="vm-1")
    vm.config.hardware.device = devices
    return vm


class TestDiskChangeId:
    def test_returns_change_id_for_matching_device(self) -> None:
        """The changeId on the matching VirtualDisk's backing is returned."""
        disk = _virtual_disk(key=2000, change_id="52 aa/1")
        vm = _fake_vm([disk])
        assert nfc_auth.disk_change_id(vm, 2000) == "52 aa/1"

    def test_no_matching_device_key_raises(self) -> None:
        """A device key not present on the VM raises ValueError."""
        vm = _fake_vm([_virtual_disk(key=2000, change_id="52 aa/1")])
        with pytest.raises(ValueError, match="no VirtualDisk with device key 9999"):
            nfc_auth.disk_change_id(vm, 9999)

    def test_empty_change_id_raises(self) -> None:
        """A matching disk with no changeId yet (CBT not active) raises."""
        vm = _fake_vm([_virtual_disk(key=2000, change_id=None)])
        with pytest.raises(ValueError, match="has no changeId yet"):
            nfc_auth.disk_change_id(vm, 2000)


class TestQueryChangedDiskAreas:
    def test_converts_result_to_dataclasses(self) -> None:
        """QueryChangedDiskAreas's result is converted to plain dataclasses."""
        vm = mock.Mock()
        vm.QueryChangedDiskAreas.return_value = mock.Mock(
            startOffset=0,
            length=10737418240,
            changedArea=[
                mock.Mock(start=0, length=65536),
                mock.Mock(start=2555904, length=65536),
            ],
        )
        snapshot = mock.Mock()

        result = nfc_auth.query_changed_disk_areas(vm, snapshot, 2000, "52 aa/1")

        vm.QueryChangedDiskAreas.assert_called_once_with(
            snapshot=snapshot, deviceKey=2000, startOffset=0, changeId="52 aa/1"
        )
        assert result == nfc_auth.ChangedDiskAreas(
            start_offset=0,
            length=10737418240,
            changed_areas=(
                nfc_auth.ChangedExtent(start=0, length=65536),
                nfc_auth.ChangedExtent(start=2555904, length=65536),
            ),
        )

    def test_passes_through_start_offset_and_wildcard_change_id(self) -> None:
        """A non-zero start_offset and change_id='*' are passed through as-is."""
        vm = mock.Mock()
        vm.QueryChangedDiskAreas.return_value = mock.Mock(
            startOffset=1024, length=0, changedArea=[]
        )
        snapshot = mock.Mock()

        result = nfc_auth.query_changed_disk_areas(
            vm, snapshot, 2000, "*", start_offset=1024
        )

        vm.QueryChangedDiskAreas.assert_called_once_with(
            snapshot=snapshot, deviceKey=2000, startOffset=1024, changeId="*"
        )
        assert result.changed_areas == ()
