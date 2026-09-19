# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise Changed Block Tracking against the lab.

Unlike VDDK/NFC features, these VIM-level calls (``nfc_auth.
enable_change_tracking`` / ``disk_change_id`` / ``query_changed_disk_areas``)
are thin wrappers around public pyVmomi; see ``docs/cbt.md``.
"""

from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import nfc_auth
from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import SECTOR_SIZE, LabEnv, _connect_vim, _wait_for_task, pattern_bytes


def _disk_device(vm: vim.VirtualMachine) -> vim.vm.device.VirtualDisk:
    """Return the lab VM's first virtual disk device."""
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualDisk):
            return device
    raise AssertionError(f"{vm._moId} has no virtual disk")


def _disable_change_tracking(vm: vim.VirtualMachine) -> None:
    spec = vim.vm.ConfigSpec(changeTrackingEnabled=False)
    _wait_for_task(vm.ReconfigVM_Task(spec=spec))


class TestCbt:
    def test_full_cbt_cycle(self, lab: LabEnv) -> None:
        """Enable CBT, write a known sector, and see it in a changed-areas query."""
        si = _connect_vim(
            lab.host, lab.username, lab.password, lab.port, lab.thumbprint, lab.allow_untrusted
        )
        try:
            vm = vim.VirtualMachine(lab.vm_moref, si._stub)
            nfc_auth.enable_change_tracking(vm)
            vm.Reload()
            assert vm.config.changeTrackingEnabled is True

            device_key = _disk_device(vm).key

            snap1 = _wait_for_task(
                vm.CreateSnapshot_Task("cbt-baseline", "", False, False)
            )
            vm.Reload()
            change_id_1 = nfc_auth.disk_change_id(vm, device_key)
            assert change_id_1

            write_sector = 7777
            written = pattern_bytes(SECTOR_SIZE, b"CBT-TEST")
            handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
            connect_kwargs = lab.vixdisklib_connect_kwargs(
                {"allow_untrusted": lab.allow_untrusted}
            )
            with (
                handle.connect(**connect_kwargs) as conn,
                handle.open(conn, _disk_device(vm).backing.fileName, flags=0) as disk,
            ):
                buf = vixdisklib.get_buffer(SECTOR_SIZE)
                buf[:SECTOR_SIZE] = written
                handle.write(disk, write_sector, 1, buf)

            snap2 = _wait_for_task(
                vm.CreateSnapshot_Task("cbt-after-write", "", False, False)
            )
            vm.Reload()

            result = nfc_auth.query_changed_disk_areas(
                vm, snap2, device_key, change_id_1
            )
            write_byte = write_sector * SECTOR_SIZE
            assert any(
                extent.start <= write_byte < extent.start + extent.length
                for extent in result.changed_areas
            ), f"sector {write_sector} not covered by any reported extent"
        finally:
            try:
                vm = vim.VirtualMachine(lab.vm_moref, si._stub)
                if vm.snapshot is not None:
                    _wait_for_task(vm.RemoveAllSnapshots_Task())
                _disable_change_tracking(vm)
            finally:
                Disconnect(si)

    def test_query_changed_disk_areas_wildcard_change_id(self, lab: LabEnv) -> None:
        """changeId='*' (initial full backup) reports allocated regions.

        Not the full sparse virtual capacity -- see docs/cbt.md.
        """
        si = _connect_vim(
            lab.host, lab.username, lab.password, lab.port, lab.thumbprint, lab.allow_untrusted
        )
        try:
            vm = vim.VirtualMachine(lab.vm_moref, si._stub)
            nfc_auth.enable_change_tracking(vm)
            vm.Reload()

            device_key = _disk_device(vm).key
            capacity_bytes = _disk_device(vm).capacityInKB * 1024

            snap = _wait_for_task(
                vm.CreateSnapshot_Task("cbt-wildcard", "", False, False)
            )
            vm.Reload()

            result = nfc_auth.query_changed_disk_areas(vm, snap, device_key, "*")
            # changeId="*" reports allocated (backed) regions, not the full
            # sparse virtual capacity -- this lab disk is thin-provisioned
            # and shared across the test session, so exactly how much is
            # allocated depends on what earlier tests wrote. Only the
            # length field (declared virtual capacity) is a fixed value;
            # changed_areas is just asserted sane (non-empty, in bounds).
            assert result.length == capacity_bytes
            assert result.changed_areas
            for extent in result.changed_areas:
                assert extent.start >= 0
                assert extent.start + extent.length <= capacity_bytes
        finally:
            try:
                vm = vim.VirtualMachine(lab.vm_moref, si._stub)
                if vm.snapshot is not None:
                    _wait_for_task(vm.RemoveAllSnapshots_Task())
                _disable_change_tracking(vm)
            finally:
                Disconnect(si)
