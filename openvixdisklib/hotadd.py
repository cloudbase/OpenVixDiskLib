# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Linux-guest HotAdd transport: SCSI-attach a VMDK and read it locally.

The source disk may sit on SCSI, NVMe, or SATA in the backup VM. This
module always HotAdds that backing onto a SCSI controller of the proxy
VM (the guest running this process), then I/Os ``/dev/sdX``. IDE disks
and RDMs are not supported.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pyVmomi import vim

from openvixdisklib.nfc_open import ReadResult

LOG = logging.getLogger(__name__)

SECTOR_SIZE = 512
SCSI_RESERVED_UNIT = 7
SCSI_MAX_UNIT = 15
SCSI_MAX_BUS = 3
SCSI_CHANNEL = 0
SCSI_LUN = 0
TASK_POLL_S = 0.5
TASK_TIMEOUT_S = 300
DEVICE_WAIT_S = 120
DEVICE_POLL_S = 0.5
DMI_VENDOR_PATH = "/sys/class/dmi/id/sys_vendor"
DMI_UUID_PATH = "/sys/class/dmi/id/product_uuid"
SCSI_HOST_DIR = "/sys/class/scsi_host"
SCSI_DEVICE_DIR = "/sys/bus/scsi/devices"


def is_vmware_guest() -> bool:
    """Return True when this process is running in a VMware guest."""
    vendor = _read_sysfs(DMI_VENDOR_PATH)
    return vendor is not None and "vmware" in vendor.lower()


def _read_sysfs(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def guest_uuid() -> str:
    """Return the SMBIOS UUID of this guest, or raise if it is missing."""
    uuid = _read_sysfs(DMI_UUID_PATH)
    if not uuid:
        raise RuntimeError(f"cannot read guest UUID from {DMI_UUID_PATH}")
    return uuid


def _byteswap_uuid(uuid: str) -> str:
    hexpart = uuid.replace("-", "")
    if len(hexpart) != 32:
        return uuid

    def _rev(field: str) -> str:
        return "".join(reversed([field[i : i + 2] for i in range(0, len(field), 2)]))

    swapped = (
        _rev(hexpart[0:8]) + _rev(hexpart[8:12]) + _rev(hexpart[12:16]) + hexpart[16:]
    )
    return (
        f"{swapped[0:8]}-{swapped[8:12]}-{swapped[12:16]}-"
        f"{swapped[16:20]}-{swapped[20:]}"
    )


def find_proxy_vm(si: vim.ServiceInstance) -> vim.VirtualMachine:
    """Locate the VM this process is running in via the BIOS UUID."""
    uuid = guest_uuid()
    search = si.RetrieveContent().searchIndex
    candidates = (uuid, uuid.lower(), uuid.upper(), _byteswap_uuid(uuid))
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        for instance_uuid in (False, True):
            vm = search.FindByUuid(None, candidate, True, instance_uuid)
            if vm is not None:
                return vm
    raise RuntimeError(f"no VM in this vCenter has UUID {uuid}")


def _controller_map(
    devices: Iterable[vim.vm.device.VirtualDevice],
) -> dict[int, vim.vm.device.VirtualController]:
    return {
        device.key: device
        for device in devices
        if isinstance(device, vim.vm.device.VirtualController)
    }


def _is_file_backed(disk: vim.vm.device.VirtualDisk) -> bool:
    backing = disk.backing
    if backing is None or not getattr(backing, "fileName", None):
        return False
    name = type(backing).__name__
    return "RawDisk" not in name


def _controller_supported(controller: vim.vm.device.VirtualController | None) -> bool:
    if controller is None:
        return False
    if isinstance(controller, vim.vm.device.VirtualIDEController):
        return False
    return isinstance(
        controller,
        (
            vim.vm.device.VirtualSCSIController,
            vim.vm.device.VirtualNVMEController,
            vim.vm.device.VirtualAHCIController,
        ),
    )


def _snapshot_moref(snapshot_ref: str) -> str:
    if "=" in snapshot_ref:
        kind, value = snapshot_ref.split("=", 1)
        if kind.lower() != "moref" or not value:
            raise ValueError(f"unsupported snapshot_ref: {snapshot_ref}")
        return value
    return snapshot_ref


def _walk_snapshots(
    trees: list[vim.vm.SnapshotTree] | None, moref: str
) -> vim.vm.SnapshotTree | None:
    for tree in trees or []:
        if tree.snapshot._moId == moref:
            return tree
        found = _walk_snapshots(tree.childSnapshotList, moref)
        if found is not None:
            return found
    return None


def source_devices(
    vm: vim.VirtualMachine, snapshot_ref: str | None
) -> list[vim.vm.device.VirtualDevice]:
    """Return hardware devices of ``vm``, or of ``snapshot_ref`` when set."""
    if snapshot_ref:
        if vm.snapshot is None:
            raise RuntimeError(f"{vm._moId} has no snapshots")
        moref = _snapshot_moref(snapshot_ref)
        tree = _walk_snapshots(vm.snapshot.rootSnapshotList, moref)
        if tree is None:
            raise RuntimeError(f"snapshot {moref} not found on {vm._moId}")
        return list(tree.config.hardware.device)
    return list(vm.config.hardware.device)


def find_source_disk(
    devices: Iterable[vim.vm.device.VirtualDevice], disk_path: str
) -> vim.vm.device.VirtualDisk:
    """Return the file-backed disk whose backing path is ``disk_path``.

    SCSI, NVMe, and SATA controllers are accepted. IDE and RDM backings
    raise ``NotImplementedError``.
    """
    controllers = _controller_map(devices)
    for device in devices:
        if not isinstance(device, vim.vm.device.VirtualDisk):
            continue
        backing = device.backing
        if getattr(backing, "fileName", None) != disk_path:
            continue
        if not _is_file_backed(device):
            raise NotImplementedError(
                f"HotAdd does not support RDM or raw backings: {disk_path}"
            )
        controller = controllers.get(device.controllerKey)
        if isinstance(controller, vim.vm.device.VirtualIDEController):
            raise NotImplementedError(f"HotAdd does not support IDE disks: {disk_path}")
        if not _controller_supported(controller):
            kind = type(controller).__name__ if controller else "missing controller"
            raise NotImplementedError(
                f"HotAdd does not support {kind} disks: {disk_path}"
            )
        return device
    raise FileNotFoundError(f"no virtual disk with backing {disk_path!r}")


def _scsi_controllers(
    devices: Iterable[vim.vm.device.VirtualDevice],
) -> list[vim.vm.device.VirtualSCSIController]:
    return [
        device
        for device in devices
        if isinstance(device, vim.vm.device.VirtualSCSIController)
    ]


def _used_units(
    devices: Iterable[vim.vm.device.VirtualDevice], controller_key: int
) -> set[int]:
    return {
        device.unitNumber
        for device in devices
        if isinstance(device, vim.vm.device.VirtualDisk)
        and device.controllerKey == controller_key
        and device.unitNumber is not None
    }


def pick_scsi_slot(
    devices: Iterable[vim.vm.device.VirtualDevice],
) -> tuple[vim.vm.device.VirtualSCSIController | None, int, int]:
    """Return ``(controller, bus, unit)`` for a free SCSI slot.

    ``controller`` is ``None`` when a new PVSCSI controller must be
    added on ``bus``; ``unit`` is then 0.
    """
    device_list = list(devices)
    for controller in sorted(_scsi_controllers(device_list), key=lambda c: c.busNumber):
        used = _used_units(device_list, controller.key)
        for unit in range(SCSI_MAX_UNIT + 1):
            if unit == SCSI_RESERVED_UNIT:
                continue
            if unit not in used:
                return controller, int(controller.busNumber), unit
    used_buses = {controller.busNumber for controller in _scsi_controllers(device_list)}
    for bus in range(SCSI_MAX_BUS + 1):
        if bus not in used_buses:
            return None, bus, 0
    raise RuntimeError("no free SCSI controller bus on the HotAdd proxy")


@dataclass
class AttachPlan:
    """ReconfigureVM spec plus the SCSI address the guest should see."""

    spec: vim.vm.ConfigSpec
    bus_number: int
    unit_number: int
    file_name: str


def build_attach_spec(
    devices: Iterable[vim.vm.device.VirtualDevice],
    file_name: str,
    read_only: bool,
    capacity_kb: int | None = None,
) -> AttachPlan:
    """Build a SCSI HotAdd spec for an existing VMDK backing.

    Never sets ``fileOperation`` (the VMDK already exists). Read-only
    opens use ``independent_nonpersistent``; writable opens use
    ``persistent``.
    """
    device_list = list(devices)
    controller, bus, unit = pick_scsi_slot(device_list)
    changes: list[vim.vm.device.VirtualDeviceSpec] = []
    if controller is None:
        new_controller = vim.vm.device.ParaVirtualSCSIController()
        new_controller.key = -101
        new_controller.busNumber = bus
        new_controller.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
        if hasattr(new_controller, "hotAddRemove"):
            new_controller.hotAddRemove = True
        controller_spec = vim.vm.device.VirtualDeviceSpec()
        controller_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        controller_spec.device = new_controller
        changes.append(controller_spec)
        controller_key = new_controller.key
    else:
        controller_key = controller.key

    backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    backing.fileName = file_name
    backing.diskMode = "independent_nonpersistent" if read_only else "persistent"

    disk = vim.vm.device.VirtualDisk()
    disk.key = -201
    disk.controllerKey = controller_key
    disk.unitNumber = unit
    disk.backing = backing
    if capacity_kb:
        disk.capacityInKB = capacity_kb
    disk.deviceInfo = vim.Description()
    disk.deviceInfo.label = "openvixdisklib-hotadd"
    disk.deviceInfo.summary = file_name

    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.device = disk
    changes.append(disk_spec)

    spec = vim.vm.ConfigSpec()
    spec.deviceChange = changes
    return AttachPlan(spec=spec, bus_number=bus, unit_number=unit, file_name=file_name)


def build_detach_spec(device: vim.vm.device.VirtualDisk) -> vim.vm.ConfigSpec:
    """Build a remove spec that detaches ``device`` without deleting files."""
    change = vim.vm.device.VirtualDeviceSpec()
    change.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
    change.device = device
    spec = vim.vm.ConfigSpec()
    spec.deviceChange = [change]
    return spec


def _wait_for_task(task: vim.Task) -> object:
    deadline = time.monotonic() + TASK_TIMEOUT_S
    while task.info.state in (vim.TaskInfo.State.running, vim.TaskInfo.State.queued):
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for vSphere task {task}")
        time.sleep(TASK_POLL_S)
    if task.info.state != vim.TaskInfo.State.success:
        raise RuntimeError(f"vSphere task failed: {task.info.error}")
    return task.info.result


def _boot_disk_path(devices: Iterable[vim.vm.device.VirtualDevice]) -> str | None:
    for device in devices:
        if isinstance(device, vim.vm.device.VirtualDisk):
            return getattr(device.backing, "fileName", None)
    return None


def _disks_with_backing(
    devices: Iterable[vim.vm.device.VirtualDevice], file_name: str
) -> list[vim.vm.device.VirtualDisk]:
    matches = []
    for device in devices:
        if not isinstance(device, vim.vm.device.VirtualDisk):
            continue
        if getattr(device.backing, "fileName", None) == file_name:
            matches.append(device)
    return matches


def _reconfigure(vm: vim.VirtualMachine, spec: vim.vm.ConfigSpec) -> None:
    _wait_for_task(vm.ReconfigVM_Task(spec))
    vm.Reload()


def _detach_device(vm: vim.VirtualMachine, device: vim.vm.device.VirtualDisk) -> None:
    LOG.info(
        "HotAdd detach %s unit=%s from %s",
        getattr(device.backing, "fileName", None),
        device.unitNumber,
        vm._moId,
    )
    _reconfigure(vm, build_detach_spec(device))


def _scsi_sysfs(bus: int, unit: int) -> str:
    return os.path.join(
        SCSI_DEVICE_DIR, f"{bus}:{SCSI_CHANNEL}:{unit}:{SCSI_LUN}", "block"
    )


def _block_names(sysfs_dir: str) -> list[str]:
    try:
        return [
            name
            for name in os.listdir(sysfs_dir)
            if not name.startswith(".") and os.path.isdir(os.path.join(sysfs_dir, name))
        ]
    except OSError:
        return []


def _scsi_block_dirs(unit: int) -> list[str]:
    """Return sysfs ``block`` dirs for SCSI target ``unit`` (any host)."""
    found: list[str] = []
    try:
        names = os.listdir(SCSI_DEVICE_DIR)
    except OSError:
        return found
    suffix = f":{SCSI_CHANNEL}:{unit}:{SCSI_LUN}"
    for name in names:
        if not name.endswith(suffix):
            continue
        block = os.path.join(SCSI_DEVICE_DIR, name, "block")
        if os.path.isdir(block):
            found.append(block)
    return found


def list_scsi_block_devices() -> set[str]:
    """Return guest ``/dev`` paths for every SCSI block device."""
    found: set[str] = set()
    try:
        names = os.listdir(SCSI_DEVICE_DIR)
    except OSError:
        return found
    for name in names:
        block = os.path.join(SCSI_DEVICE_DIR, name, "block")
        for dev in _block_names(block):
            found.add(f"/dev/{dev}")
    return found


def find_scsi_block_device(
    bus: int, unit: int, before: set[str] | None = None
) -> str | None:
    """Return ``/dev/sdX`` for the HotAdded SCSI disk, if present.

    Linux SCSI host numbers often do not match VMware bus numbers.
    Matching uses ``/sys/bus/scsi/devices/<host>:0:<unit>:0/block``.
    """
    exact = _scsi_sysfs(bus, unit)
    names = _block_names(exact)
    if names:
        return f"/dev/{names[0]}"
    matches = _scsi_block_dirs(unit)
    candidates: list[str] = []
    for block_dir in matches:
        candidates.extend(f"/dev/{name}" for name in _block_names(block_dir))
    if before is not None:
        new = [path for path in candidates if path not in before]
        if len(new) == 1:
            return new[0]
        appeared = list_scsi_block_devices() - before
        if len(appeared) == 1:
            return appeared.pop()
    if len(candidates) == 1:
        return candidates[0]
    return None


def rescan_scsi_hosts() -> None:
    """Ask every SCSI host to scan for new LUNs."""
    if not os.path.isdir(SCSI_HOST_DIR):
        return
    for host in os.listdir(SCSI_HOST_DIR):
        scan = os.path.join(SCSI_HOST_DIR, host, "scan")
        try:
            with open(scan, "w", encoding="ascii") as handle:
                handle.write("- - -\n")
        except OSError:
            continue


def wait_for_scsi_device(
    bus: int,
    unit: int,
    timeout_s: float = DEVICE_WAIT_S,
    before: set[str] | None = None,
) -> str:
    """Rescan SCSI and wait until the HotAdded disk has a block device."""
    deadline = time.monotonic() + timeout_s
    last: str | None = None
    while time.monotonic() < deadline:
        rescan_scsi_hosts()
        last = find_scsi_block_device(bus, unit, before=before)
        if last and os.path.exists(last):
            return last
        time.sleep(DEVICE_POLL_S)
    raise TimeoutError(
        f"HotAdded disk did not appear at SCSI {bus}:0:{unit}:0 ({last})"
    )


def _offline_scsi_unit(unit: int) -> None:
    """Ask Linux to drop SCSI devices with target ``unit``."""
    for block_dir in _scsi_block_dirs(unit):
        delete_path = os.path.join(os.path.dirname(block_dir), "delete")
        try:
            with open(delete_path, "w", encoding="ascii") as handle:
                handle.write("1\n")
        except OSError:
            continue


def wait_scsi_device_gone(
    bus: int, unit: int, timeout_s: float = DEVICE_WAIT_S
) -> None:
    """Wait until the SCSI device sysfs node disappears after detach."""
    del bus
    _offline_scsi_unit(unit)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not _scsi_block_dirs(unit):
            return
        _offline_scsi_unit(unit)
        time.sleep(DEVICE_POLL_S)
    raise TimeoutError(f"HotAdded disk still present at SCSI unit {unit}")


def _pread_all(fd: int, size: int, offset: int) -> bytes:
    chunks = bytearray()
    remaining = size
    pos = offset
    while remaining:
        data = os.pread(fd, remaining, pos)
        if not data:
            raise OSError(f"short read at offset {pos}: got {len(chunks)} of {size}")
        chunks.extend(data)
        remaining -= len(data)
        pos += len(data)
    return bytes(chunks)


def _pwrite_all(fd: int, data: bytes, offset: int) -> None:
    remaining = memoryview(data)
    pos = offset
    while remaining:
        written = os.pwrite(fd, remaining, pos)
        if written <= 0:
            raise OSError(f"short write at offset {pos}")
        remaining = remaining[written:]
        pos += written


class HotAddDisk:
    """A locally attached HotAdd VMDK opened as a SCSI block device."""

    def __init__(
        self,
        fd: int,
        dev_path: str,
        bus_number: int,
        unit_number: int,
        detach: Callable[[], None],
        sector_size: int = SECTOR_SIZE,
    ) -> None:
        """Wrap an open block-device fd and a detach callback.

        Args:
            fd: File descriptor for the SCSI disk.
            dev_path: Guest path such as ``/dev/sdb``.
            bus_number: VMware SCSI bus of the attached disk.
            unit_number: VMware SCSI unit of the attached disk.
            detach: Called from ``close`` after the fd is closed.
            sector_size: Sector size in bytes (VDDK uses 512).
        """
        self._fd = fd
        self.dev_path = dev_path
        self.bus_number = bus_number
        self.unit_number = unit_number
        self._detach = detach
        self.sector_size = sector_size
        self._closed = False

    def readinto(
        self,
        start_sector: int,
        num_sectors: int,
        buf: bytearray | memoryview,
        skip_decompression: bool = False,
    ) -> ReadResult:
        """Read ``num_sectors`` into ``buf`` starting at ``start_sector``.

        ``skip_decompression`` is an NFC option and is ignored; HotAdd
        has no compressed extras. ``fragments`` is always empty.

        Args:
            start_sector: Sector offset from the start of the disk.
            num_sectors: Number of sectors to read.
            buf: Destination buffer.
            skip_decompression: Ignored; accepted for API compatibility.
        """
        del skip_decompression
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        length = num_sectors * self.sector_size
        view = buf if isinstance(buf, memoryview) else memoryview(buf)
        if view.readonly:
            raise TypeError("read buffer is read-only")
        raw = view.cast("B") if view.format != "B" else view
        if len(raw) < length:
            raise RuntimeError(f"read buffer is {len(raw)} bytes, need {length}")
        data = _pread_all(self._fd, length, start_sector * self.sector_size)
        raw[:length] = data
        return ReadResult(
            uncompressed_length=length, compressed_length=length, fragments=()
        )

    def write(self, start_sector: int, num_sectors: int, data: bytes) -> None:
        """Write ``num_sectors`` starting at ``start_sector``.

        Args:
            start_sector: Sector offset from the start of the disk.
            num_sectors: Number of sectors to write.
            data: Bytes to write; length must be ``num_sectors * sector_size``.
        """
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        length = num_sectors * self.sector_size
        if len(data) != length:
            raise ValueError(f"write data is {len(data)} bytes, need {length}")
        _pwrite_all(self._fd, data, start_sector * self.sector_size)
        os.fsync(self._fd)

    def close(self) -> None:
        """Close the block device and detach the VMDK from the proxy."""
        if self._closed:
            return
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._detach()
        self._closed = True

    def __enter__(self) -> HotAddDisk:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def open_disk(
    si: vim.ServiceInstance,
    source_vm: vim.VirtualMachine,
    disk_path: str,
    snapshot_ref: str | None = None,
    read_only: bool = True,
) -> HotAddDisk:
    """HotAdd ``disk_path`` from ``source_vm`` onto this guest and open it.

    The source VM must be powered off, or ``snapshot_ref`` must name a
    snapshot whose hardware contains ``disk_path``. The disk is always
    attached to a SCSI controller on the proxy.

    Args:
        si: Logged-in VIM session.
        source_vm: VM that owns ``disk_path``.
        disk_path: Datastore path of the VMDK.
        snapshot_ref: Snapshot moref required when ``source_vm`` is on.
        read_only: Independent-nonpersistent attach when True.
    """
    if not is_vmware_guest():
        raise RuntimeError("HotAdd requires a VMware guest (the backup proxy)")
    if (
        source_vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn
        and not snapshot_ref
    ):
        raise RuntimeError(
            "snapshot_ref is required to HotAdd a powered-on virtual machine"
        )

    proxy = find_proxy_vm(si)
    proxy_devices = list(proxy.config.hardware.device)
    boot_path = _boot_disk_path(proxy_devices)
    if boot_path == disk_path:
        raise RuntimeError("refusing to HotAdd the proxy VM's boot disk")

    for leftover in _disks_with_backing(proxy_devices, disk_path):
        LOG.warning("detaching leftover HotAdd disk %s from %s", disk_path, proxy._moId)
        _detach_device(proxy, leftover)
        proxy_devices = list(proxy.config.hardware.device)

    devices = source_devices(source_vm, snapshot_ref)
    source = find_source_disk(devices, disk_path)
    capacity = getattr(source, "capacityInKB", None)
    plan = build_attach_spec(
        proxy_devices, disk_path, read_only=read_only, capacity_kb=capacity
    )
    LOG.info(
        "HotAdd attach %s onto %s SCSI %s:%s read_only=%s",
        disk_path,
        proxy._moId,
        plan.bus_number,
        plan.unit_number,
        read_only,
    )
    attached: vim.vm.device.VirtualDisk | None = None
    before = list_scsi_block_devices()
    try:
        _reconfigure(proxy, plan.spec)
        matches = _disks_with_backing(proxy.config.hardware.device, disk_path)
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one attached disk {disk_path!r}, found {len(matches)}"
            )
        attached = matches[0]
        bus = plan.bus_number
        unit = plan.unit_number
        controllers = _controller_map(proxy.config.hardware.device)
        controller = controllers.get(attached.controllerKey)
        if isinstance(controller, vim.vm.device.VirtualSCSIController):
            bus = int(controller.busNumber)
            unit = int(attached.unitNumber)
        dev_path = wait_for_scsi_device(bus, unit, before=before)
        flags = os.O_RDONLY if read_only else os.O_RDWR
        fd = os.open(dev_path, flags)
    except Exception:
        victim = attached
        if victim is None:
            leftovers = _disks_with_backing(proxy.config.hardware.device, disk_path)
            victim = leftovers[0] if leftovers else None
        if victim is not None:
            _detach_best_effort(proxy, victim)
        raise

    def _detach() -> None:
        try:
            _detach_device(proxy, attached)
        finally:
            wait_scsi_device_gone(bus, unit)

    return HotAddDisk(fd, dev_path, bus, unit, _detach)


def _detach_best_effort(
    vm: vim.VirtualMachine, device: vim.vm.device.VirtualDisk
) -> None:
    """Detach ``device`` after a failed open; log and ignore errors."""
    try:
        _detach_device(vm, device)
        unit = device.unitNumber
        if unit is not None:
            _offline_scsi_unit(int(unit))
    except Exception:
        LOG.exception("HotAdd cleanup after failed open")
