# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Lab helpers for openvixdisklib integration tests."""

from __future__ import annotations

import contextlib
import ctypes
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

import pytest
import yaml
from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import nfc_auth
from openvixdisklib.nfc_auth import NfcAuthSession

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_CONFIG_PATH = os.path.join(_REPO_ROOT, ".test_config.yaml")
_CONFIG_KEYS = (
    "host",
    "port",
    "username",
    "password",
    "allow_untrusted",
    "datacenter",
    "datastore",
)
_VDDK_DIR = os.path.join(_REPO_ROOT, ".vddk")
_VDDK_LIB = os.path.join(_VDDK_DIR, "libvixDiskLib.so")
_DISK_CAPACITY_KB = 10 * 1024 * 1024
_TASK_POLL_S = 0.5
_TASK_TIMEOUT_S = 300
_LAB_VM_PREFIX = "ovdl-test-"

VDDK_DIR = _VDDK_DIR
SECTOR_SIZE = 512
SECTOR_AT_1GB = (1024 * 1024 * 1024) // SECTOR_SIZE
SECTOR_AT_5GB = (5 * 1024 * 1024 * 1024) // SECTOR_SIZE


@dataclass
class LabEnv:
    """vCenter settings and the temporary VM used by a pytest session."""

    host: str
    port: int
    username: str
    password: str
    allow_untrusted: bool
    datacenter: str
    datastore: str
    thumbprint: str
    vm_moref: str
    vmx_spec: str
    disk_path: str

    def authenticate(
        self, read_only: bool = True, nfc_ssl: bool = True
    ) -> NfcAuthSession:
        """Login to the lab vCenter and complete NFC authd for the temp VM."""
        return nfc_auth.authenticate(
            host=self.host,
            username=self.username,
            password=self.password,
            vm_moref=self.vm_moref,
            thumbprint=self.thumbprint,
            allow_untrusted=self.allow_untrusted,
            disk_path=None if read_only else self.disk_path,
            read_only=read_only,
            nfc_ssl=nfc_ssl,
        )

    def vixdisklib_connect_kwargs(
        self, extra: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Return common ``VixDiskLib_ConnectEx`` arguments for the temp VM."""
        kwargs: dict[str, Any] = {
            "server_name": self.host,
            "port": self.port,
            "thumbprint": self.thumbprint,
            "username": self.username,
            "password": self.password,
            "vmx_spec": self.vmx_spec,
            "transport_modes": "nbdssl",
            "read_only": False,
        }
        if extra:
            kwargs.update(extra)
        return kwargs


def pattern_bytes(length: int, seed: bytes) -> bytes:
    """Return ``length`` bytes by repeating ``seed``."""
    if not seed:
        raise ValueError("seed must be non-empty")
    return (seed * ((length // len(seed)) + 1))[:length]


def ensure_vddk_library_path() -> None:
    """Prepend ``.vddk`` to ``LD_LIBRARY_PATH`` if it is not already there."""
    current = os.environ.get("LD_LIBRARY_PATH", "")
    parts = [p for p in current.split(":") if p]
    if VDDK_DIR not in parts:
        os.environ["LD_LIBRARY_PATH"] = (
            VDDK_DIR if not current else f"{VDDK_DIR}:{current}"
        )


def require_vddk() -> None:
    """Skip when ``libvixDiskLib`` cannot be loaded from ``.vddk``."""
    ensure_vddk_library_path()
    try:
        ctypes.CDLL(_VDDK_LIB)
    except OSError as exc:
        pytest.skip(f"VDDK library not available at {_VDDK_LIB}: {exc}")


def _load_test_config() -> dict[str, Any]:
    if not os.path.isfile(_CONFIG_PATH):
        pytest.skip(
            "integration tests need .test_config.yaml in the repo "
            "root; see README.md for a sample"
        )
    with open(_CONFIG_PATH, encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    missing = [key for key in _CONFIG_KEYS if key not in data]
    if missing:
        raise RuntimeError(f"{_CONFIG_PATH} is missing keys: {', '.join(missing)}")
    return {
        "host": str(data["host"]),
        "port": int(data["port"]),
        "username": str(data["username"]),
        "password": str(data["password"]),
        "allow_untrusted": bool(data["allow_untrusted"]),
        "datacenter": str(data["datacenter"]),
        "datastore": str(data["datastore"]),
    }


def _connect_vim(
    host: str,
    username: str,
    password: str,
    port: int,
    thumbprint: str,
    allow_untrusted: bool,
) -> vim.ServiceInstance:
    return nfc_auth.connect_vim(
        host,
        username,
        password,
        port=port,
        thumbprint=thumbprint,
        allow_untrusted=allow_untrusted,
    )


def _esxi_direct_credentials(vc_password: str) -> tuple[str, str]:
    """Return ESXi hostd credentials for direct-connect tests.

    Optional ``esxi.username`` / ``esxi.password`` in ``.test_config.yaml``
    override the defaults (``root`` and the vCenter password).
    """
    if not os.path.isfile(_CONFIG_PATH):
        return "root", vc_password
    with open(_CONFIG_PATH, encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    section = data.get("esxi")
    if not isinstance(section, dict):
        section = {}
    username = str(section["username"]) if section.get("username") else "root"
    password = str(section["password"]) if section.get("password") else vc_password
    return username, password


def _host_management_ip(host: vim.HostSystem) -> str:
    vnics = list(host.config.network.vnic or [])
    for vnic in vnics:
        ip = vnic.spec.ip.ipAddress if vnic.spec.ip else None
        if ip and vnic.device == "vmk0":
            return str(ip)
    for vnic in vnics:
        ip = vnic.spec.ip.ipAddress if vnic.spec.ip else None
        if ip:
            return str(ip)
    if host.name:
        return str(host.name)
    raise RuntimeError(f"no management IPv4 on host {host._moId}")


def resolve_direct_esxi_lab(lab: LabEnv) -> LabEnv:
    """Return a ``LabEnv`` that talks to the lab VM's ESXi host, not vCenter.

    The host is the one ``lab``'s VM is registered on. Hostd credentials
    default to ``root`` plus the vCenter password. Tests should skip when
    lockdown is on or hostd login fails.
    """
    si = _connect_vim(
        lab.host,
        lab.username,
        lab.password,
        lab.port,
        lab.thumbprint,
        lab.allow_untrusted,
    )
    esxi_host = ""
    instance_uuid = ""
    try:
        if si.content.about.apiType == "HostAgent":
            return lab
        vm = vim.VirtualMachine(lab.vm_moref, si._stub)
        host = vm.runtime.host
        lockdown = str(getattr(host.config, "lockdownMode", "") or "")
        if lockdown and not lockdown.endswith("lockdownDisabled"):
            pytest.skip(f"ESXi {host.name} is in lockdown ({lockdown})")
        esxi_host = _host_management_ip(host)
        instance_uuid = vm.config.instanceUuid
        if not instance_uuid:
            pytest.skip(f"lab VM {lab.vm_moref} has no instanceUuid")
    finally:
        Disconnect(si)

    username, password = _esxi_direct_credentials(lab.password)
    try:
        thumbprint = nfc_auth.get_ssl_cert_thumbprint(esxi_host, lab.port)
    except OSError as exc:
        pytest.skip(f"cannot reach ESXi {esxi_host}: {exc}")
    try:
        esxi_si = _connect_vim(
            esxi_host,
            username,
            password,
            lab.port,
            thumbprint,
            lab.allow_untrusted,
        )
    except vim.fault.InvalidLogin:
        pytest.skip(
            f"direct ESXi login to {esxi_host} failed; set esxi.username / "
            "esxi.password in .test_config.yaml"
        )
    except vim.fault.NoPermission:
        pytest.skip(
            f"ESXi user has no hostd privileges on {esxi_host}; set "
            "esxi.username / esxi.password in .test_config.yaml"
        )
    except OSError as exc:
        pytest.skip(f"cannot connect to ESXi {esxi_host}: {exc}")
    try:
        if esxi_si.content.about.apiType != "HostAgent":
            pytest.skip(
                f"{esxi_host} apiType is {esxi_si.content.about.apiType}, not HostAgent"
            )
        found = esxi_si.content.searchIndex.FindByUuid(None, instance_uuid, True, True)
        if found is None:
            pytest.skip(
                f"lab VM instanceUuid {instance_uuid} not found on ESXi {esxi_host}"
            )
        return LabEnv(
            host=esxi_host,
            port=lab.port,
            username=username,
            password=password,
            allow_untrusted=lab.allow_untrusted,
            datacenter=lab.datacenter,
            datastore=lab.datastore,
            thumbprint=thumbprint,
            vm_moref=found._moId,
            vmx_spec=f"moref={found._moId}",
            disk_path=lab.disk_path,
        )
    finally:
        Disconnect(esxi_si)


def _wait_for_task(task: vim.Task) -> Any:
    deadline = time.monotonic() + _TASK_TIMEOUT_S
    while task.info.state in (vim.TaskInfo.State.running, vim.TaskInfo.State.queued):
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for vSphere task {task}")
        time.sleep(_TASK_POLL_S)
    if task.info.state != vim.TaskInfo.State.success:
        raise RuntimeError(f"vSphere task failed: {task.info.error}")
    return task.info.result


def _find_datacenter(
    content: vim.ServiceInstanceContent, datacenter_name: str
) -> vim.Datacenter:
    matches = [
        entity
        for entity in content.rootFolder.childEntity
        if isinstance(entity, vim.Datacenter) and entity.name == datacenter_name
    ]
    if not matches:
        raise RuntimeError(f"datacenter {datacenter_name!r} not found")
    return matches[0]


def _find_datastore(datacenter: vim.Datacenter, datastore_name: str) -> vim.Datastore:
    matches = [
        datastore
        for datastore in datacenter.datastore
        if datastore.name == datastore_name
    ]
    if not matches:
        raise RuntimeError(
            f"datastore {datastore_name!r} not found in datacenter {datacenter.name!r}"
        )
    return matches[0]


def _vm_config_spec(vm_name: str, datastore_name: str) -> vim.vm.ConfigSpec:
    config = vim.vm.ConfigSpec()
    config.name = vm_name
    config.guestId = "otherGuest64"
    config.memoryMB = 128
    config.numCPUs = 1
    config.files = vim.vm.FileInfo(vmPathName=f"[{datastore_name}]")

    controller = vim.vm.device.ParaVirtualSCSIController()
    controller.key = 1000
    controller.busNumber = 0
    controller.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
    controller_spec = vim.vm.device.VirtualDeviceSpec()
    controller_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    controller_spec.device = controller

    backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    backing.diskMode = "persistent"
    backing.thinProvisioned = True
    backing.fileName = f"[{datastore_name}]"
    disk = vim.vm.device.VirtualDisk()
    disk.key = 2000
    disk.controllerKey = 1000
    disk.unitNumber = 0
    disk.capacityInKB = _DISK_CAPACITY_KB
    disk.backing = backing
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
    disk_spec.device = disk

    config.deviceChange = [controller_spec, disk_spec]
    return config


def create_lab_vm() -> LabEnv:
    """Create an empty VM with a 10 GiB thin disk for I/O tests."""
    cfg = _load_test_config()
    thumbprint = nfc_auth.get_ssl_cert_thumbprint(cfg["host"], cfg["port"])
    si = _connect_vim(
        cfg["host"],
        cfg["username"],
        cfg["password"],
        cfg["port"],
        thumbprint,
        cfg["allow_untrusted"],
    )
    vm = None
    try:
        content = si.RetrieveContent()
        datacenter = _find_datacenter(content, cfg["datacenter"])
        datastore = _find_datastore(datacenter, cfg["datastore"])
        if not datastore.host:
            raise RuntimeError(
                f"datastore {cfg['datastore']!r} is not mounted on any host"
            )
        host = datastore.host[0].key
        pool = host.parent.resourcePool
        vm_name = _LAB_VM_PREFIX + uuid.uuid4().hex[:12]
        vm = _wait_for_task(
            datacenter.vmFolder.CreateVM_Task(
                config=_vm_config_spec(vm_name, datastore.name), pool=pool, host=host
            )
        )
        disks = [
            device.backing.fileName
            for device in vm.config.hardware.device
            if isinstance(device, vim.vm.device.VirtualDisk)
        ]
        if not disks:
            raise RuntimeError(f"temporary VM {vm_name!r} has no virtual disks")
        return LabEnv(
            host=cfg["host"],
            port=cfg["port"],
            username=cfg["username"],
            password=cfg["password"],
            allow_untrusted=cfg["allow_untrusted"],
            datacenter=cfg["datacenter"],
            datastore=cfg["datastore"],
            thumbprint=thumbprint,
            vm_moref=vm._moId,
            vmx_spec=f"moref={vm._moId}",
            disk_path=disks[0],
        )
    except Exception:
        if vm is not None:
            with contextlib.suppress(Exception):
                _wait_for_task(vm.Destroy_Task())
        raise
    finally:
        Disconnect(si)


def destroy_lab_vm(lab: LabEnv) -> None:
    """Power off and delete the temporary lab VM if it still exists."""
    si = _connect_vim(
        lab.host,
        lab.username,
        lab.password,
        lab.port,
        lab.thumbprint,
        lab.allow_untrusted,
    )
    try:
        vm = vim.VirtualMachine(lab.vm_moref, si._stub)
        try:
            vm.Reload()
        except Exception:
            return
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            _wait_for_task(vm.PowerOffVM_Task())
        _wait_for_task(vm.Destroy_Task())
    finally:
        Disconnect(si)
