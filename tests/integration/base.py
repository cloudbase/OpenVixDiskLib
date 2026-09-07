# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Test base classes for openvixdisklib integration tests."""

from __future__ import annotations

import ctypes
import os
import time
import unittest
import uuid
from typing import Any, Optional

import yaml
from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import nfc_auth
from openvixdisklib.nfc_auth import NfcAuthSession

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
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


class TestBase(unittest.TestCase):
    """Shared lab vSphere settings for live NFC / VDDK integration tests."""

    HOST: str
    PORT: int
    USERNAME: str
    PASSWORD: str
    ALLOW_UNTRUSTED: bool
    DATACENTER: str
    DATASTORE: str
    THUMBPRINT: str
    VM_MOREF: str
    VMX_SPEC: str
    DISK_PATH: str
    SECTOR_SIZE = 512
    SECTOR_AT_1GB = (1024 * 1024 * 1024) // SECTOR_SIZE
    VDDK_DIR = _VDDK_DIR
    _lab_refcount = 0
    _lab_vm_moref: Optional[str] = None
    _lab_vm_name: Optional[str] = None

    @classmethod
    def setUpClass(cls) -> None:
        """Prepare process environment and create a temporary lab VM."""
        super().setUpClass()
        os.environ.pop("LD_PRELOAD", None)
        cls._ensure_vddk_library_path()
        TestBase._acquire_lab()

    @classmethod
    def tearDownClass(cls) -> None:
        """Release the temporary lab VM when the last test class finishes."""
        TestBase._release_lab()
        super().tearDownClass()

    def setUp(self) -> None:
        """Reset per-test state; subclasses may reuse this."""
        super().setUp()

    @classmethod
    def _ensure_vddk_library_path(cls) -> None:
        current = os.environ.get("LD_LIBRARY_PATH", "")
        parts = [p for p in current.split(":") if p]
        if cls.VDDK_DIR not in parts:
            os.environ["LD_LIBRARY_PATH"] = (
                cls.VDDK_DIR if not current else f"{cls.VDDK_DIR}:{current}")

    @classmethod
    def require_vddk(cls) -> None:
        """Skip when ``libvixDiskLib`` cannot be loaded from ``.vddk``."""
        cls._ensure_vddk_library_path()
        try:
            ctypes.CDLL(_VDDK_LIB)
        except OSError as exc:
            raise unittest.SkipTest(
                f"VDDK library not available at {_VDDK_LIB}: {exc}") from exc

    @classmethod
    def _load_test_config(cls) -> None:
        """Load lab settings from the repo-root ``.test_config.yaml``."""
        if not os.path.isfile(_CONFIG_PATH):
            raise unittest.SkipTest(
                "integration tests need .test_config.yaml in the repo "
                "root; see README.md for a sample")
        with open(_CONFIG_PATH, encoding="utf-8") as config_file:
            data = yaml.safe_load(config_file) or {}
        missing = [key for key in _CONFIG_KEYS if key not in data]
        if missing:
            raise RuntimeError(
                f"{_CONFIG_PATH} is missing keys: {', '.join(missing)}")
        TestBase.HOST = str(data["host"])
        TestBase.PORT = int(data["port"])
        TestBase.USERNAME = str(data["username"])
        TestBase.PASSWORD = str(data["password"])
        TestBase.ALLOW_UNTRUSTED = bool(data["allow_untrusted"])
        TestBase.DATACENTER = str(data["datacenter"])
        TestBase.DATASTORE = str(data["datastore"])

    @classmethod
    def _connect_vim(cls) -> vim.ServiceInstance:
        return nfc_auth.connect_vim(
            cls.HOST,
            cls.USERNAME,
            cls.PASSWORD,
            port=cls.PORT,
            thumbprint=cls.THUMBPRINT,
            allow_untrusted=cls.ALLOW_UNTRUSTED)

    @classmethod
    def _wait_for_task(cls, task: vim.Task) -> Any:
        deadline = time.monotonic() + _TASK_TIMEOUT_S
        while task.info.state in (
                vim.TaskInfo.State.running, vim.TaskInfo.State.queued):
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"timed out waiting for vSphere task {task}")
            time.sleep(_TASK_POLL_S)
        if task.info.state != vim.TaskInfo.State.success:
            raise RuntimeError(f"vSphere task failed: {task.info.error}")
        return task.info.result

    @classmethod
    def _find_datacenter(
            cls, content: vim.ServiceInstanceContent) -> vim.Datacenter:
        matches = [
            entity for entity in content.rootFolder.childEntity
            if isinstance(entity, vim.Datacenter)
            and entity.name == cls.DATACENTER]
        if not matches:
            raise RuntimeError(f"datacenter {cls.DATACENTER!r} not found")
        return matches[0]

    @classmethod
    def _find_datastore(cls, datacenter: vim.Datacenter) -> vim.Datastore:
        matches = [
            datastore for datastore in datacenter.datastore
            if datastore.name == cls.DATASTORE]
        if not matches:
            raise RuntimeError(
                f"datastore {cls.DATASTORE!r} not found in "
                f"datacenter {cls.DATACENTER!r}")
        return matches[0]

    @classmethod
    def _bind_lab_fields(cls) -> None:
        """Copy shared lab VM fields onto the active test class."""
        cls.HOST = TestBase.HOST
        cls.PORT = TestBase.PORT
        cls.USERNAME = TestBase.USERNAME
        cls.PASSWORD = TestBase.PASSWORD
        cls.ALLOW_UNTRUSTED = TestBase.ALLOW_UNTRUSTED
        cls.DATACENTER = TestBase.DATACENTER
        cls.DATASTORE = TestBase.DATASTORE
        cls.THUMBPRINT = TestBase.THUMBPRINT
        cls.VM_MOREF = TestBase.VM_MOREF
        cls.VMX_SPEC = TestBase.VMX_SPEC
        cls.DISK_PATH = TestBase.DISK_PATH

    @classmethod
    def _acquire_lab(cls) -> None:
        if TestBase._lab_refcount == 0:
            TestBase._load_test_config()
            TestBase.THUMBPRINT = nfc_auth.get_ssl_cert_thumbprint(
                TestBase.HOST, TestBase.PORT)
            TestBase._create_lab_vm()
        TestBase._lab_refcount += 1
        cls._bind_lab_fields()

    @classmethod
    def _release_lab(cls) -> None:
        if TestBase._lab_refcount == 0:
            return
        TestBase._lab_refcount -= 1
        if TestBase._lab_refcount == 0:
            cls._destroy_lab_vm()

    @classmethod
    def _create_lab_vm(cls) -> None:
        """Create an empty VM with a 10 GiB thin disk for I/O tests."""
        si = cls._connect_vim()
        vm = None
        try:
            content = si.RetrieveContent()
            datacenter = cls._find_datacenter(content)
            datastore = cls._find_datastore(datacenter)
            if not datastore.host:
                raise RuntimeError(
                    f"datastore {cls.DATASTORE!r} is not mounted on any host")
            host = datastore.host[0].key
            pool = host.parent.resourcePool
            vm_name = _LAB_VM_PREFIX + uuid.uuid4().hex[:12]
            vm = cls._wait_for_task(
                datacenter.vmFolder.CreateVM_Task(
                    config=cls._vm_config_spec(vm_name, datastore.name),
                    pool=pool,
                    host=host))
            TestBase._lab_vm_moref = vm._moId
            TestBase._lab_vm_name = vm_name
            TestBase.VM_MOREF = vm._moId
            TestBase.VMX_SPEC = f"moref={vm._moId}"
            disks = [
                device.backing.fileName
                for device in vm.config.hardware.device
                if isinstance(device, vim.vm.device.VirtualDisk)]
            if not disks:
                raise RuntimeError(
                    f"temporary VM {vm_name!r} has no virtual disks")
            TestBase.DISK_PATH = disks[0]
        except Exception:
            if vm is not None:
                try:
                    cls._wait_for_task(vm.Destroy_Task())
                except Exception:
                    pass
            TestBase._lab_vm_moref = None
            TestBase._lab_vm_name = None
            raise
        finally:
            Disconnect(si)

    @classmethod
    def _vm_config_spec(
            cls, vm_name: str, datastore_name: str) -> vim.vm.ConfigSpec:
        config = vim.vm.ConfigSpec()
        config.name = vm_name
        config.guestId = "otherGuest64"
        config.memoryMB = 128
        config.numCPUs = 1
        config.files = vim.vm.FileInfo(
            vmPathName=f"[{datastore_name}]")

        controller = vim.vm.device.ParaVirtualSCSIController()
        controller.key = 1000
        controller.busNumber = 0
        controller.sharedBus = (
            vim.vm.device.VirtualSCSIController.Sharing.noSharing)
        controller_spec = vim.vm.device.VirtualDeviceSpec()
        controller_spec.operation = (
            vim.vm.device.VirtualDeviceSpec.Operation.add)
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
        disk_spec.fileOperation = (
            vim.vm.device.VirtualDeviceSpec.FileOperation.create)
        disk_spec.device = disk

        config.deviceChange = [controller_spec, disk_spec]
        return config

    @classmethod
    def _destroy_lab_vm(cls) -> None:
        """Power off and delete the temporary lab VM if it still exists."""
        moref = TestBase._lab_vm_moref
        TestBase._lab_vm_moref = None
        TestBase._lab_vm_name = None
        if not moref:
            return
        si = cls._connect_vim()
        try:
            vm = vim.VirtualMachine(moref, si._stub)
            try:
                vm.Reload()
            except Exception:
                return
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                cls._wait_for_task(vm.PowerOffVM_Task())
            cls._wait_for_task(vm.Destroy_Task())
        finally:
            Disconnect(si)

    def authenticate(self, read_only: bool = True) -> NfcAuthSession:
        """Login to the lab vCenter and complete NFC authd for the temp VM."""
        return nfc_auth.authenticate(
            host=self.HOST,
            username=self.USERNAME,
            password=self.PASSWORD,
            vm_moref=self.VM_MOREF,
            thumbprint=self.THUMBPRINT,
            allow_untrusted=self.ALLOW_UNTRUSTED,
            disk_path=None if read_only else self.DISK_PATH,
            read_only=read_only)

    def vixdisklib_connect_kwargs(
            self, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Return common ``VixDiskLib_ConnectEx`` arguments for the temp VM."""
        kwargs: dict[str, Any] = {
            "server_name": self.HOST,
            "port": self.PORT,
            "thumbprint": self.THUMBPRINT,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "vmx_spec": self.VMX_SPEC,
            "transport_modes": "nbd",
            "read_only": False,
        }
        if extra:
            kwargs.update(extra)
        return kwargs

    def pattern_bytes(self, length: int, seed: bytes) -> bytes:
        """Return ``length`` bytes by repeating ``seed``."""
        if not seed:
            raise ValueError("seed must be non-empty")
        return (seed * ((length // len(seed)) + 1))[:length]
