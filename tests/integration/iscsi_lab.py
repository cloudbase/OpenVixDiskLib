# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""File-backed iSCSI LUN for SAN transport tests.

Presents a loop device through in-kernel LIO so lab ESXi can create a
temporary VMFS datastore. The pytest runner also logs in as an initiator
so the same NAA is visible locally for SAN I/O. Not part of the library.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import nfc_auth
from tests.integration.base import (
    _connect_vim,
    _find_datacenter,
    _find_datastore,
    _load_test_config,
    _wait_for_task,
    load_iscsi_san_config,
)

LOG = logging.getLogger(__name__)

IQN_PREFIX = "iqn.2026-09.io.openvixdisklib:"
DATASTORE_PREFIX = "ovdl-iscsi-"
STATE_DIR = "/var/tmp"
CONFIGFS_TARGET = "/sys/kernel/config/target"
ISCSI_PORT = 3260
LUN_SIZE_BYTES = 20 * 1024 * 1024 * 1024
HBA_WAIT_S = 180
HBA_POLL_S = 2
DEVICE_WAIT_S = 60
DEVICE_POLL_S = 0.5
LIO_HBA = "iblock_0"


@dataclass
class IscsiSanLab:
    """Runtime state for one file-backed iSCSI VMFS datastore."""

    lab_id: str
    portal: str
    port: int
    iqn: str
    img_path: str
    loop_dev: str
    naa: str
    local_dev: str
    datastore_name: str
    host_moref: str
    backstore_name: str
    iptables_added: bool = False
    enabled_software_iscsi: bool = False
    bound_vnic: str = ""


def default_portal_ip() -> str:
    """Return the IPv4 address used for the default route."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    finally:
        sock.close()
    if not ip or ip.startswith("127."):
        raise RuntimeError("could not determine a non-loopback portal IPv4 address")
    return str(ip)


def _need_sudo() -> bool:
    return os.geteuid() != 0


def _priv_args(args: list[str]) -> list[str]:
    if _need_sudo():
        return ["sudo", "-n", *args]
    return args


def _run(
    args: list[str],
    check: bool = True,
    privileged: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = _priv_args(args) if privileged else args
    LOG.debug("run %s", cmd)
    result = subprocess.run(
        cmd, capture_output=True, text=True, check=False, input=input_text
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} failed rc={result.returncode}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def _write_attr(path: str, value: str) -> None:
    payload = value if value.endswith("\n") else value + "\n"
    if not _need_sudo():
        with open(path, "w", encoding="ascii") as handle:
            handle.write(payload)
        return
    result = _run(["tee", path], privileged=True, input_text=payload, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"cannot write {path}: {result.stderr.strip()}")


def _read_attr(path: str) -> str:
    if not _need_sudo():
        with open(path, encoding="ascii") as handle:
            return handle.read().strip()
    result = _run(["cat", path], privileged=True)
    return result.stdout.strip()


def _mkdir(path: str) -> None:
    if not _need_sudo():
        os.makedirs(path, exist_ok=True)
        return
    _run(["mkdir", "-p", path], privileged=True)


def _rmdir(path: str) -> None:
    if not _need_sudo():
        os.rmdir(path)
        return
    _run(["rmdir", path], privileged=True, check=False)


def _unlink(path: str) -> None:
    if not _need_sudo():
        os.unlink(path)
        return
    _run(["rm", "-f", path], privileged=True, check=False)


def _symlink(target: str, path: str) -> None:
    if not _need_sudo():
        os.symlink(target, path)
        return
    _run(["ln", "-s", target, path], privileged=True)


def _listdir(path: str) -> list[str]:
    try:
        return os.listdir(path)
    except FileNotFoundError:
        return []


def _load_lio_modules() -> None:
    for module in ("target_core_mod", "target_core_iblock", "iscsi_target_mod"):
        result = _run(["modprobe", module], check=False, privileged=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"modprobe {module} failed: {result.stderr.strip() or result.stdout.strip()}"
            )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if os.path.isdir(CONFIGFS_TARGET):
            _mkdir(os.path.join(CONFIGFS_TARGET, "core"))
            _mkdir(os.path.join(CONFIGFS_TARGET, "iscsi"))
            return
        time.sleep(0.1)
    raise RuntimeError(f"{CONFIGFS_TARGET} did not appear after loading LIO modules")


def _create_sparse_file(path: str, size: int) -> None:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(fd, size)
    finally:
        os.close(fd)


def _attach_loop(img_path: str) -> str:
    result = _run(
        ["losetup", "--find", "--show", "--direct-io=on", img_path],
        check=False,
        privileged=True,
    )
    if result.returncode != 0:
        result = _run(["losetup", "--find", "--show", img_path], privileged=True)
    loop_dev = result.stdout.strip()
    if not loop_dev.startswith("/dev/loop"):
        raise RuntimeError(f"losetup returned unexpected device {loop_dev!r}")
    return loop_dev


def _setup_lio_target(
    lab_id: str, loop_dev: str, portal: str, port: int, iqn: str, backstore: str
) -> None:
    _load_lio_modules()
    hba_dir = os.path.join(CONFIGFS_TARGET, "core", LIO_HBA)
    _mkdir(hba_dir)
    bs_dir = os.path.join(hba_dir, backstore)
    _mkdir(bs_dir)
    _write_attr(os.path.join(bs_dir, "control"), f"udev_path={loop_dev}")
    serial = f"ovdl{lab_id}"[:36]
    _write_attr(os.path.join(bs_dir, "wwn", "vpd_unit_serial"), serial)
    _write_attr(os.path.join(bs_dir, "enable"), "1")

    tgt_dir = os.path.join(CONFIGFS_TARGET, "iscsi", iqn)
    _mkdir(tgt_dir)
    tpgt_dir = os.path.join(tgt_dir, "tpgt_1")
    _mkdir(tpgt_dir)
    lun_dir = os.path.join(tpgt_dir, "lun", "lun_0")
    _mkdir(lun_dir)
    link_path = os.path.join(lun_dir, backstore)
    if not os.path.lexists(link_path):
        _symlink(bs_dir, link_path)
    _mkdir(os.path.join(tpgt_dir, "np", f"{portal}:{port}"))
    attrib = os.path.join(tpgt_dir, "attrib")
    _write_attr(os.path.join(attrib, "authentication"), "0")
    _write_attr(os.path.join(attrib, "generate_node_acls"), "1")
    _write_attr(os.path.join(attrib, "cache_dynamic_acls"), "1")
    _write_attr(os.path.join(attrib, "demo_mode_write_protect"), "0")
    _write_attr(os.path.join(tpgt_dir, "enable"), "1")


def _teardown_lio_target(iqn: str, backstore: str) -> None:
    tgt_dir = os.path.join(CONFIGFS_TARGET, "iscsi", iqn)
    tpgt_dir = os.path.join(tgt_dir, "tpgt_1")
    enable = os.path.join(tpgt_dir, "enable")
    if os.path.isfile(enable):
        with contextlib.suppress(Exception):
            _write_attr(enable, "0")
    np_dir = os.path.join(tpgt_dir, "np")
    for portal in _listdir(np_dir):
        _rmdir(os.path.join(np_dir, portal))
    lun0 = os.path.join(tpgt_dir, "lun", "lun_0")
    link_path = os.path.join(lun0, backstore)
    if os.path.lexists(link_path):
        _unlink(link_path)
    _rmdir(lun0)
    _rmdir(os.path.join(tpgt_dir, "lun"))
    _rmdir(tpgt_dir)
    _rmdir(tgt_dir)

    bs_dir = os.path.join(CONFIGFS_TARGET, "core", LIO_HBA, backstore)
    bs_enable = os.path.join(bs_dir, "enable")
    if os.path.isfile(bs_enable):
        with contextlib.suppress(Exception):
            _write_attr(bs_enable, "0")
    _rmdir(bs_dir)


def _block_by_id() -> set[str]:
    by_id = "/dev/disk/by-id"
    if not os.path.isdir(by_id):
        return set()
    return {os.path.join(by_id, name) for name in os.listdir(by_id)}


def _iscsi_login(iqn: str, portal: str, port: int) -> None:
    target = f"{portal}:{port}"
    _run(
        ["iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", target],
        privileged=True,
    )
    result = _run(
        ["iscsiadm", "-m", "node", "-T", iqn, "-p", target, "--login"],
        check=False,
        privileged=True,
    )
    if (
        result.returncode != 0
        and "already" not in (result.stderr + result.stdout).lower()
    ):
        raise RuntimeError(
            f"iscsiadm login failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def _iscsi_logout(iqn: str, portal: str, port: int) -> None:
    target = f"{portal}:{port}"
    _run(
        ["iscsiadm", "-m", "node", "-T", iqn, "-p", target, "--logout"],
        check=False,
        privileged=True,
    )
    _run(
        ["iscsiadm", "-m", "node", "-T", iqn, "-p", target, "-o", "delete"],
        check=False,
        privileged=True,
    )


def _wait_new_wwn_dev(before: set[str], timeout_s: float = DEVICE_WAIT_S) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        after = _block_by_id()
        new_wwn = sorted(
            path
            for path in after - before
            if os.path.basename(path).startswith("wwn-")
            and not os.path.basename(path).endswith("-part1")
            and "-part" not in os.path.basename(path)
        )
        if new_wwn:
            return os.path.realpath(new_wwn[0])
        time.sleep(DEVICE_POLL_S)
    raise RuntimeError("local iSCSI LUN did not appear under /dev/disk/by-id")


def _naa_from_dev(dev_path: str) -> str:
    name = os.path.basename(os.path.realpath(dev_path))
    wwid_path = f"/sys/block/{name}/device/wwid"
    wwid = ""
    if os.path.isfile(wwid_path):
        wwid = _read_attr(wwid_path).lower()
    if not wwid:
        by_id = "/dev/disk/by-id"
        real = os.path.realpath(dev_path)
        for entry in _listdir(by_id):
            path = os.path.join(by_id, entry)
            if os.path.realpath(path) == real and entry.startswith("wwn-0x"):
                wwid = "naa." + entry[len("wwn-0x") :]
                break
    if wwid.startswith("naa."):
        return wwid
    if wwid.startswith("wwn-0x"):
        return "naa." + wwid[6:]
    if wwid.startswith("0x"):
        return "naa." + wwid[2:]
    digits = "".join(ch for ch in wwid if ch in "0123456789abcdef")
    if len(digits) >= 16:
        return "naa." + digits
    raise RuntimeError(f"could not read NAA for {dev_path}: wwid={wwid!r}")


def _ensure_iscsi_port(portal: str, port: int) -> bool:
    result = _run(
        [
            "iptables",
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "-d",
            portal,
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ],
        check=False,
        privileged=True,
    )
    if result.returncode == 0:
        return False
    _run(
        [
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-p",
            "tcp",
            "-d",
            portal,
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ],
        check=False,
        privileged=True,
    )
    return True


def _drop_iscsi_port(portal: str, port: int) -> None:
    _run(
        [
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "-d",
            portal,
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ],
        check=False,
        privileged=True,
    )


def _state_path(lab_id: str) -> str:
    return os.path.join(STATE_DIR, f"ovdl-iscsi-{lab_id}.json")


def _write_state(lab: IscsiSanLab) -> None:
    payload = {
        "lab_id": lab.lab_id,
        "portal": lab.portal,
        "port": lab.port,
        "iqn": lab.iqn,
        "img_path": lab.img_path,
        "loop_dev": lab.loop_dev,
        "naa": lab.naa,
        "local_dev": lab.local_dev,
        "datastore_name": lab.datastore_name,
        "host_moref": lab.host_moref,
        "backstore_name": lab.backstore_name,
        "iptables_added": lab.iptables_added,
        "enabled_software_iscsi": lab.enabled_software_iscsi,
        "bound_vnic": lab.bound_vnic,
    }
    with open(_state_path(lab.lab_id), "w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def _read_state(path: str) -> IscsiSanLab | None:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return IscsiSanLab(
            lab_id=str(data["lab_id"]),
            portal=str(data["portal"]),
            port=int(data["port"]),
            iqn=str(data["iqn"]),
            img_path=str(data["img_path"]),
            loop_dev=str(data["loop_dev"]),
            naa=str(data["naa"]),
            local_dev=str(data.get("local_dev", "")),
            datastore_name=str(data["datastore_name"]),
            host_moref=str(data.get("host_moref", "")),
            backstore_name=str(data["backstore_name"]),
            iptables_added=bool(data.get("iptables_added", False)),
            enabled_software_iscsi=bool(data.get("enabled_software_iscsi", False)),
            bound_vnic=str(data.get("bound_vnic", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _software_iscsi_enabled(host: vim.HostSystem) -> bool:
    return bool(
        getattr(host.config.storageDevice, "softwareInternetScsiEnabled", False)
    )


def _ensure_software_iscsi(host: vim.HostSystem) -> bool:
    """Enable the software iSCSI adapter when it is missing. Return True if we enabled it."""
    if _software_iscsi_enabled(host) or _find_software_iscsi_hba_or_none(host):
        return False
    LOG.info("enabling software iSCSI on %s", host.name)
    host.configManager.storageSystem.UpdateSoftwareInternetScsiEnabled(True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        fresh = vim.HostSystem(host._moId, host._stub)
        if _find_software_iscsi_hba_or_none(fresh):
            return True
        time.sleep(1)
    raise RuntimeError(f"software iSCSI adapter did not appear on {host.name}")


def _find_software_iscsi_hba_or_none(
    host: vim.HostSystem,
) -> vim.host.InternetScsiHba | None:
    for hba in host.config.storageDevice.hostBusAdapter:
        if not isinstance(hba, vim.host.InternetScsiHba):
            continue
        driver = (hba.driver or "").lower()
        model = (hba.model or "").lower()
        if driver == "iscsi_vmk" or "software" in model:
            return hba
    return None


def _bind_management_vmk(host: vim.HostSystem, hba: vim.host.InternetScsiHba) -> str:
    """Bind vmk0 when the software adapter has no VMkernel NIC."""
    storage = host.configManager.storageSystem
    try:
        bound = storage.QueryBoundVnics(iScsiHbaDevice=hba.device) or []
    except Exception:
        bound = []
    if bound:
        return ""
    vmk = None
    for vnic in host.config.network.vnic or []:
        if vnic.device == "vmk0":
            vmk = vnic.device
            break
    if vmk is None and host.config.network.vnic:
        vmk = host.config.network.vnic[0].device
    if not vmk:
        return ""
    LOG.info("binding %s to %s on %s", vmk, hba.device, host.name)
    try:
        storage.BindVnic(iScsiHbaDevice=hba.device, vnicDevice=vmk)
    except Exception as exc:
        LOG.warning("BindVnic %s failed: %s", vmk, exc)
        return ""
    return vmk


def _find_software_iscsi_hba(host: vim.HostSystem) -> vim.host.InternetScsiHba:
    hba = _find_software_iscsi_hba_or_none(host)
    if hba is None:
        raise RuntimeError(
            f"host {host.name} has no software iSCSI adapter; "
            "enable vmhba iscsi_vmk before running SAN tests"
        )
    return hba


def _host_from_datastore(datastore: vim.Datastore) -> vim.HostSystem:
    if not datastore.host:
        raise RuntimeError(f"datastore {datastore.name!r} is not mounted on any host")
    return datastore.host[0].key


def _refresh_host(si: vim.ServiceInstance, moref: str) -> vim.HostSystem:
    return vim.HostSystem(moref, si._stub)


def _find_scsi_disk(host: vim.HostSystem, naa: str) -> vim.host.ScsiDisk | None:
    want = naa.lower()
    if not want.startswith("naa."):
        want = "naa." + want
    bare = want[4:]
    for lun in host.config.storageDevice.scsiLun or []:
        if not isinstance(lun, vim.host.ScsiDisk):
            continue
        canonical = (lun.canonicalName or "").lower()
        if canonical == want or canonical.replace("naa.", "") == bare:
            return lun
        uuid = (lun.uuid or "").lower().replace("-", "")
        if bare in uuid:
            return lun
    return None


def _add_send_target(
    host: vim.HostSystem, hba: vim.host.InternetScsiHba, portal: str, port: int
) -> None:
    for existing in hba.configuredSendTarget or []:
        if existing.address == portal and int(existing.port or ISCSI_PORT) == port:
            return
    target = vim.host.InternetScsiHba.SendTarget()
    target.address = portal
    target.port = port
    host.configManager.storageSystem.AddInternetScsiSendTargets(
        iScsiHbaDevice=hba.device, targets=[target]
    )


def _remove_send_target(host: vim.HostSystem, portal: str, port: int) -> None:
    try:
        hba = _find_software_iscsi_hba(host)
    except RuntimeError:
        return
    match = None
    for existing in hba.configuredSendTarget or []:
        if existing.address == portal and int(existing.port or ISCSI_PORT) == port:
            match = existing
            break
    if match is None:
        return
    with contextlib.suppress(Exception):
        host.configManager.storageSystem.RemoveInternetScsiSendTargets(
            iScsiHbaDevice=hba.device, targets=[match]
        )


def _wait_for_esxi_disk(
    si: vim.ServiceInstance, host_moref: str, naa: str
) -> vim.host.ScsiDisk:
    deadline = time.monotonic() + HBA_WAIT_S
    last_names: list[str] = []
    while time.monotonic() < deadline:
        host = _refresh_host(si, host_moref)
        with contextlib.suppress(Exception):
            host.configManager.storageSystem.RescanHba(
                hbaDevice=_find_software_iscsi_hba(host).device
            )
        with contextlib.suppress(Exception):
            host.configManager.storageSystem.RescanVmfs()
        host = _refresh_host(si, host_moref)
        disk = _find_scsi_disk(host, naa)
        if disk is not None:
            return disk
        last_names = [
            str(lun.canonicalName)
            for lun in host.config.storageDevice.scsiLun or []
            if isinstance(lun, vim.host.ScsiDisk)
        ]
        time.sleep(HBA_POLL_S)
    raise RuntimeError(
        f"ESXi host did not discover iSCSI LUN {naa}; scsi disks={last_names[:12]}"
    )


def _create_vmfs_datastore(
    host: vim.HostSystem, disk: vim.host.ScsiDisk, name: str
) -> vim.Datastore:
    ds_sys = host.configManager.datastoreSystem
    options = ds_sys.QueryVmfsDatastoreCreateOptions(devicePath=disk.devicePath)
    if not options:
        options = ds_sys.QueryVmfsDatastoreCreateOptions(
            devicePath=disk.devicePath, vmfsMajorVersion=6
        )
    if not options:
        raise RuntimeError(
            f"QueryVmfsDatastoreCreateOptions returned no layout for {disk.canonicalName}"
        )
    spec = options[0].spec
    spec.vmfs.volumeName = name
    if getattr(spec.vmfs, "majorVersion", None) in (None, 0):
        spec.vmfs.majorVersion = 6
    return ds_sys.CreateVmfsDatastore(spec=spec)


def _destroy_vms_on_datastore(
    si: vim.ServiceInstance, datacenter: vim.Datacenter, name: str
) -> None:
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        datacenter, [vim.VirtualMachine], True
    )
    try:
        vms = list(container.view)
    finally:
        container.Destroy()
    for vm in vms:
        try:
            datastores = [ds.name for ds in (vm.datastore or [])]
        except Exception:
            LOG.debug("skipping VM while listing datastores", exc_info=True)
            continue
        if name not in datastores:
            continue
        LOG.info("destroying leftover SAN lab VM %s on %s", vm.name, name)
        try:
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                _wait_for_task(vm.PowerOffVM_Task())
            _wait_for_task(vm.Destroy_Task())
        except Exception:
            LOG.exception("failed to destroy leftover VM %s", vm.name)


def _remove_vmfs_datastore(
    si: vim.ServiceInstance, datacenter: vim.Datacenter, name: str
) -> None:
    _destroy_vms_on_datastore(si, datacenter, name)
    try:
        datastore = _find_datastore(datacenter, name)
    except RuntimeError:
        return
    hosts = [mount.key for mount in datastore.host or []]
    for host in hosts:
        with contextlib.suppress(Exception):
            host.configManager.datastoreSystem.RemoveDatastore(datastore)
            return
    with contextlib.suppress(Exception):
        _wait_for_task(datastore.Destroy_Task())


def _connect_lab_vim() -> tuple[vim.ServiceInstance, dict[str, Any]]:
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
    return si, cfg


def cleanup_leftover_iscsi_labs(
    si: vim.ServiceInstance | None = None,
    datacenter: vim.Datacenter | None = None,
) -> None:
    """Tear down leftover ovdl-iscsi LIO targets, files, and VMFS volumes."""
    for name in _listdir(STATE_DIR):
        if not name.startswith("ovdl-iscsi-") or not name.endswith(".json"):
            continue
        lab = _read_state(os.path.join(STATE_DIR, name))
        if lab is None:
            continue
        LOG.warning("cleaning leftover iSCSI SAN lab %s", lab.lab_id)
        if si is not None and datacenter is not None:
            with contextlib.suppress(Exception):
                _remove_vmfs_datastore(si, datacenter, lab.datastore_name)
            if lab.host_moref:
                host = _refresh_host(si, lab.host_moref)
                with contextlib.suppress(Exception):
                    _remove_send_target(host, lab.portal, lab.port)
                with contextlib.suppress(Exception):
                    _restore_esxi_iscsi(host, lab)
        _teardown_local(lab)


def _require_privileged() -> None:
    result = _run(["true"], check=False, privileged=True)
    if result.returncode != 0:
        raise RuntimeError(
            "iSCSI SAN lab needs root or passwordless sudo for LIO, "
            f"losetup, and iscsiadm: {result.stderr.strip()}"
        )


def _chmod_dev(path: str, mode: str = "0666") -> None:
    _run(["chmod", mode, path], privileged=True, check=False)


def _teardown_local(lab: IscsiSanLab) -> None:
    _iscsi_logout(lab.iqn, lab.portal, lab.port)
    _teardown_lio_target(lab.iqn, lab.backstore_name)
    if lab.loop_dev:
        _run(["losetup", "-d", lab.loop_dev], check=False, privileged=True)
    if lab.img_path:
        with contextlib.suppress(OSError):
            os.unlink(lab.img_path)
    if lab.iptables_added:
        _drop_iscsi_port(lab.portal, lab.port)
    with contextlib.suppress(OSError):
        os.unlink(_state_path(lab.lab_id))


def setup_iscsi_san_lab() -> IscsiSanLab:
    """Create a loop-backed LIO LUN, attach it to lab ESXi, and format VMFS.

    Raises:
        RuntimeError: when the runner or ESXi cannot host the LUN. Callers
            should skip the SAN tests.
    """
    _require_privileged()

    san_cfg = load_iscsi_san_config() or {}
    portal = san_cfg.get("portal") or default_portal_ip()
    lab_id = uuid.uuid4().hex[:12]
    iqn = f"{IQN_PREFIX}ovdl-{lab_id}"
    backstore = f"ovdl_{lab_id}"
    img_path = os.path.join(STATE_DIR, f"ovdl-iscsi-{lab_id}.img")
    datastore_name = f"{DATASTORE_PREFIX}{lab_id}"
    loop_dev = ""
    iptables_added = False
    local_dev = ""
    naa = ""
    si: vim.ServiceInstance | None = None
    lab = IscsiSanLab(
        lab_id=lab_id,
        portal=portal,
        port=ISCSI_PORT,
        iqn=iqn,
        img_path=img_path,
        loop_dev=loop_dev,
        naa=naa,
        local_dev=local_dev,
        datastore_name=datastore_name,
        host_moref="",
        backstore_name=backstore,
        iptables_added=False,
    )
    try:
        si, cfg = _connect_lab_vim()
        content = si.RetrieveContent()
        datacenter = _find_datacenter(content, cfg["datacenter"])
        cleanup_leftover_iscsi_labs(si, datacenter)
        lab_ds = _find_datastore(datacenter, cfg["datastore"])
        host = _host_from_datastore(lab_ds)
        lab.host_moref = host._moId
        lab.enabled_software_iscsi = _ensure_software_iscsi(host)
        host = _refresh_host(si, lab.host_moref)
        hba = _find_software_iscsi_hba(host)
        lab.bound_vnic = _bind_management_vmk(host, hba)
        host = _refresh_host(si, lab.host_moref)
        hba = _find_software_iscsi_hba(host)

        _create_sparse_file(img_path, LUN_SIZE_BYTES)
        loop_dev = _attach_loop(img_path)
        lab.loop_dev = loop_dev
        _setup_lio_target(lab_id, loop_dev, portal, ISCSI_PORT, iqn, backstore)
        iptables_added = _ensure_iscsi_port(portal, ISCSI_PORT)
        lab.iptables_added = iptables_added

        before = _block_by_id()
        _iscsi_login(iqn, portal, ISCSI_PORT)
        local_dev = _wait_new_wwn_dev(before)
        _chmod_dev(local_dev)
        naa = _naa_from_dev(local_dev)
        lab.local_dev = local_dev
        lab.naa = naa
        _write_state(lab)

        host = _refresh_host(si, lab.host_moref)
        hba = _find_software_iscsi_hba(host)
        _add_send_target(host, hba, portal, ISCSI_PORT)
        disk = _wait_for_esxi_disk(si, lab.host_moref, naa)
        host = _refresh_host(si, lab.host_moref)
        _create_vmfs_datastore(host, disk, datastore_name)
        _write_state(lab)
        LOG.info(
            "iSCSI SAN lab %s portal=%s:%s naa=%s datastore=%s local=%s",
            lab_id,
            portal,
            ISCSI_PORT,
            naa,
            datastore_name,
            local_dev,
        )
        return lab
    except Exception:
        if si is not None:
            with contextlib.suppress(Exception):
                content = si.RetrieveContent()
                cfg = _load_test_config()
                datacenter = _find_datacenter(content, cfg["datacenter"])
                _remove_vmfs_datastore(si, datacenter, datastore_name)
            if lab.host_moref:
                with contextlib.suppress(Exception):
                    _remove_send_target(
                        _refresh_host(si, lab.host_moref), portal, ISCSI_PORT
                    )
                with contextlib.suppress(Exception):
                    _restore_esxi_iscsi(_refresh_host(si, lab.host_moref), lab)
        _teardown_local(lab)
        raise
    finally:
        if si is not None:
            Disconnect(si)


def _restore_esxi_iscsi(host: vim.HostSystem, lab: IscsiSanLab) -> None:
    storage = host.configManager.storageSystem
    if lab.bound_vnic:
        with contextlib.suppress(Exception):
            hba = _find_software_iscsi_hba(host)
            storage.UnbindVnic(
                iScsiHbaDevice=hba.device, vnicDevice=lab.bound_vnic, force=True
            )
    if lab.enabled_software_iscsi:
        with contextlib.suppress(Exception):
            storage.UpdateSoftwareInternetScsiEnabled(False)


def teardown_iscsi_san_lab(lab: IscsiSanLab) -> None:
    """Remove the VMFS datastore, ESXi send target, and local LIO LUN."""
    si: vim.ServiceInstance | None = None
    try:
        si, cfg = _connect_lab_vim()
        content = si.RetrieveContent()
        datacenter = _find_datacenter(content, cfg["datacenter"])
        _remove_vmfs_datastore(si, datacenter, lab.datastore_name)
        if lab.host_moref:
            host = _refresh_host(si, lab.host_moref)
            _remove_send_target(host, lab.portal, lab.port)
            with contextlib.suppress(Exception):
                hba = _find_software_iscsi_hba(host)
                host.configManager.storageSystem.RescanHba(hbaDevice=hba.device)
            _restore_esxi_iscsi(host, lab)
    except Exception:
        LOG.exception("ESXi teardown for iSCSI SAN lab %s failed", lab.lab_id)
    finally:
        if si is not None:
            Disconnect(si)
        _teardown_local(lab)


@contextlib.contextmanager
def iscsi_san_lab() -> Iterator[IscsiSanLab]:
    """Context manager around :func:`setup_iscsi_san_lab`."""
    lab = setup_iscsi_san_lab()
    try:
        yield lab
    finally:
        teardown_iscsi_san_lab(lab)
