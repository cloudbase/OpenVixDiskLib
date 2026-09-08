# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Drop-in replacement for ``tests.integration.vixdisklib`` that does not
use VDDK.

Callers can switch with::

    from openvixdisklib import openvixdisklib as vixdisklib

``VixDiskLibHandle.connect`` / ``open`` / ``read`` match the VDDK wrapper
in ``tests/integration/vixdisklib.py``. VIM login uses pyVmomi; NFC ticket,
authd, and disk I/O use ``nfc_auth`` and ``nfc_open``.
"""

from __future__ import annotations

import contextlib
import ctypes
import logging
import os
from typing import Iterator, Optional, Union

from pyVim.connect import Disconnect
from pyVmomi import vim

from openvixdisklib import nfc_auth, nfc_open

LOG = logging.getLogger(__name__)

VIXDISKLIB_VERSION_MAJOR = 8
VIXDISKLIB_VERSION_MINOR = 0

VIXDISKLIB_SECTOR_SIZE = 512

VIXDISKLIB_CRED_UID = 1

VIXDISKLIB_FLAG_OPEN_UNBUFFERED = 1
VIXDISKLIB_FLAG_OPEN_SINGLE_LINK = 2
VIXDISKLIB_FLAG_OPEN_READ_ONLY = 4

VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB = 16
VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ = 32
VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ = 64


def _nfc_compression(flags: int) -> int:
    """Return the NFC IO compression type for VixDiskLib open ``flags``."""
    alg = flags & (
        VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB
        | VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ
        | VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ
    )
    if alg == 0:
        return nfc_open.NFC_COMPRESSION_NONE
    if alg == VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ:
        return nfc_open.NFC_COMPRESSION_FASTLZ
    if alg & (alg - 1):
        raise NotImplementedError(
            "Cannot set two or more NBD compression algorithms at the same time"
        )
    raise NotImplementedError(f"NBD compression open flag 0x{alg:x} is not supported")


VIX_SUPPORTED_COMPATIBILITY_MODES = ["6.0", "6.5", "6.7", "7.0", "8.0"]


def get_buffer(size: int):
    """Return a ctypes buffer of ``size`` bytes, as the VDDK wrapper did."""
    return ctypes.create_string_buffer(size)


def _parse_vm_moref(vmx_spec: Optional[str]) -> str:
    if not vmx_spec:
        raise ValueError("vmx_spec is required (for example 'moref=vm-13098')")
    if "=" in vmx_spec:
        kind, value = vmx_spec.split("=", 1)
        if kind.lower() != "moref" or not value:
            raise ValueError(f"unsupported vmx_spec: {vmx_spec}")
        return value
    return vmx_spec


def _select_transport(transport_modes: Optional[str]) -> str:
    """Return the first requested transport this replacement implements.

    ``None`` defaults to ``nbdssl``. A colon-separated list (VDDK
    style, for example ``file:nbdssl:nbd``) picks the first of
    ``nbdssl`` or ``nbd``.
    """
    if transport_modes is None:
        return "nbdssl"
    for mode in transport_modes.split(":"):
        if mode in ("nbdssl", "nbd"):
            return mode
    raise NotImplementedError(
        f"supported transports are nbdssl and nbd, got {transport_modes!r}"
    )


class _Connection:
    """VIM session plus the VM moref needed to issue an NFC ticket at Open."""

    def __init__(
        self,
        si: vim.ServiceInstance,
        vm_moref: str,
        snapshot_ref: Optional[str],
        thumbprint: Optional[str],
        allow_untrusted: bool,
        read_only: bool,
        transport_mode: str,
    ) -> None:
        self.si = si
        self.vm_moref = vm_moref
        self.snapshot_ref = snapshot_ref
        self.thumbprint = thumbprint
        self.allow_untrusted = allow_untrusted
        self.read_only = read_only
        self.transport_mode = transport_mode


class _DiskHandle:
    """Opened NFC disk plus the authd TLS socket it was taken from."""

    def __init__(self, disk: nfc_open.NfcDisk, authd_sock, transport_mode: str) -> None:
        self.disk = disk
        self.authd_sock = authd_sock
        self.transport_mode = transport_mode


class VixDiskLibHandle:
    """VDDK-compatible handle backed by pyVmomi and the NFC replacement."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        vixdisklib_compatibility_version: Optional[str] = None,
    ) -> None:
        """Accept the VDDK wrapper constructor; no native library is loaded.

        Args:
            config_path: Ignored. VDDK used this for logging plugins.
            vixdisklib_compatibility_version: Optional ``major.minor`` string
                such as ``8.0``. Validated for form only.
        """
        del config_path
        target_versions = VIX_SUPPORTED_COMPATIBILITY_MODES
        if vixdisklib_compatibility_version:
            target_versions = [vixdisklib_compatibility_version]
        LOG.debug("vixDiskLib versions targeted: %s", target_versions)

        version_used = None
        for version in reversed(target_versions):
            try:
                major_ver, minor_ver = version.split(".")
                int(major_ver)
                int(minor_ver)
            except ValueError as ex:
                raise ValueError(
                    "Unsupported vixDiskLib version format '%s'. vixDiskLib "
                    "compatibility mode must be of the form "
                    "'$major.$minor'" % version
                ) from ex
            version_used = version
            break

        if not version_used:
            raise Exception(
                "Could not initialize vixDiskLib with any of the following "
                "versions: %s" % target_versions
            )

        LOG.info(
            "Successfully initialized vixDiskLib with target version '%s'", version_used
        )

    @classmethod
    def get_vix_disklib_name(cls) -> str:
        """Return the native library name; this replacement does not load it."""
        if os.name == "nt":
            return "vixDiskLib.dll"
        return "libvixDiskLib.so"

    def get_transport_modes(self) -> list[str]:
        """Return the transport modes this replacement implements."""
        return ["nbdssl", "nbd"]

    def get_transport_mode(self, disk_handle: _DiskHandle) -> str:
        """Return the transport used for ``disk_handle``."""
        return disk_handle.transport_mode

    @contextlib.contextmanager
    def connect(
        self,
        server_name: str,
        thumbprint: Optional[str],
        username: str,
        password: str,
        vmx_spec: Optional[str] = None,
        snapshot_ref: Optional[str] = None,
        read_only: bool = True,
        transport_modes: Optional[str] = None,
        port: int = 443,
        allow_untrusted: bool = False,
    ) -> Iterator[_Connection]:
        """Login to vCenter/ESXi. Matches ``VixDiskLib_ConnectEx``.

        The NFC ticket and authd handshake are deferred to ``open``, as in
        VDDK. Writable opens use ``NfcRandomAccessOpenDisk``; read-only
        opens use ``NfcGetVmFiles``. ``snapshot_ref`` is accepted for API
        compatibility and is not sent on the ticket SOAP call.

        Args:
            server_name: vCenter or ESXi hostname/IP.
            thumbprint: SHA-1 thumbprint of the management TLS certificate.
            username: VIM user name.
            password: VIM password.
            vmx_spec: VM selector, ``moref=vm-…``.
            snapshot_ref: Snapshot moref; unused on the NFC ticket.
            read_only: When False, the disk may be opened for write.
            transport_modes: ``nbdssl``, ``nbd``, or a colon list. The
                first supported mode is used; ``None`` defaults to
                ``nbdssl``.
            port: HTTPS port, usually 443.
            allow_untrusted: Skip management TLS verification when True.
        """
        LOG.debug("Connecting VixDiskLib: %s", server_name)
        transport_mode = _select_transport(transport_modes)
        vm_moref = _parse_vm_moref(vmx_spec)
        si = nfc_auth.connect_vim(
            server_name,
            username,
            password,
            port=port,
            thumbprint=thumbprint,
            allow_untrusted=allow_untrusted or not thumbprint,
        )
        conn = _Connection(
            si,
            vm_moref,
            snapshot_ref,
            thumbprint,
            allow_untrusted or not thumbprint,
            read_only,
            transport_mode,
        )
        try:
            yield conn
        finally:
            self.disconnect(conn)

    @contextlib.contextmanager
    def open(
        self,
        conn: _Connection,
        disk_path: str,
        flags: int = VIXDISKLIB_FLAG_OPEN_READ_ONLY,
    ) -> Iterator[_DiskHandle]:
        """Open ``disk_path`` over NFC. Matches ``VixDiskLib_Open``.

        Read-only opens request ``NfcGetVmFiles`` (VM only). The VMDK
        path, including a snapshot parent such as ``…-000007.vmdk``, is
        sent on NFC ``OPEN_FILE``. Writable opens use
        ``NfcRandomAccessOpenDisk`` and resolve a device key from the
        disk's backing chain.

        Args:
            conn: Connection from ``connect``.
            disk_path: Datastore path of the VMDK.
            flags: Open flags. ``VIXDISKLIB_FLAG_OPEN_READ_ONLY`` opens
                the disk read-only; omit it for write.
                ``VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ`` compresses
                NFC IO. zlib and skipz are not implemented.
        """
        LOG.debug("Openning VixDiskLib disk: %s", disk_path)
        compression = _nfc_compression(flags)
        read_only = bool(flags & VIXDISKLIB_FLAG_OPEN_READ_ONLY)
        if not read_only and conn.read_only:
            raise NotImplementedError("ConnectEx was read-only; cannot open for write")

        vm = vim.VirtualMachine(conn.vm_moref, conn.si._stub)
        nfc_ssl = conn.transport_mode == "nbdssl"
        ticket = nfc_auth.get_nfc_ticket(
            conn.si, vm, read_only=read_only, disk_path=None if read_only else disk_path
        )
        authd_sock = nfc_auth.connect_authd(
            ticket, allow_untrusted=conn.allow_untrusted, nfc_ssl=nfc_ssl
        )
        session = nfc_auth.NfcAuthSession(conn.si, ticket, authd_sock, nfc_ssl=nfc_ssl)
        try:
            disk = nfc_open.open_disk(
                session, disk_path, read_only=read_only, compression=compression
            )
        except Exception:
            authd_sock.close()
            raise
        handle = _DiskHandle(disk, authd_sock, conn.transport_mode)
        try:
            yield handle
        finally:
            self.close(handle)

    def read(
        self,
        disk_handle: _DiskHandle,
        start_sector: int,
        num_sectors: int,
        buf: Union[ctypes.Array, bytearray, memoryview],
    ) -> None:
        """Read ``num_sectors`` from ``start_sector`` into ``buf``.

        Args:
            disk_handle: Handle from ``open``.
            start_sector: First sector to read.
            num_sectors: Number of sectors to read.
            buf: Destination buffer (``get_buffer`` or a writable bytes-like).
        """
        data = disk_handle.disk.read(start_sector, num_sectors)
        if isinstance(buf, (bytearray, memoryview)):
            if len(buf) < len(data):
                raise Exception(f"read buffer is {len(buf)} bytes, need {len(data)}")
            buf[: len(data)] = data
            return
        ctypes.memmove(buf, data, len(data))

    def write(
        self,
        disk_handle: _DiskHandle,
        start_sector: int,
        num_sectors: int,
        buf: Union[ctypes.Array, bytes, bytearray, memoryview],
    ) -> None:
        """Write ``num_sectors`` from ``buf`` starting at ``start_sector``.

        Args:
            disk_handle: Handle from ``open``.
            start_sector: First sector to write.
            num_sectors: Number of sectors to write.
            buf: Source buffer (``get_buffer`` or a bytes-like).
        """
        length = num_sectors * VIXDISKLIB_SECTOR_SIZE
        if isinstance(buf, (bytes, bytearray, memoryview)):
            data = bytes(buf[:length])
        else:
            data = buf.raw[:length]
        disk_handle.disk.write(start_sector, num_sectors, data)

    def close(self, disk_handle: _DiskHandle) -> None:
        """Close the VMDK and the authd socket used for NFC.

        Args:
            disk_handle: Handle from ``open``.
        """
        LOG.debug("Closing VixDiskLib disk handle: %s", disk_handle)
        try:
            disk_handle.disk.close()
        finally:
            try:
                disk_handle.authd_sock.close()
            except OSError:
                pass

    def disconnect(self, conn: _Connection) -> None:
        """Logout of the VIM session.

        Args:
            conn: Connection from ``connect``.
        """
        LOG.debug("Disconnecting VixDiskLib")
        Disconnect(conn.si)

    def exit(self) -> None:
        """No-op; there is no native VDDK library to tear down."""
        return
