# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""VDDK-compatible vSphere NFC authentication.

VixDiskLib_ConnectEx / Open authenticate in two stages:

1. SOAP login to vCenter (or ESXi) and an internal NfcService call that
   returns a one-time vim.HostServiceTicket.
2. A TLS session to the ESXi authd daemon on TCP 902, completed with the
   ticket's sessionId and service name.

pyVim / pyVmomi are used for every public VIM operation (login, inventory,
HostServiceTicket). NfcService is not in the public WSDL, so it is registered
with pyVmomi's type system and invoked through the same SOAP stub.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Optional

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim
from pyVmomi.VmomiSupport import F_OPTIONAL, CreateManagedType, GetVmodlType

NFC_SERVICE_MOID = "nfcService"
AUTHD_DEFAULT_PORT = 902
_NFC_TYPES_REGISTERED = False


def _ssl_client_context(verify: bool = True) -> ssl.SSLContext:
    """Return a client TLS context built with public ``ssl`` APIs."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _register_nfc_types() -> None:
    """Register internal vim.NfcService methods on the pyVmomi type map."""
    global _NFC_TYPES_REGISTERED
    if _NFC_TYPES_REGISTERED:
        return
    try:
        GetVmodlType("vim.NfcService")
        _NFC_TYPES_REGISTERED = True
        return
    except Exception:
        pass

    CreateManagedType(
        "vim.NfcService",
        "NfcService",
        "vmodl.ManagedObject",
        "vim.version.version1",
        [],
        [
            (
                "getVmFiles",
                "NfcGetVmFiles",
                "vim.version.version1",
                (("vm", "vim.VirtualMachine", "vim.version.version1", 0, None),),
                (0, "vim.HostServiceTicket", "vim.HostServiceTicket"),
                None,
                None,
            ),
            (
                "randomAccessOpen",
                "NfcRandomAccessOpenDisk",
                "vim.version.version1",
                (
                    ("vm", "vim.VirtualMachine", "vim.version.version1", 0, None),
                    ("diskDeviceKey", "int", "vim.version.version1", 0, None),
                    (
                        "hostForAccess",
                        "vim.HostSystem",
                        "vim.version.version1",
                        F_OPTIONAL,
                        None,
                    ),
                ),
                (0, "vim.HostServiceTicket", "vim.HostServiceTicket"),
                None,
                None,
            ),
            (
                "randomAccessOpenReadonly",
                "NfcRandomAccessOpenReadonly",
                "vim.version.version1",
                (
                    ("vm", "vim.VirtualMachine", "vim.version.version1", 0, None),
                    ("diskDeviceKey", "int", "vim.version.version1", 0, None),
                    (
                        "hostForAccess",
                        "vim.HostSystem",
                        "vim.version.version1",
                        F_OPTIONAL,
                        None,
                    ),
                ),
                (0, "vim.HostServiceTicket", "vim.HostServiceTicket"),
                None,
                None,
            ),
            (
                "getServerNfcLibVersion",
                "NfcGetServerNfcLibVersion",
                "vim.version.version1",
                (("hostForAccess", "vim.HostSystem", "vim.version.version1", 0, None),),
                (0, "int", "int"),
                None,
                None,
            ),
        ],
    )
    _NFC_TYPES_REGISTERED = True


def nfc_service(si: vim.ServiceInstance) -> vim.NfcService:
    """Return the vCenter/ESXi NfcService managed object on ``si``'s SOAP stub.

    Args:
        si: An authenticated ServiceInstance from pyVim.connect.SmartConnect.
    """
    _register_nfc_types()
    nfc_cls = GetVmodlType("vim.NfcService")
    return nfc_cls(NFC_SERVICE_MOID, si._stub)


def connect_vim(
    host: str,
    username: str,
    password: str,
    port: int = 443,
    thumbprint: Optional[str] = None,
    allow_untrusted: bool = False,
) -> vim.ServiceInstance:
    """Login to vCenter or ESXi using pyVim.connect.SmartConnect.

    Args:
        host: vCenter or ESXi hostname/IP.
        username: VIM user name.
        password: VIM password.
        port: HTTPS port, usually 443.
        thumbprint: Optional SHA-1 SSL thumbprint of the management endpoint.
        allow_untrusted: If True, skip certificate validation.
    """
    ssl_context = None
    if allow_untrusted:
        ssl_context = _ssl_client_context(verify=False)
    return SmartConnect(
        host=host,
        user=username,
        pwd=password,
        port=port,
        thumbprint=thumbprint,
        sslContext=ssl_context,
        disableSslCertValidation=allow_untrusted,
    )


def _virtual_disk_key(vm: vim.VirtualMachine, disk_path: str) -> int:
    """Return the VirtualDisk device key for ``disk_path``.

    ``disk_path`` may be the currently attached leaf or any parent in
    that disk's snapshot delta chain (``backing.parent``). After a
    snapshot, the VM's hardware points at the new leaf (for example
    ``…-000008.vmdk``) while VDDK Open still uses the snapshot file
    (``…-000007.vmdk``). Both share the same ``VirtualDisk.key``.
    """
    for device in vm.config.hardware.device:
        if not isinstance(device, vim.vm.device.VirtualDisk):
            continue
        backing = getattr(device, "backing", None)
        while backing is not None:
            if getattr(backing, "fileName", None) == disk_path:
                return device.key
            backing = getattr(backing, "parent", None)
    raise ValueError(f"VMDK path {disk_path!r} is not attached to {vm._moId}")


def get_nfc_ticket(
    si: vim.ServiceInstance,
    vm: vim.VirtualMachine,
    disk_device_key: Optional[int] = None,
    host_for_access: Optional[vim.HostSystem] = None,
    read_only: bool = True,
    disk_path: Optional[str] = None,
) -> vim.HostServiceTicket:
    """Return a one-time NFC HostServiceTicket for ``vm``.

    Matches VDDK: ``NfcGetVmFiles`` when only the VM is known (read-only),
    ``NfcRandomAccessOpenReadonly`` / ``NfcRandomAccessOpenDisk`` when a
    virtual disk device key (or datastore path) is supplied.

    Args:
        si: Authenticated ServiceInstance.
        vm: Target virtual machine.
        disk_device_key: Optional VirtualDisk.device key (for example 2000).
        host_for_access: Host that should serve NFC; defaults to the VM's host.
        read_only: When False, request a writable ticket (needs a disk).
        disk_path: Datastore path used to resolve ``disk_device_key``.
    """
    nfc = nfc_service(si)
    if read_only and disk_device_key is None and disk_path is None:
        return nfc.GetVmFiles(vm)
    if disk_device_key is None:
        if disk_path is None:
            raise ValueError("writable NFC tickets need disk_path or disk_device_key")
        disk_device_key = _virtual_disk_key(vm, disk_path)
    if host_for_access is None:
        host_for_access = vm.runtime.host
    if read_only:
        return nfc.RandomAccessOpenReadonly(vm, disk_device_key, host_for_access)
    return nfc.RandomAccessOpen(vm, disk_device_key, host_for_access)


def _format_thumbprint(digest: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in digest)


def _sha1_thumbprint(der_cert: bytes) -> str:
    return _format_thumbprint(hashlib.sha1(der_cert).digest())


def _normalize_thumbprint(thumbprint: str) -> str:
    return thumbprint.replace(":", "").replace(" ", "").upper()


def get_ssl_cert_thumbprint(
    host: str,
    port: int = 443,
    digest_algorithm: str = "sha1",
    ssl_context: Optional[ssl.SSLContext] = None,
    timeout: float = 30.0,
) -> str:
    """Return the TLS certificate thumbprint of ``host``:``port``.

    Reads the peer certificate in DER form and hashes it with ``hashlib``.
    The result is colon-separated uppercase hex (for example
    ``A5:AF:7D:…``), matching VDDK / pyVmomi SHA-1 thumbprints.

    Args:
        host: Hostname or IP of the TLS server.
        port: TLS port, usually 443.
        digest_algorithm: Hash name accepted by ``hashlib.new``. Default
            ``sha1`` is the format VDDK and pyVmomi expect.
        ssl_context: Optional SSL context. When omitted, a default client
            context is used with hostname checks and certificate
            validation disabled so a self-signed management certificate
            can still be read.
        timeout: Connect timeout in seconds.
    """
    if ssl_context is None:
        ssl_context = _ssl_client_context(verify=False)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=True)
    if not cert:
        raise ConnectionError(f"no peer certificate from {host}:{port}")
    return _format_thumbprint(hashlib.new(digest_algorithm, cert).digest())


def _readline(sock: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("authd connection closed")
        buf += chunk
        if len(buf) > 4096:
            raise ConnectionError("oversized authd response")
    return buf.decode("ascii", "replace").rstrip("\r\n")


def _expect_code(line: str, code: str, what: str) -> str:
    if not line.startswith(code):
        raise ConnectionError(f"authd {what} failed: {line}")
    return line[len(code) :].lstrip()


def nfcssl_service_name(service: str) -> str:
    """Return the NFCSSL authd PROXY service for an NFC service name.

    VCenter tickets still report ``vpxa-nfc``. NBDSSL uses
    ``PROXY vpxa-nfcssl`` (or ``ha-nfcssl`` on a direct ESXi ticket).

    Args:
        service: Ticket ``service`` field, for example ``vpxa-nfc``.
    """
    if service.endswith("ssl"):
        return service
    return f"{service}ssl"


def connect_authd(
    ticket: vim.HostServiceTicket,
    allow_untrusted: bool = False,
    timeout: float = 30.0,
    nfc_ssl: bool = True,
) -> ssl.SSLSocket:
    """Complete the ESXi authd handshake using an NFC HostServiceTicket.

    Wire sequence captured from VDDK against authd on TCP 902:

    1. Read the plaintext 220 banner, then wrap the socket with TLS.
    2. SESSION <sessionId>
    3. BANNER
    4. THUMBPRINT_SHA2 PlainText
    5. PROXY <ticket.service>     (vpxa-nfc / nbd) or vpxa-nfcssl (nbdssl)

    ``THUMBPRINT_SHA2 PlainText`` is used for both transports. NBDSSL
    is selected by the PROXY service name; after ``200 Connect
    ha-nfcssl`` a second TLS handshake is started in ``nfc_open``.

    Args:
        ticket: One-time ticket from get_nfc_ticket().
        allow_untrusted: If False, require the peer SHA-1 thumbprint to match
            ticket.sslThumbprint.
        timeout: Socket timeout in seconds.
        nfc_ssl: When True (the default), PROXY to the NFCSSL service
            used by nbdssl. Pass False for plaintext NFC (nbd).
    """
    host = ticket.host
    port = ticket.port or AUTHD_DEFAULT_PORT
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        banner = _readline(raw)
        if not banner.startswith("220"):
            raise ConnectionError(f"unexpected authd banner: {banner}")

        ssl_context = _ssl_client_context(verify=False)
        ssock = ssl_context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise

    try:
        if not allow_untrusted and ticket.sslThumbprint:
            peer = _sha1_thumbprint(ssock.getpeercert(True))
            if _normalize_thumbprint(peer) != _normalize_thumbprint(
                ticket.sslThumbprint
            ):
                raise ConnectionError(
                    f"ESXi SSL thumbprint mismatch: got {peer}, "
                    f"expected {ticket.sslThumbprint}"
                )

        ssock.sendall(f"SESSION {ticket.sessionId}\r\n".encode("ascii"))
        # Trailing space is part of the BANNER command token used by authd.
        ssock.sendall(b"BANNER \r\n")
        _expect_code(_readline(ssock), "220", "BANNER")

        ssock.sendall(b"THUMBPRINT_SHA2 PlainText\r\n")
        _expect_code(_readline(ssock), "200", "THUMBPRINT_SHA2")

        service = ticket.service or "vpxa-nfc"
        if nfc_ssl:
            service = nfcssl_service_name(service)
        ssock.sendall(f"PROXY {service}\r\n".encode("ascii"))
        _expect_code(_readline(ssock), "200", "PROXY")
        return ssock
    except Exception:
        ssock.close()
        raise


class NfcAuthSession:
    """Authenticated VIM session plus an authd/NFC TLS socket."""

    def __init__(
        self,
        si: vim.ServiceInstance,
        ticket: vim.HostServiceTicket,
        authd_sock: ssl.SSLSocket,
        nfc_ssl: bool = True,
    ) -> None:
        self.si = si
        self.ticket = ticket
        self.authd_sock = authd_sock
        self.nfc_ssl = nfc_ssl

    def close(self) -> None:
        """Close the authd socket and logout of the VIM session."""
        try:
            self.authd_sock.close()
        finally:
            Disconnect(self.si)

    def __enter__(self) -> "NfcAuthSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def authenticate(
    host: str,
    username: str,
    password: str,
    vm_moref: str,
    port: int = 443,
    thumbprint: Optional[str] = None,
    allow_untrusted: bool = False,
    disk_device_key: Optional[int] = None,
    disk_path: Optional[str] = None,
    read_only: bool = True,
    nfc_ssl: bool = True,
) -> NfcAuthSession:
    """Login to vSphere and complete NFC authd authentication for a VM.

    Args:
        host: vCenter or ESXi hostname/IP.
        username: VIM user name.
        password: VIM password.
        vm_moref: Virtual machine managed object id (for example ``vm-13098``).
        port: HTTPS port for VIM, usually 443.
        thumbprint: Optional SHA-1 thumbprint of the management endpoint.
        allow_untrusted: Skip TLS certificate checks when True.
        disk_device_key: Optional VirtualDisk device key; when omitted with
            ``read_only``, the VDDK ``NfcGetVmFiles`` ticket is used.
        disk_path: Datastore path used to resolve ``disk_device_key``.
        read_only: When False, request a writable ``NfcRandomAccessOpenDisk``
            ticket.
        nfc_ssl: When True (the default), complete authd with the NFCSSL
            PROXY service used by nbdssl. Pass False for nbd.
    """
    si = connect_vim(
        host,
        username,
        password,
        port=port,
        thumbprint=thumbprint,
        allow_untrusted=allow_untrusted,
    )
    try:
        vm = vim.VirtualMachine(vm_moref, si._stub)
        ticket = get_nfc_ticket(
            si,
            vm,
            disk_device_key=disk_device_key,
            disk_path=disk_path,
            read_only=read_only,
        )
        authd_sock = connect_authd(
            ticket, allow_untrusted=allow_untrusted, nfc_ssl=nfc_ssl
        )
    except Exception:
        Disconnect(si)
        raise
    return NfcAuthSession(si, ticket, authd_sock, nfc_ssl=nfc_ssl)
