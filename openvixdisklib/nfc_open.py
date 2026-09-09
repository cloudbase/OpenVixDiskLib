# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""VDDK-compatible NFC disk open, sector read, and sector write.

After ``nfc_auth.connect_authd`` returns ``200 Connect``, NBD
(``useSSL=0``) stops using ``SSL_write`` and speaks NFC as raw TCP on
that file descriptor. NBDSSL (``useSSL=1``) starts a second TLS
handshake on the same TCP connection (``200 Connect ha-nfcssl``) and
speaks the same NFC frames as TLS application data. This module dups
the authd fd and speaks:

1. Classic 264-byte NFC messages (handshake, version, connection data,
   AIO session open).
2. NFC AIO frames (16-byte header plus payload) to open a VMDK and read
   or write sectors.

pyVmomi is not involved here; the ticket and TLS authd handshake already
happened in ``nfc_auth``.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct

from openvixdisklib import fastlz
from openvixdisklib.nfc_auth import NfcAuthSession, _ssl_client_context

NFC_MSG_SIZE = 264
NFC_AIO_MAGIC = 0xA100DA7A
NFC_AIO_HDR_SIZE = 16
NFC_SECTOR_SIZE = 512
NFC_PROTOCOL_VERSION = 11
# Max data bytes in one AIO IO request/reply fragment
# (NfcAioInitSession buffer).
NFC_AIO_BUFFER_SIZE = 65536

# Classic NFC message types observed on the wire (uint32 at offset 0).
NFC_MSG_SESSION_COMPLETE = 4
NFC_MSG_SESSION_PARAMS = 33
NFC_MSG_SESSION_PARAMS_REPLY = 36
NFC_MSG_HANDSHAKE = 43
NFC_MSG_VERSION = 51
NFC_MSG_AIO_SESSION_OPEN = 52
NFC_MSG_CONNECTION_DATA = 54
NFC_MSG_SESSION_FEATURES = 55

# SessionParams / feature bits from VDDK logs (interruption | switch).
NFC_SESSION_FEATURE_INTERRUPTION_SWITCH = 3

# AIO message types (NfcAioSendMessage "type = N").
NFC_AIO_MSG_ERROR = 1
NFC_AIO_MSG_OPEN_SESSION = 2
NFC_AIO_MSG_CLOSE_SESSION = 3
NFC_AIO_MSG_OPEN_FILE = 4
NFC_AIO_MSG_CLOSE_FILE = 5
NFC_AIO_MSG_IO = 7
NFC_AIO_MSG_SET_SOCK_OPTS = 9
NFC_AIO_MSG_DDB_GET = 11
NFC_AIO_MSG_SET_RES_POOL = 22

# Open-file body: file type NFC_DISK. 0x1e is what VDDK sends for
# VIXDISKLIB_FLAG_OPEN_READ_ONLY; writable opens clear bit 0x04 (0x1a).
NFC_DISK = 2
NFC_OPEN_FLAGS_READ_ONLY = 0x1E
NFC_OPEN_FLAGS_READ_WRITE = 0x1A

NFC_AIO_IO_WRITE = 0
NFC_AIO_IO_READ = 1

# High 32 bits of the IO opcode uint64. Captured from VDDK FASTLZ:
# writes that shrink go on the wire as type 2; incompressible writes
# fall back to type 0 with raw extra data.
NFC_COMPRESSION_NONE = 0
NFC_COMPRESSION_FASTLZ = 2


class NfcProtocolError(ConnectionError):
    """Raised when an NFC message is malformed or reports failure."""


def takeover_authd_socket(ssock: ssl.SSLSocket) -> socket.socket:
    """Return a raw socket on the authd TCP connection.

    VDDK writes NFC with ``write(SSL_get_fd(ssl), ...)`` after PROXY, so
    those bytes are not TLS records. Duping the fd lets Python do the
    same without ``SSLSocket.send`` re-encrypting, and without
    ``SSL_shutdown``.

    Args:
        ssock: The TLS socket from ``nfc_auth.connect_authd``.
    """
    timeout = ssock.gettimeout()
    raw = socket.socket(
        family=ssock.family,
        type=ssock.type,
        proto=ssock.proto,
        fileno=os.dup(ssock.fileno()),
    )
    raw.settimeout(timeout)
    _enable_tcp_nodelay(raw)
    return raw


def wrap_nfcssl_socket(ssock: ssl.SSLSocket, server_hostname: str) -> ssl.SSLSocket:
    """Start the second TLS session used by NBDSSL after PROXY.

    After ``200 Connect ha-nfcssl``, authd TLS is finished and
    ``ha-nfcssl`` expects a new ClientHello on the same TCP connection.
    The fd is dup'd so the original authd ``SSLSocket`` can be closed
    later without ``SSL_shutdown`` of this NFCSSL session.

    Args:
        ssock: The TLS socket from ``nfc_auth.connect_authd``.
        server_hostname: Host name passed to ``SSLContext.wrap_socket``.
    """
    raw = takeover_authd_socket(ssock)
    ssl_context = _ssl_client_context(verify=False)
    try:
        return ssl_context.wrap_socket(raw, server_hostname=server_hostname)
    except Exception:
        raw.close()
        raise


def _enable_tcp_nodelay(sock: socket.socket) -> None:
    """Disable Nagle so a small AIO header is not held back from its extra."""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def _recvn(sock: socket.socket, size: int) -> bytes:
    buf = bytearray(size)
    _recvn_into(sock, memoryview(buf))
    return bytes(buf)


def _recvn_into(sock: socket.socket, buf: memoryview) -> None:
    """Read exactly ``len(buf)`` bytes into ``buf``."""
    view = buf.cast("B") if buf.format != "B" else buf
    filled = 0
    n = len(view)
    while filled < n:
        got = sock.recv_into(view[filled:n])
        if not got:
            raise NfcProtocolError(
                f"NFC connection closed, needed {n} bytes, got {filled}"
            )
        filled += got


def _writable_bytes(buf: bytearray | memoryview, length: int) -> memoryview:
    """Return a writable ``B`` view of the first ``length`` bytes of ``buf``."""
    view = buf if isinstance(buf, memoryview) else memoryview(buf)
    if view.readonly:
        raise TypeError("read buffer is read-only")
    raw = view.cast("B") if view.format != "B" else view
    if len(raw) < length:
        raise RuntimeError(f"read buffer is {len(raw)} bytes, need {length}")
    return raw[:length]


def _send_nfc_msg(sock: socket.socket, msg_type: int, body: bytes = b"") -> None:
    if len(body) > NFC_MSG_SIZE - 4:
        raise ValueError("NFC classic message body too large")
    frame = struct.pack("<I", msg_type) + body
    sock.sendall(frame.ljust(NFC_MSG_SIZE, b"\x00"))


def _recv_nfc_msg(sock: socket.socket) -> tuple[int, bytes]:
    frame = _recvn(sock, NFC_MSG_SIZE)
    msg_type = struct.unpack_from("<I", frame)[0]
    return msg_type, frame[4:]


def _pack_aio_hdr(msg_type: int, payload_size: int, op_id: int) -> bytes:
    return struct.pack("<IIII", NFC_AIO_MAGIC, msg_type, payload_size, op_id)


def _unpack_aio_hdr(hdr: bytes) -> tuple[int, int, int]:
    magic, msg_type, size, op_id = struct.unpack_from("<IIII", hdr)
    if magic != NFC_AIO_MAGIC:
        raise NfcProtocolError(
            f"AIO header magic mismatch: 0x{magic:x}, expected 0x{NFC_AIO_MAGIC:x}"
        )
    if msg_type == NFC_AIO_MSG_ERROR:
        raise NfcProtocolError(f"AIO error opId={op_id} size={size}")
    return msg_type, size, op_id


class NfcDisk:
    """An NFC AIO session with one VMDK opened for I/O."""

    def __init__(
        self,
        sock: socket.socket,
        path: str,
        handle: int,
        sector_size: int,
        compression: int = NFC_COMPRESSION_NONE,
    ) -> None:
        """Wrap an AIO session that already has ``path`` open.

        Args:
            sock: NFC socket after handshake (raw TCP for nbd, TLS for nbdssl).
            path: Datastore path that was opened.
            handle: Server file handle from OPEN_FILE.
            sector_size: Sector size from the OPEN_FILE reply.
            compression: NFC IO compression type (``NFC_COMPRESSION_NONE``
                or ``NFC_COMPRESSION_FASTLZ``).
        """
        self._sock = sock
        self._op_id = 0
        self.path = path
        self.handle = handle
        self.sector_size = sector_size
        self.compression = compression
        self._closed = False

    def _next_op_id(self) -> int:
        op_id = self._op_id
        self._op_id += 1
        return op_id

    def _aio_send(self, msg_type: int, payload: bytes, extra: bytes = b"") -> int:
        """Send one AIO request (header, payload, and extra in one write)."""
        op_id = self._next_op_id()
        self._sock.sendall(
            _pack_aio_hdr(msg_type, len(payload), op_id) + payload + extra
        )
        return op_id

    def _aio_recv_reply(self) -> tuple[int, int, bytes]:
        """Read the next AIO reply. Returns ``(type, op_id, payload)``."""
        rhdr = _recvn(self._sock, NFC_AIO_HDR_SIZE)
        magic, rtype, rsize, rop = struct.unpack_from("<IIII", rhdr)
        if magic != NFC_AIO_MAGIC:
            raise NfcProtocolError(
                f"AIO header magic mismatch: 0x{magic:x}, expected 0x{NFC_AIO_MAGIC:x}"
            )
        body = _recvn(self._sock, rsize) if rsize else b""
        if rtype == NFC_AIO_MSG_ERROR:
            raise NfcProtocolError(f"AIO error opId={rop} size={rsize} {body.hex()}")
        return rtype, rop, body

    def _aio_roundtrip(
        self, msg_type: int, payload: bytes, extra: bytes = b"", extra_recv: int = 0
    ) -> bytes:
        """Send one AIO request and return the reply payload (+ extra)."""
        op_id = self._aio_send(msg_type, payload, extra)
        rtype, rop, body = self._aio_recv_reply()
        if rtype != msg_type or rop != op_id:
            raise NfcProtocolError(
                f"AIO reply type={rtype} opId={rop}, "
                f"expected type={msg_type} opId={op_id}"
            )
        if extra_recv:
            body += _recvn(self._sock, extra_recv)
        return body

    def read(self, start_sector: int, num_sectors: int = 1) -> bytes:
        """Read ``num_sectors`` starting at ``start_sector``.

        Matches ``VixDiskLib_Read``: one ``NFC_AIO_MSG_IO`` request in
        byte units. If the length exceeds the AIO buffer (64 KiB) the
        server replies with several same-``opId`` fragments, which are
        placed by the fragment byte offset in the reply (they may arrive
        out of order). FASTLZ open requests compression in the opcode;
        each reply fragment may be compressed (type 2) or raw (type 0).

        Args:
            start_sector: Sector offset from the start of the disk.
            num_sectors: Number of sectors to read.
        """
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        buf = bytearray(num_sectors * self.sector_size)
        self.readinto(start_sector, num_sectors, buf)
        return bytes(buf)

    def readinto(
        self,
        start_sector: int,
        num_sectors: int,
        buf: bytearray | memoryview,
    ) -> int:
        """Read ``num_sectors`` into ``buf`` starting at ``start_sector``.

        Uncompressed fragments are received directly into ``buf``. FastLZ
        still decompresses into a temporary buffer, then copies the
        result. ``buf`` must be writable and at least
        ``num_sectors * sector_size`` bytes (a ``get_buffer`` ctypes
        array is wrapped with ``memoryview`` by the VDDK-shaped handle).

        Args:
            start_sector: Sector offset from the start of the disk.
            num_sectors: Number of sectors to read.
            buf: Destination buffer.

        Returns:
            The number of bytes written to ``buf``.
        """
        if num_sectors < 1:
            raise ValueError("num_sectors must be at least 1")
        length = num_sectors * self.sector_size
        data = _writable_bytes(buf, length)
        offset = start_sector * self.sector_size
        opcode = NFC_AIO_IO_READ | (self.compression << 32)
        payload = struct.pack(
            "<QQQQIII", self.handle, opcode, offset, length, length, length, 0
        )
        op_id = self._next_op_id()
        self._sock.sendall(_pack_aio_hdr(NFC_AIO_MSG_IO, len(payload), op_id) + payload)
        filled = 0
        seen: set[int] = set()
        while filled < length:
            rhdr = _recvn(self._sock, NFC_AIO_HDR_SIZE)
            rtype, rsize, rop = _unpack_aio_hdr(rhdr)
            if rtype != NFC_AIO_MSG_IO or rop != op_id:
                raise NfcProtocolError(
                    f"AIO IO reply type={rtype} opId={rop}, "
                    f"expected type={NFC_AIO_MSG_IO} opId={op_id}"
                )
            body = _recvn(self._sock, rsize)
            if rsize < 36:
                raise NfcProtocolError(f"AIO IO reply payload too short: {rsize}")
            # Fragments may arrive out of order. Offset 28 is the byte
            # offset of this chunk within the request (0, 65536, …),
            # not a 0-based index. Offset 32 is the uncompressed
            # fragment length. When the opcode high bits are FastLZ
            # (2), extra data is compressed and offset 36 is its size.
            opcode = struct.unpack_from("<Q", body, 8)[0]
            dest, chunk_len = struct.unpack_from("<II", body, 28)
            if dest in seen or chunk_len == 0 or dest + chunk_len > length:
                raise NfcProtocolError(
                    f"AIO IO chunk offset={dest} length={chunk_len} invalid, "
                    f"request {length}"
                )
            seen.add(dest)
            ctype = opcode >> 32
            chunk_view = data[dest : dest + chunk_len]
            if ctype == NFC_COMPRESSION_FASTLZ:
                comp_len = struct.unpack_from("<I", body, 36)[0]
                extra = _recvn(self._sock, comp_len)
                try:
                    chunk = fastlz.decompress(extra, chunk_len)
                except ValueError as exc:
                    raise NfcProtocolError(
                        f"FastLZ read fragment failed: {exc}"
                    ) from exc
                if len(chunk) != chunk_len:
                    raise NfcProtocolError(
                        f"FastLZ read got {len(chunk)} bytes, expected {chunk_len}"
                    )
                chunk_view[:] = chunk
            elif ctype == NFC_COMPRESSION_NONE:
                _recvn_into(self._sock, chunk_view)
            else:
                raise NfcProtocolError(f"unsupported NFC IO compression type {ctype}")
            filled += chunk_len
        return length

    def write(self, start_sector: int, num_sectors: int, data: bytes) -> None:
        """Write ``num_sectors`` starting at ``start_sector``.

        Matches ``VixDiskLib_Write``: one ``NFC_AIO_MSG_IO`` ``opId``
        for the whole call. Chunks larger than the AIO buffer (64 KiB)
        are extra fragments with that same ``opId``; the server replies
        once. FASTLZ open compresses each fragment when that shrinks it.

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
        disk_offset = start_sector * self.sector_size
        op_id = self._next_op_id()
        frag_offset = 0
        while frag_offset < length:
            chunk = data[frag_offset : frag_offset + NFC_AIO_BUFFER_SIZE]
            extra = chunk
            extra_len = len(chunk)
            ctype = NFC_COMPRESSION_NONE
            if self.compression == NFC_COMPRESSION_FASTLZ and extra_len >= 16:
                compressed = fastlz.compress(chunk)
                if compressed and len(compressed) < extra_len:
                    extra = compressed
                    extra_len = len(compressed)
                    ctype = NFC_COMPRESSION_FASTLZ
            opcode = NFC_AIO_IO_WRITE | (ctype << 32)
            payload = struct.pack(
                "<QQQIIIII",
                self.handle,
                opcode,
                disk_offset,
                length,
                frag_offset,
                len(chunk),
                extra_len,
                0,
            )
            self._sock.sendall(
                _pack_aio_hdr(NFC_AIO_MSG_IO, len(payload), op_id) + payload + extra
            )
            frag_offset += len(chunk)
        rtype, rop, _body = self._aio_recv_reply()
        if rtype != NFC_AIO_MSG_IO or rop != op_id:
            raise NfcProtocolError(
                f"AIO IO write reply type={rtype} opId={rop}, "
                f"expected type={NFC_AIO_MSG_IO} opId={op_id}"
            )

    def close(self) -> None:
        """Close the VMDK, the AIO session, and the classic NFC session."""
        if self._closed:
            return
        self._closed = True
        try:
            self._aio_roundtrip(NFC_AIO_MSG_CLOSE_FILE, struct.pack("<Q", self.handle))
            self._aio_roundtrip(NFC_AIO_MSG_CLOSE_SESSION, struct.pack("<I", 0))
            _send_nfc_msg(self._sock, NFC_MSG_SESSION_COMPLETE)
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    def __enter__(self) -> NfcDisk:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _handshake(sock: socket.socket, client_name: str, op_id: str, version: int) -> None:
    """Run the classic NFC session handshake used by VDDK NBD."""
    _send_nfc_msg(sock, NFC_MSG_HANDSHAKE, b"PlainText")
    _send_nfc_msg(sock, NFC_MSG_SESSION_PARAMS)
    reply_type, _ = _recv_nfc_msg(sock)
    if reply_type != NFC_MSG_SESSION_PARAMS_REPLY:
        raise NfcProtocolError(
            f"expected session-params reply {NFC_MSG_SESSION_PARAMS_REPLY}, "
            f"got {reply_type}"
        )

    _send_nfc_msg(sock, NFC_MSG_VERSION, struct.pack("<I", version))
    reply_type, body = _recv_nfc_msg(sock)
    if reply_type != NFC_MSG_VERSION:
        raise NfcProtocolError(
            f"expected version reply {NFC_MSG_VERSION}, got {reply_type}"
        )
    remote_version = struct.unpack_from("<I", body)[0]
    if remote_version < 3:
        raise NfcProtocolError(
            f"NFC server version {remote_version} is too old for AIO"
        )

    name_b = client_name.encode("ascii")
    op_b = op_id.encode("ascii")
    _send_nfc_msg(
        sock, NFC_MSG_CONNECTION_DATA, struct.pack("<II", len(name_b), len(op_b))
    )
    sock.sendall(name_b)
    sock.sendall(op_b)
    _send_nfc_msg(
        sock,
        NFC_MSG_SESSION_FEATURES,
        struct.pack("<I", NFC_SESSION_FEATURE_INTERRUPTION_SWITCH),
    )
    _send_nfc_msg(sock, NFC_MSG_AIO_SESSION_OPEN)
    reply_type, _ = _recv_nfc_msg(sock)
    if reply_type != NFC_MSG_AIO_SESSION_OPEN:
        raise NfcProtocolError(
            f"expected AIO session-open reply "
            f"{NFC_MSG_AIO_SESSION_OPEN}, got {reply_type}"
        )


def _aio_prepare(disk: NfcDisk) -> None:
    disk._aio_roundtrip(NFC_AIO_MSG_OPEN_SESSION, bytes(16))
    disk._aio_roundtrip(NFC_AIO_MSG_SET_SOCK_OPTS, bytes(12))
    disk._aio_roundtrip(NFC_AIO_MSG_SET_RES_POOL, struct.pack("<I", 1))


def _parse_open_reply(body: bytes) -> tuple[int, int]:
    if len(body) < 40:
        raise NfcProtocolError(f"OPEN_FILE reply too short: {len(body)}")
    handle, file_type, _flags = struct.unpack_from("<QII", body, 8)
    sector_size = struct.unpack_from("<I", body, 36)[0]
    if file_type != NFC_DISK:
        raise NfcProtocolError(f"opened file type {file_type}, expected NFC_DISK")
    if sector_size == 0:
        sector_size = NFC_SECTOR_SIZE
    return handle, sector_size


def open_disk(
    session: NfcAuthSession,
    disk_path: str,
    client_name: str = "vddk",
    op_id: str = "nbdmode",
    version: int = NFC_PROTOCOL_VERSION,
    read_only: bool = True,
    compression: int = NFC_COMPRESSION_NONE,
) -> NfcDisk:
    """Open ``disk_path`` over the authenticated authd socket.

    Matches VDDK ``VixDiskLib_Open`` of a datastore path after the NFC
    ticket and authd PROXY handshake: session init, AIO open, then
    ``NFC_AIO_MSG_OPEN_FILE`` with type ``NFC_DISK``. NBD dups the
    authd fd and sends plaintext NFC. NBDSSL wraps that dup in a
    second TLS session (``session.nfc_ssl``).

    Args:
        session: Result of ``nfc_auth.authenticate``.
        disk_path: Datastore path, for example
            ``[datastore0] vm/vm.vmdk``.
        client_name: NFC client name; VDDK sends ``vddk``.
        op_id: NFC operation id; VDDK NBD sends ``nbdmode``.
        version: Client NFC protocol version (lab ESXi answered 11).
        read_only: When True, open with VDDK's read-only NFC flags.
        compression: ``NFC_COMPRESSION_NONE`` or ``NFC_COMPRESSION_FASTLZ``.
            OPEN_FILE flags are unchanged; compression is per IO message.
    """
    if compression not in (NFC_COMPRESSION_NONE, NFC_COMPRESSION_FASTLZ):
        raise NotImplementedError(
            f"NFC compression type {compression} is not supported"
        )
    sock: socket.socket
    if session.nfc_ssl:
        sock = wrap_nfcssl_socket(session.authd_sock, session.ticket.host)
    else:
        sock = takeover_authd_socket(session.authd_sock)
    try:
        _handshake(sock, client_name, op_id, version)
        disk = NfcDisk(
            sock,
            disk_path,
            handle=0,
            sector_size=NFC_SECTOR_SIZE,
            compression=compression,
        )
        _aio_prepare(disk)
        path_b = disk_path.encode("utf-8")
        open_flags = (
            NFC_OPEN_FLAGS_READ_ONLY if read_only else NFC_OPEN_FLAGS_READ_WRITE
        )
        open_body = struct.pack("<IIIIII", len(path_b), 0, 0, 0, NFC_DISK, open_flags)
        open_body = open_body.ljust(60, b"\x00")
        reply = disk._aio_roundtrip(NFC_AIO_MSG_OPEN_FILE, open_body, extra=path_b)
        handle, sector_size = _parse_open_reply(reply)
        disk.handle = handle
        disk.sector_size = sector_size
        return disk
    except Exception:
        sock.close()
        raise
