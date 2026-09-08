#!/usr/bin/env python3
"""Probe NFC write open-flags / opcode. Not part of the library."""

from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(0, "/home/ubuntu/workspace/vmware_nbd_tests")
os.environ.pop("LD_PRELOAD", None)

from openvixdisklib import nfc_open
from tests.integration.base import TestBase

NFC_AIO_MSG_ERROR = 1
NFC_AIO_MSG_IO = 7


def recvn(sock, size):
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise RuntimeError(f"closed, got {len(buf)}/{size}")
        buf.extend(chunk)
    return bytes(buf)


def open_rw(session, disk_path, oflag):
    sock = nfc_open.takeover_authd_socket(session.authd_sock)
    nfc_open._handshake(sock, "vddk", "nbdmode", nfc_open.NFC_PROTOCOL_VERSION)
    disk = nfc_open.NfcDisk(
        sock, disk_path, handle=0, sector_size=nfc_open.NFC_SECTOR_SIZE)
    nfc_open._aio_prepare(disk)
    path_b = disk_path.encode("utf-8")
    open_body = struct.pack(
        "<IIIIII", len(path_b), 0, 0, 0, nfc_open.NFC_DISK, oflag)
    open_body = open_body.ljust(60, b"\x00")
    reply = disk._aio_roundtrip(
        nfc_open.NFC_AIO_MSG_OPEN_FILE, open_body, extra=path_b)
    handle, sector_size = nfc_open._parse_open_reply(reply)
    disk.handle = handle
    disk.sector_size = sector_size
    echoed = struct.unpack_from("<I", reply, 20)[0]
    print(f"OPEN sent=0x{oflag:x} echoed=0x{echoed:x} handle={handle}")
    return disk


def try_io(disk, opcode, flags_field, data, send_extra=True):
    length = len(data)
    payload = struct.pack(
        "<QQQQIII",
        disk.handle, opcode, 0, length, length, length, flags_field)
    op_id = disk._next_op_id()
    disk._sock.sendall(
        nfc_open._pack_aio_hdr(NFC_AIO_MSG_IO, len(payload), op_id) + payload)
    if send_extra:
        disk._sock.sendall(data)
    rhdr = recvn(disk._sock, 16)
    magic, rtype, rsize, rop = struct.unpack_from("<IIII", rhdr)
    body = recvn(disk._sock, rsize) if rsize else b""
    extra = b""
    if rtype == NFC_AIO_MSG_IO and rsize >= 36:
        chunk_len = struct.unpack_from("<I", body, 32)[0]
        if 0 < chunk_len <= 65536:
            extra = recvn(disk._sock, chunk_len)
    return rtype, rsize, body, extra


class Probe(TestBase):
    def test_probe(self):
        data = self.pattern_bytes(self.SECTOR_SIZE, b"PROBE-S0")
        open_flags = [
            0x1C, 0x00, 0x1F, 0x0E, 0x0C, 0x04, 0x06, 0x02,
            0x3E, 0x5E, 0x16, 0x1A, 0x1D, 0x0A, 0x08, 0x20,
            0x3C, 0x7E, 0xFE, 0x100, 0x1E, 0x0F, 0x18,
        ]
        # First: opcode 2 (guessed write) across open flags
        for oflag in open_flags:
            with self.authenticate() as session:
                try:
                    disk = open_rw(session, self.DISK_PATH, oflag)
                except Exception as exc:
                    print(f"OPEN FAIL 0x{oflag:x} {exc}")
                    continue
                rtype, rsize, body, extra = try_io(disk, 2, 0, data)
                print(
                    f"  IO op=2 flags=0x{oflag:x} rtype={rtype} "
                    f"extra={len(extra)} body={body.hex()}")
                if rtype == NFC_AIO_MSG_IO:
                    got = disk.read(0, 1)
                    print(f"  readback match={got==data} {got[:16]!r}")
                    if got == data:
                        print("SUCCESS opcode=2")
                        disk.close()
                        return
                try:
                    disk.close()
                except Exception:
                    disk._sock.close()

        # Then: opcode 1 with ioflags as write bit, open 0x1C and 0x00
        for oflag in (0x1C, 0x00, 0x0E):
            for opcode, ioflags, send_extra in (
                    (1, 1, True), (1, 2, True), (2, 1, True),
                    (4, 0, True), (5, 0, True), (8, 0, True),
                    (2, 0, True)):
                with self.authenticate() as session:
                    disk = open_rw(session, self.DISK_PATH, oflag)
                    rtype, rsize, body, extra = try_io(
                        disk, opcode, ioflags, data, send_extra)
                    print(
                        f"  IO op={opcode} iofl={ioflags} of=0x{oflag:x} "
                        f"rtype={rtype} extra={len(extra)} body={body[:16].hex()}")
                    if rtype == NFC_AIO_MSG_IO:
                        try:
                            got = disk.read(0, 1)
                            print(f"  readback match={got==data} {got[:16]!r}")
                            if got == data:
                                print("SUCCESS")
                                disk.close()
                                return
                        except Exception as exc:
                            print(f"  readback exc {exc}")
                    try:
                        disk.close()
                    except Exception:
                        disk._sock.close()
        print("NO SUCCESS")


if __name__ == "__main__":
    unittest.main()
