#!/usr/bin/env python3
"""Trace VDDK Read at several offsets/sizes for NFC IO capture."""

import ctypes
import os

VDDK_DIR = "/home/ubuntu/workspace/vmware_nbd_tests/vddk"
lib = ctypes.CDLL(os.path.join(VDDK_DIR, "libvixDiskLib.so"))

VIXDISKLIB_CRED_UID = 1
VIXDISKLIB_FLAG_OPEN_READ_ONLY = 4
SECTOR = 512


class VixDiskLibUidPasswdCreds(ctypes.Structure):
    _fields_ = [
        ("userName", ctypes.c_char_p),
        ("password", ctypes.c_char_p),
    ]


class VixDiskLibSessionIdCreds(ctypes.Structure):
    _fields_ = [
        ("cookie", ctypes.c_char_p),
        ("userName", ctypes.c_char_p),
        ("key", ctypes.c_char_p),
    ]


class VixDiskLibCreds(ctypes.Union):
    _fields_ = [
        ("uid", VixDiskLibUidPasswdCreds),
        ("sessionId", VixDiskLibSessionIdCreds),
    ]


class VixDiskLibConnectParams(ctypes.Structure):
    _fields_ = [
        ("vmxSpec", ctypes.c_char_p),
        ("serverName", ctypes.c_char_p),
        ("thumbPrint", ctypes.c_char_p),
        ("privateUse", ctypes.c_longlong),
        ("credType", ctypes.c_uint32),
        ("creds", VixDiskLibCreds),
        ("port", ctypes.c_uint32),
        ("nfcHostPort", ctypes.c_uint32),
        ("vimApiVer", ctypes.c_char_p),
    ]


def check(err, what):
    if err != 0:
        lib.VixDiskLib_GetErrorText.restype = ctypes.c_void_p
        lib.VixDiskLib_GetErrorText.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
        msg = lib.VixDiskLib_GetErrorText(err, None)
        text = ctypes.cast(msg, ctypes.c_char_p).value
        lib.VixDiskLib_FreeErrorText.argtypes = [ctypes.c_char_p]
        lib.VixDiskLib_FreeErrorText(ctypes.cast(msg, ctypes.c_char_p))
        raise SystemExit(f"{what} failed: {err} {text}")


def main():
    os.makedirs("/tmp/vddk-read-trace", exist_ok=True)
    config_path = "/tmp/vddk-read-trace/vddk.config"
    with open(config_path, "w") as f:
        f.write("tmpDirectory=/tmp/vddk-read-trace\n")
        f.write("log.fileName=/tmp/vddk-read-trace/vddk.log\n")
        f.write("log.fileLevel=verbose\n")
        f.write("vixDiskLib.nfc.LogLevel=4\n")
        f.write("vixDiskLib.transport.LogLevel=4\n")

    lib.VixDiskLib_InitEx.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.VixDiskLib_InitEx.restype = ctypes.c_uint64
    check(lib.VixDiskLib_InitEx(
        8, 0, None, None, None, VDDK_DIR.encode(), config_path.encode()),
        "InitEx")

    params = VixDiskLibConnectParams()
    params.vmxSpec = b"<sanitized>"
    params.serverName = b"<sanitized>"
    params.thumbPrint = b"<sanitized>"
    params.credType = VIXDISKLIB_CRED_UID
    params.creds.uid.userName = b"<sanitized>"
    params.creds.uid.password = b"<sanitized>"
    params.port = 443

    lib.VixDiskLib_ConnectEx.argtypes = [
        ctypes.POINTER(VixDiskLibConnectParams), ctypes.c_char,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.VixDiskLib_ConnectEx.restype = ctypes.c_uint64
    conn = ctypes.c_void_p()
    check(lib.VixDiskLib_ConnectEx(
        params, True, b"snapshot-13442", b"nbd", ctypes.byref(conn)),
        "ConnectEx")
    print("ConnectEx ok", flush=True)

    lib.VixDiskLib_Open.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p)]
    lib.VixDiskLib_Open.restype = ctypes.c_uint64
    disk = ctypes.c_void_p()
    path = b"[datastore0] test-coriolis-jenkins-rocky9/test-coriolis-jenkins-rocky9-000007.vmdk"
    check(lib.VixDiskLib_Open(conn, path, VIXDISKLIB_FLAG_OPEN_READ_ONLY, ctypes.byref(disk)),
          "Open")
    print("Open ok", flush=True)

    lib.VixDiskLib_Read.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
    lib.VixDiskLib_Read.restype = ctypes.c_uint64

    reads = [
        (0, 1),
        (0, 2),
        (1, 1),
        (8, 8),
        (0, 128),
        (0, 129),
        (256, 64),
    ]
    for start, n in reads:
        buf = ctypes.create_string_buffer(n * SECTOR)
        check(lib.VixDiskLib_Read(disk, start, n, buf), f"Read {start}+{n}")
        nz = sum(1 for b in buf.raw if b)
        print(f"Read start={start} n={n} first16={buf.raw[:16].hex()} nonzero={nz}",
              flush=True)

    lib.VixDiskLib_Close.argtypes = [ctypes.c_void_p]
    lib.VixDiskLib_Close.restype = ctypes.c_uint64
    lib.VixDiskLib_Disconnect.argtypes = [ctypes.c_void_p]
    lib.VixDiskLib_Disconnect.restype = ctypes.c_uint64
    lib.VixDiskLib_Close(disk)
    lib.VixDiskLib_Disconnect(conn)
    lib.VixDiskLib_Exit()


if __name__ == "__main__":
    main()
