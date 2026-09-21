#!/usr/bin/env python3
"""Trace native VDDK SAN open/read (device matching + VMFS, not NFC).

SAN is not a wire protocol. Capture with::

    strace -f -e openat,pread64,pwrite64,ioctl -o /tmp/vddk-san.strace \\
        python3 docs/probing_samples/vddk_san_trace.py

``InitEx`` must pass a libDir that contains ``lib64/libdiskLibPlugin.so``
(the advanced transport plugin). VDDK then matches the VMFS LUN by NAA
and reads the flat extent through its VMFS driver.

Replace the ``<sanitized>`` fields with lab values. Do not commit
credentials or live IPs.
"""

import ctypes
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VDDK_DIR = os.path.join(REPO, ".vddk")
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
    os.makedirs("/tmp/vddk-san-trace", exist_ok=True)
    config_path = "/tmp/vddk-san-trace/vddk.config"
    with open(config_path, "w") as f:
        f.write("tmpDirectory=/tmp/vddk-san-trace\n")
        f.write("log.fileName=/tmp/vddk-san-trace/vddk.log\n")
        f.write("log.fileLevel=verbose\n")
        f.write("vixDiskLib.transport.LogLevel=4\n")

    plugin = os.path.join(VDDK_DIR, "lib64", "libdiskLibPlugin.so")
    if not os.path.isfile(plugin):
        raise SystemExit(
            f"missing {plugin}; SAN needs libdiskLibPlugin under libDir/lib64"
        )

    lib.VixDiskLib_InitEx.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.VixDiskLib_InitEx.restype = ctypes.c_uint64
    check(lib.VixDiskLib_InitEx(
        8, 0, None, None, None, VDDK_DIR.encode(), config_path.encode()),
        "InitEx")

    lib.VixDiskLib_ListTransportModes.restype = ctypes.c_char_p
    print("ListTransportModes", lib.VixDiskLib_ListTransportModes(), flush=True)

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
        params, True, None, b"san", ctypes.byref(conn)),
        "ConnectEx")
    print("ConnectEx ok", flush=True)

    lib.VixDiskLib_Open.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p)]
    lib.VixDiskLib_Open.restype = ctypes.c_uint64
    disk = ctypes.c_void_p()
    path = b"[ovdl-iscsi-<id>] <vm>/<vm>.vmdk"
    check(lib.VixDiskLib_Open(conn, path, VIXDISKLIB_FLAG_OPEN_READ_ONLY, ctypes.byref(disk)),
          "Open")
    print("Open ok", flush=True)

    lib.VixDiskLib_GetTransportMode.argtypes = [ctypes.c_void_p]
    lib.VixDiskLib_GetTransportMode.restype = ctypes.c_char_p
    print("transport", lib.VixDiskLib_GetTransportMode(disk), flush=True)

    lib.VixDiskLib_Read.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
    lib.VixDiskLib_Read.restype = ctypes.c_uint64
    for start, n in ((0, 1), ((1024 * 1024 * 1024) // SECTOR, 1)):
        buf = ctypes.create_string_buffer(n * SECTOR)
        check(lib.VixDiskLib_Read(disk, start, n, buf), f"Read {start}+{n}")
        print(
            f"Read start={start} n={n} first16={buf.raw[:16].hex()}",
            flush=True,
        )

    lib.VixDiskLib_Close.argtypes = [ctypes.c_void_p]
    lib.VixDiskLib_Close.restype = ctypes.c_uint64
    lib.VixDiskLib_Disconnect.argtypes = [ctypes.c_void_p]
    lib.VixDiskLib_Disconnect.restype = ctypes.c_uint64
    lib.VixDiskLib_Close(disk)
    lib.VixDiskLib_Disconnect(conn)
    lib.VixDiskLib_Exit()


if __name__ == "__main__":
    main()
