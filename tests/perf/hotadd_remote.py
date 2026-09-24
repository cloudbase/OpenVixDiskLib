# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Time HotAdd write/read inside the proxy guest. Invoked over SSH by perf."""

from __future__ import annotations

import json
import sys
import time

from openvixdisklib import openvixdisklib as vixdisklib


def _pattern_bytes(length: int, seed: bytes) -> bytes:
    return (seed * ((length // len(seed)) + 1))[:length]


def main() -> int:
    """Read connect kwargs and size from stdin, HotAdd, time write/read."""
    cfg = json.load(sys.stdin)
    nbytes = int(cfg["nbytes"])
    if nbytes % vixdisklib.VIXDISKLIB_SECTOR_SIZE:
        print(json.dumps({"ok": False, "error": f"unaligned size {nbytes}"}))
        return 1
    n_sectors = nbytes // vixdisklib.VIXDISKLIB_SECTOR_SIZE
    payload = _pattern_bytes(nbytes, f"PERF-{cfg['label']}-".encode())
    handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
    modes = handle.get_transport_modes()
    if "hotadd" not in modes:
        print(json.dumps({"ok": False, "error": f"hotadd not listed: {modes}"}))
        return 1
    connect_kwargs = {
        "server_name": cfg["server_name"],
        "thumbprint": cfg["thumbprint"],
        "username": cfg["username"],
        "password": cfg["password"],
        "vmx_spec": cfg["vmx_spec"],
        "read_only": False,
        "transport_modes": "hotadd",
        "port": cfg.get("port", 443),
        "allow_untrusted": cfg.get("allow_untrusted", False),
    }
    write_buf = vixdisklib.get_buffer(nbytes)
    read_buf = vixdisklib.get_buffer(nbytes)
    write_buf[:nbytes] = payload
    mode = ""
    with (
        handle.connect(**connect_kwargs) as conn,
        handle.open(conn, cfg["disk_path"], flags=0) as disk,
    ):
        mode = handle.get_transport_mode(disk)
        if mode != "hotadd":
            print(json.dumps({"ok": False, "error": f"mode {mode!r}"}))
            return 1
        started = time.perf_counter()
        handle.write(disk, 0, n_sectors, write_buf)
        write_s = time.perf_counter() - started
        read_buf[:nbytes] = b"\xa5" * nbytes
        started = time.perf_counter()
        handle.read(disk, 0, n_sectors, read_buf)
        read_s = time.perf_counter() - started
        if read_buf.raw[:nbytes] != payload:
            print(json.dumps({"ok": False, "error": "mismatch after read"}))
            return 1
    print(
        json.dumps(
            {
                "ok": True,
                "mode": mode,
                "write_s": write_s,
                "read_s": read_s,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
