# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Run HotAdd I/O inside the proxy guest. Invoked over SSH by tests."""

from __future__ import annotations

import json
import sys

from pyVmomi import vim

from openvixdisklib import openvixdisklib as vixdisklib
from openvixdisklib.hotadd import find_proxy_vm


def main() -> int:
    """Read connect kwargs and sector patterns from stdin, HotAdd, write/read."""
    cfg = json.load(sys.stdin)
    handle = vixdisklib.VixDiskLibHandle(vixdisklib_compatibility_version="8.0")
    modes = handle.get_transport_modes()
    if "hotadd" not in modes:
        print(json.dumps({"ok": False, "error": f"hotadd not listed: {modes}"}))
        return 1
    patterns = {
        int(sector): bytes.fromhex(data) for sector, data in cfg["patterns"].items()
    }
    sector_size = cfg.get("sector_size", vixdisklib.VIXDISKLIB_SECTOR_SIZE)
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
    write_buf = vixdisklib.get_buffer(sector_size)
    read_buf = vixdisklib.get_buffer(sector_size)
    extra_after = 0
    mode = ""
    with handle.connect(**connect_kwargs) as conn:
        with handle.open(conn, cfg["disk_path"], flags=0) as disk:
            mode = handle.get_transport_mode(disk)
            if mode != "hotadd":
                print(json.dumps({"ok": False, "error": f"mode {mode!r}"}))
                return 1
            for start, expected in patterns.items():
                write_buf[:sector_size] = expected
                handle.write(disk, start, 1, write_buf)
                read_buf[:sector_size] = b"\xa5" * sector_size
                handle.read(disk, start, 1, read_buf)
                if read_buf.raw[:sector_size] != expected:
                    print(
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"mismatch at sector {start}",
                            }
                        )
                    )
                    return 1
        extra_after = _extra_disk_count(conn.si)
    print(
        json.dumps({"ok": True, "mode": mode, "extra_disks_after_close": extra_after})
    )
    return 0


def _extra_disk_count(si) -> int:
    """Return how many non-boot disks remain on the proxy VM."""
    proxy = find_proxy_vm(si)
    disks = [
        device
        for device in proxy.config.hardware.device
        if isinstance(device, vim.vm.device.VirtualDisk)
    ]
    return max(0, len(disks) - 1)


if __name__ == "__main__":
    sys.exit(main())
