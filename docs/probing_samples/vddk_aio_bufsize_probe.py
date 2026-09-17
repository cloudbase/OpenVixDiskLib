#!/usr/bin/env python3
"""Probe VDDK ``vixDiskLib.nfcAio.Session.BufSizeIn64KB`` vs NFC read extras.

Not part of the library. Creates a temp lab VM, runs native VDDK over ``nbd``
under ``strace``, and prints OPEN_SESSION payloads plus IO reply chunk
lengths. BufSizeIn64KB=1 is 64 KiB; 32 is 2 MiB.
"""

from __future__ import annotations

import os
import pickle
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
os.environ.pop("LD_PRELOAD", None)

from tests.integration import vixdisklib  # noqa: E402
from tests.integration.base import (  # noqa: E402
    SECTOR_SIZE,
    create_lab_vm,
    destroy_lab_vm,
    ensure_vddk_library_path,
)

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
_VDDK = os.path.join(_REPO, ".vddk")
_AIO_MAGIC = 0xA100DA7A
_AIO_HDR = 16
_NFC_AIO_MSG_OPEN_SESSION = 2
_NFC_AIO_MSG_IO = 7
_NFC_AIO_IO_READ = 1
# 129 sectors: two 64 KiB-class fragments today. 4097: 2 MiB + 512.
_READS = ((129, "129s"), (4097, "2MiB+512"))


def _vddk_config(directory: str, buf_size_in_64kb: int, buf_count: int) -> str:
    path = os.path.join(directory, "vddk.config")
    log = os.path.join(directory, "vddk.log")
    with open(path, "w", encoding="utf-8") as config:
        config.write(f"tmpDirectory={directory}\n")
        config.write(f"log.fileName={log}\n")
        config.write("log.fileLevel=verbose\n")
        config.write("vixDiskLib.nfc.LogLevel=4\n")
        config.write("vixDiskLib.transport.LogLevel=4\n")
        config.write(f"vixDiskLib.nfcAio.Session.BufSizeIn64KB={buf_size_in_64kb}\n")
        config.write(f"vixDiskLib.nfcAio.Session.BufCount={buf_count}\n")
    return path


def _worker(lab_pkl: str, work_dir: str, buf_size_in_64kb: int, buf_count: int) -> None:
    ensure_vddk_library_path()
    with open(lab_pkl, "rb") as pickle_file:
        lab = pickle.load(pickle_file)
    config_path = _vddk_config(work_dir, buf_size_in_64kb, buf_count)
    handle = vixdisklib.VixDiskLibHandle(
        vixdisklib_compatibility_version="8.0", config_path=config_path
    )
    kwargs = {
        "server_name": lab.host,
        "port": lab.port,
        "thumbprint": lab.thumbprint,
        "username": lab.username,
        "password": lab.password,
        "vmx_spec": lab.vmx_spec,
        "transport_modes": "nbd",
        "read_only": True,
    }
    with (
        handle.connect(**kwargs) as conn,
        handle.open(
            conn, lab.disk_path, flags=vixdisklib.VIXDISKLIB_FLAG_OPEN_READ_ONLY
        ) as disk,
    ):
        print("transport", handle.get_transport_mode(disk), flush=True)
        for n_sectors, label in _READS:
            buf = vixdisklib.get_buffer(n_sectors * SECTOR_SIZE)
            handle.read(disk, 0, n_sectors, buf)
            print(f"read {label} ok", flush=True)
    handle.exit()


def _decode_strace_hex(quoted: str) -> bytes:
    parts = re.findall(r"\\x([0-9a-fA-F]{2})", quoted)
    return bytes(int(part, 16) for part in parts)


def parse_strace(path: str) -> tuple[list[bytes], list[tuple[int, int, int]]]:
    """Return client OPEN_SESSION payloads and **server** read-reply chunks.

    VDDK reads the 16-byte AIO header in one syscall and the payload in
    the next, so bytes are concatenated per fd before parsing.
    """
    syscall_re = re.compile(r'(read|write|recv|send)\((\d+),\s*"(.*?)"')
    writes: dict[int, bytearray] = {}
    reads: dict[int, bytearray] = {}
    with open(path, encoding="utf-8", errors="replace") as strace_file:
        for line in strace_file:
            match = syscall_re.search(line)
            if not match:
                continue
            op, fd_s, quoted = match.group(1), match.group(2), match.group(3)
            buf = _decode_strace_hex(quoted)
            if not buf:
                continue
            fd = int(fd_s)
            bucket = writes if op in ("write", "send") else reads
            bucket.setdefault(fd, bytearray()).extend(buf)

    def walk(buf: bytes, collect_open: bool, collect_io: bool) -> None:
        offset = 0
        while offset + _AIO_HDR <= len(buf):
            magic, msg_type, size, _opid = struct.unpack_from("<IIII", buf, offset)
            if magic != _AIO_MAGIC:
                offset += 1
                continue
            payload = buf[offset + _AIO_HDR : offset + _AIO_HDR + size]
            if collect_open and msg_type == _NFC_AIO_MSG_OPEN_SESSION and len(payload) >= 16:
                open_sessions.append(payload[:16])
            if collect_io and msg_type == _NFC_AIO_MSG_IO and len(payload) >= 40:
                opcode = struct.unpack_from("<Q", payload, 8)[0]
                if opcode & 0xFFFFFFFF == _NFC_AIO_IO_READ:
                    dest, chunk_len, extra_len = struct.unpack_from("<III", payload, 28)
                    io_reads.append((dest, chunk_len, extra_len))
            offset += _AIO_HDR + size

    open_sessions: list[bytes] = []
    io_reads: list[tuple[int, int, int]] = []
    for buf in writes.values():
        walk(bytes(buf), collect_open=True, collect_io=False)
    for buf in reads.values():
        walk(bytes(buf), collect_open=False, collect_io=True)
    return open_sessions, io_reads


def _interesting_log_lines(log_path: str) -> list[str]:
    keys = (
        "Buffer Size",
        "BufCount",
        "BufSize",
        "AIO session",
        "Aio Session",
        "maximum session",
        "Req. buffer",
    )
    lines: list[str] = []
    if not os.path.isfile(log_path):
        return lines
    with open(log_path, encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            if any(key in line for key in keys):
                lines.append(line.rstrip())
    return lines


def _run_traced(lab_pkl: str, buf_size_in_64kb: int, buf_count: int) -> None:
    work_dir = tempfile.mkdtemp(prefix=f"vddk-aio-bufsize-{buf_size_in_64kb}-")
    strace_path = os.path.join(work_dir, "nfc.strace")
    python = sys.executable
    cmd = [
        "strace",
        "-f",
        "-x",
        "-s",
        "96",
        "-e",
        "trace=read,write,readv,writev,send,recv,sendto,recvfrom",
        "-o",
        strace_path,
        python,
        __file__,
        "--worker",
        lab_pkl,
        work_dir,
        str(buf_size_in_64kb),
        str(buf_count),
    ]
    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    lib_path = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = _VDDK if not lib_path else f"{_VDDK}:{lib_path}"
    print(f"\n=== BufSizeIn64KB={buf_size_in_64kb} BufCount={buf_count} ===")
    print("work_dir", work_dir)
    proc = subprocess.run(cmd, env=env, check=False, text=True, capture_output=True)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    print("worker exit", proc.returncode)
    for line in _interesting_log_lines(os.path.join(work_dir, "vddk.log")):
        print("LOG", line)
    open_sessions, io_reads = parse_strace(strace_path)
    for payload in open_sessions:
        ints = struct.unpack("<IIII", payload)
        print("OPEN_SESSION hex", payload.hex(), "u32", ints)
    print("read fragments (dest, chunk_len, extra_len):")
    for dest, chunk_len, extra_len in io_reads:
        print(f"  dest={dest} chunk_len={chunk_len} extra_len={extra_len}")
    if io_reads:
        print("max chunk_len", max(item[1] for item in io_reads))


def main() -> None:
    if "--worker" in sys.argv:
        _, lab_pkl, work_dir, buf_size, buf_count = sys.argv[1:]
        _worker(lab_pkl, work_dir, int(buf_size), int(buf_count))
        return
    ensure_vddk_library_path()
    lab = create_lab_vm()
    lab_pkl = "/tmp/vddk-aio-bufsize-lab.pkl"
    try:
        with open(lab_pkl, "wb") as pickle_file:
            pickle.dump(lab, pickle_file)
        print("lab", lab.disk_path, lab.vm_moref)
        for buf_size, buf_count in ((1, 1), (32, 1)):
            _run_traced(lab_pkl, buf_size, buf_count)
    finally:
        destroy_lab_vm(lab)


if __name__ == "__main__":
    main()
