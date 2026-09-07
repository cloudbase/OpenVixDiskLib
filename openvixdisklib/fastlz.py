# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""FastLZ compress / decompress used by NFC NBD compression.

The pip ``fastlz`` module (PyPI name ``pyfastlz``) prefixes compressed
output with a native ``uint32`` uncompressed length. NFC extra data is
raw FastLZ, so this wrapper strips that prefix on compress and restores
it on decompress.
"""

from __future__ import annotations

import struct

import fastlz as _fastlz  # type: ignore[import-untyped,import-not-found]

_PREFIX_SIZE = struct.calcsize("I")


def compress(data: bytes) -> bytes:
    """Compress ``data`` with FastLZ (level 1 below 64 KiB, else level 2).

    Args:
        data: Uncompressed bytes. FastLZ needs at least 16 bytes.
    """
    level = 1 if len(data) < 65536 else 2
    try:
        wrapped = _fastlz.compress(data, level=level)
    except _fastlz.FastlzError as exc:
        raise ValueError(str(exc)) from exc
    if len(wrapped) < _PREFIX_SIZE:
        raise ValueError("FastLZ compress returned a truncated buffer")
    return wrapped[_PREFIX_SIZE:]


def decompress(data: bytes, maxout: int) -> bytes:
    """Decompress FastLZ ``data`` into at most ``maxout`` bytes.

    Args:
        data: Compressed FastLZ buffer (no length prefix).
        maxout: Expected uncompressed length (output cap).
    """
    if not data:
        raise ValueError("FastLZ input is empty")
    wrapped = struct.pack("I", maxout) + data
    try:
        out = _fastlz.decompress(wrapped)
    except _fastlz.FastlzError as exc:
        raise ValueError(str(exc)) from exc
    if len(out) > maxout:
        raise ValueError(f"FastLZ decompressed {len(out)} bytes, cap is {maxout}")
    return out
