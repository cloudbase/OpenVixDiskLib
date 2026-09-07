# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.
#
# Python port of FastLZ (Byte-aligned LZ77), used by VMware NFC
# VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ.
#
# FastLZ - Copyright (C) 2005-2020 Ariya Hidayat <ariya.hidayat@gmail.com>
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""FastLZ compress / decompress used by NFC NBD compression."""

from __future__ import annotations

MAX_COPY = 32
MAX_LEN = 264
MAX_L1_DISTANCE = 8192
MAX_L2_DISTANCE = 8191
MAX_FARDISTANCE = 65535 + MAX_L2_DISTANCE - 1
HASH_LOG = 13
HASH_SIZE = 1 << HASH_LOG
HASH_MASK = HASH_SIZE - 1


def _readu32(buf: bytes | bytearray, offset: int) -> int:
    return buf[offset] | (buf[offset + 1] << 8) | (
        buf[offset + 2] << 16) | (buf[offset + 3] << 24)


def _hash(value: int) -> int:
    return ((value * 2654435769) >> (32 - HASH_LOG)) & HASH_MASK


def _cmp(src: bytes, p: int, q: int, q_end: int) -> int:
    start = p
    if _readu32(src, p) == _readu32(src, q):
        p += 4
        q += 4
    while q < q_end:
        mismatch = src[p] != src[q]
        p += 1
        q += 1
        if mismatch:
            break
    return p - start


def _extend_match(out: bytearray, ref: int, length: int) -> None:
    while length:
        take = min(length, len(out) - ref)
        out.extend(out[ref:ref + take])
        length -= take


def _literals(src: bytes, src_off: int, runs: int, out: bytearray) -> None:
    while runs >= MAX_COPY:
        out.append(MAX_COPY - 1)
        out.extend(src[src_off:src_off + MAX_COPY])
        src_off += MAX_COPY
        runs -= MAX_COPY
    if runs > 0:
        out.append(runs - 1)
        out.extend(src[src_off:src_off + runs])


def _flz1_match(length: int, distance: int, out: bytearray) -> None:
    distance -= 1
    if length > MAX_LEN - 2:
        while length > MAX_LEN - 2:
            out.append((7 << 5) + (distance >> 8))
            out.append(MAX_LEN - 2 - 7 - 2)
            out.append(distance & 255)
            length -= MAX_LEN - 2
    if length < 7:
        out.append((length << 5) + (distance >> 8))
        out.append(distance & 255)
    else:
        out.append((7 << 5) + (distance >> 8))
        out.append(length - 7)
        out.append(distance & 255)


def _flz2_match(length: int, distance: int, out: bytearray) -> None:
    distance -= 1
    if distance < MAX_L2_DISTANCE:
        if length < 7:
            out.append((length << 5) + (distance >> 8))
            out.append(distance & 255)
        else:
            out.append((7 << 5) + (distance >> 8))
            length -= 7
            while length >= 255:
                out.append(255)
                length -= 255
            out.append(length)
            out.append(distance & 255)
    elif length < 7:
        distance -= MAX_L2_DISTANCE
        out.append((length << 5) + 31)
        out.append(255)
        out.append(distance >> 8)
        out.append(distance & 255)
    else:
        distance -= MAX_L2_DISTANCE
        out.append((7 << 5) + 31)
        length -= 7
        while length >= 255:
            out.append(255)
            length -= 255
        out.append(length)
        out.append(255)
        out.append(distance >> 8)
        out.append(distance & 255)


def _compress_level(src: bytes, level: int) -> bytes:
    length = len(src)
    ip = 0
    ip_bound = length - 4
    ip_limit = length - 12 - 1
    out = bytearray()
    htab = [0] * HASH_SIZE
    max_distance = MAX_L1_DISTANCE if level == 1 else MAX_FARDISTANCE
    anchor = 0
    ip = 2
    while ip < ip_limit:
        while True:
            seq = _readu32(src, ip) & 0xffffff
            h = _hash(seq)
            ref = htab[h]
            htab[h] = ip
            distance = ip - ref
            cmp_val = (
                _readu32(src, ref) & 0xffffff
                if 0 <= ref < ip and distance < max_distance
                else 0x1000000)
            if ip >= ip_limit:
                break
            ip += 1
            if seq == cmp_val:
                break
        if ip >= ip_limit:
            break
        ip -= 1
        if level == 2 and distance >= MAX_L2_DISTANCE:
            if src[ref + 3] != src[ip + 3] or src[ref + 4] != src[ip + 4]:
                ip += 1
                continue
        if ip > anchor:
            _literals(src, anchor, ip - anchor, out)
        match_len = _cmp(src, ref + 3, ip + 3, ip_bound)
        if level == 1:
            _flz1_match(match_len, distance, out)
        else:
            _flz2_match(match_len, distance, out)
        ip += match_len
        seq = _readu32(src, ip)
        htab[_hash(seq & 0xffffff)] = ip
        ip += 1
        htab[_hash(seq >> 8)] = ip
        ip += 1
        anchor = ip
    _literals(src, anchor, length - anchor, out)
    if level == 2 and out:
        out[0] |= 1 << 5
    return bytes(out)


def compress(data: bytes) -> bytes:
    """Compress ``data`` with FastLZ (level 1 below 64 KiB, else level 2).

    Args:
        data: Uncompressed bytes. FastLZ needs at least 16 bytes.
    """
    if len(data) < 65536:
        return _compress_level(data, 1)
    return _compress_level(data, 2)


def decompress(data: bytes, maxout: int) -> bytes:
    """Decompress FastLZ ``data`` into at most ``maxout`` bytes.

    Args:
        data: Compressed FastLZ buffer.
        maxout: Expected uncompressed length (output cap).
    """
    if not data:
        raise ValueError("FastLZ input is empty")
    level = (data[0] >> 5) + 1
    if level == 1:
        return _decompress_level1(data, maxout)
    if level == 2:
        return _decompress_level2(data, maxout)
    raise ValueError(f"unsupported FastLZ level {level}")


def _decompress_level1(src: bytes, maxout: int) -> bytes:
    ip = 0
    ip_limit = len(src)
    ip_bound = ip_limit - 2
    out = bytearray()
    ctrl = src[ip] & 31
    ip += 1
    while True:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ofs = (ctrl & 31) << 8
            if length == 6:
                if ip > ip_bound:
                    raise ValueError("truncated FastLZ match")
                length += src[ip]
                ip += 1
            if ip >= ip_limit:
                raise ValueError("truncated FastLZ match distance")
            ofs += src[ip]
            ip += 1
            length += 3
            ref = len(out) - ofs - 1
            if ref < 0 or len(out) + length > maxout:
                raise ValueError("FastLZ match out of range")
            _extend_match(out, ref, length)
        else:
            ctrl += 1
            if ip + ctrl > ip_limit or len(out) + ctrl > maxout:
                raise ValueError("truncated FastLZ literals")
            out.extend(src[ip:ip + ctrl])
            ip += ctrl
        if ip > ip_bound:
            break
        ctrl = src[ip]
        ip += 1
    return bytes(out)


def _decompress_level2(src: bytes, maxout: int) -> bytes:
    ip = 0
    ip_limit = len(src)
    ip_bound = ip_limit - 2
    out = bytearray()
    ctrl = src[ip] & 31
    ip += 1
    while True:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ofs = (ctrl & 31) << 8
            if length == 6:
                while True:
                    if ip > ip_bound:
                        raise ValueError("truncated FastLZ match")
                    code = src[ip]
                    ip += 1
                    length += code
                    if code != 255:
                        break
            if ip >= ip_limit:
                raise ValueError("truncated FastLZ match distance")
            code = src[ip]
            ip += 1
            ofs += code
            length += 3
            ref = len(out) - ofs - 1
            if code == 255 and ofs == (31 << 8):
                if ip >= ip_bound:
                    raise ValueError("truncated FastLZ far match")
                ofs = (src[ip] << 8) + src[ip + 1]
                ip += 2
                ref = len(out) - ofs - MAX_L2_DISTANCE - 1
            if ref < 0 or len(out) + length > maxout:
                raise ValueError("FastLZ match out of range")
            _extend_match(out, ref, length)
        else:
            ctrl += 1
            if ip + ctrl > ip_limit or len(out) + ctrl > maxout:
                raise ValueError("truncated FastLZ literals")
            out.extend(src[ip:ip + ctrl])
            ip += ctrl
        if ip >= ip_limit:
            break
        ctrl = src[ip]
        ip += 1
    return bytes(out)
