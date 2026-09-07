# VDDK NFC disk write

This document records how `NfcDisk.write` in
`openvixdisklib/nfc_open.py` implements `VixDiskLib_Write` over NFC AIO.
The request layout matches the captured `VixDiskLib_Read` IO message in
`docs/nfc_read.md`. Open flags and the IO direction field were taken
from a `strace` of VDDK 8 writing one sector to a temporary 10 GiB
disk (`docs/reverse_engineering_procedure.md`).

The public `VixDiskLib_Write` prototype is in `.vddk/vixDiskLib.h`:

```
VixError VixDiskLib_Write(VixDiskLibHandle diskHandle,
                          VixDiskLibSectorType startSector,
                          VixDiskLibSectorType numSectors,
                          const uint8 *writeBuffer);
```

`ConnectEx(..., Bool readOnly, ...)` with `readOnly=FALSE` and `Open`
without `VIXDISKLIB_FLAG_OPEN_READ_ONLY` (that flag is `1 << 2` in the
same header) is what produces the writable NFC open below. The ticket
must be `NfcRandomAccessOpenDisk` (`docs/nfc_auth.md`); flags `0x1a`
on a `NfcGetVmFiles` ticket are rejected as `VIX_E_FILE_READ_ONLY`.

## Mapping from VDDK

Units on the wire are **bytes**, as for reads:

```
offset = startSector * sectorSize
length = numSectors * sectorSize
```

| VDDK call                                   | Wire effect                                      |
| ------------------------------------------- | ------------------------------------------------ |
| Open without `VIXDISKLIB_FLAG_OPEN_READ_ONLY` | `OPEN_FILE` flags `0x1a`                       |
| Open with `VIXDISKLIB_FLAG_OPEN_READ_ONLY`  | `OPEN_FILE` flags `0x1e` (read-only)             |
| `VixDiskLib_Write(h, start, n, buf)`        | IO opcode `0`, then `n * 512` data bytes         |
| `VixDiskLib_Read(h, start, n, buf)`         | IO opcode `1`                                    |

`0x1e` vs `0x1a` is bit `0x04`, the same value as
`VIXDISKLIB_FLAG_OPEN_READ_ONLY`. Writable opens clear that bit.

VDDK also issues several `DDB_GET` queries and a type-10
`GET_FILE_INFO` (`longContentID`) before the first write. They are not
required to write or read sectors.

## Request (44 bytes + data)

Little-endian, after the usual 16-byte AIO header
(`magic 0xA100DA7A`, type 7, size 44, monotonic `opId`):

| Offset | Type     | `Write(start, n)`                                  |
| ------ | -------- | -------------------------------------------------- |
| 0      | `uint64` | File handle from `OPEN_FILE`                       |
| 8      | `uint64` | `0` (`NFC_AIO_IO_WRITE`; read uses `1`)            |
| 16     | `uint64` | Byte offset                                        |
| 24     | `uint64` | Byte length                                        |
| 32     | `uint32` | Byte length (same value)                           |
| 36     | `uint32` | Byte length (same value)                           |
| 40     | `uint32` | `0`                                                |

FASTLZ writes use the same 44-byte header. The opcode `uint64` high
half is `2`, offset 36 is the compressed size, and FastLZ bytes follow
instead of raw sectors. If compression does not shrink the chunk, VDDK
sends type `0` and raw extra (same as an uncompressed write).

Sector bytes follow the 44-byte payload and are **not** counted in AIO
`size`. VDDK sends header + payload + data in one `write()`. The
replacement does the same (`sendall` of those bytes together) and sets
`TCP_NODELAY` on the NFC socket so a small FastLZ extra is not delayed
behind Nagle / delayed ACK.

The server replies with a type-7 header and a 44-byte payload for that
`opId`. There is no extra data on the write reply (unlike reads).

A 1-sector VDDK write was 572 bytes on the wire: 16 + 44 + 512.

## Client-side split

`NfcAioInitSession` advertises a 64 KiB buffer and count 4. VDDK splits
writes larger than 64 KiB into 64 KiB chunks (VDDK programming guide)
and keeps several IOs in flight. The Python client does the same: IO
requests of at most `NFC_AIO_BUFFER_SIZE` bytes, up to
`NFC_AIO_BUFFER_COUNT` outstanding `opId`s before waiting for a reply.

## Python replacement

`NfcDisk.write(start_sector, num_sectors, data)` in
`openvixdisklib/nfc_open.py`. `open_disk(..., read_only=False)` selects
flags `0x1a`. The drop-in handle exposes the same shape as VDDK:
`connect(read_only=False)`, `open` without
`VIXDISKLIB_FLAG_OPEN_READ_ONLY`, then `write`.

Integration tests create an empty 10 GiB disk, write known patterns,
and read them back (`tests/integration/test_nfc_read_write.py`,
`tests/integration/test_openvixdisklib.py`). Cross-check tests write
with VDDK and with the replacement and read with both
(`tests/integration/test_crosscheck.py`).
