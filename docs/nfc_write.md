# VDDK NFC disk write

This document records how `NfcDisk.write` in
`openvixdisklib/nfc_open.py` implements `VixDiskLib_Write` over NFC AIO.
The request layout matches the captured `VixDiskLib_Read` IO message in
`docs/nfc_read.md` (write requests use the same fragment fields as
read replies). Open flags and the IO direction field were taken
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
(`magic 0xA100DA7A`, type 7, size 44, one `opId` per
`VixDiskLib_Write`):

| Offset | Type     | `Write(start, n)`                                         |
| ------ | -------- | --------------------------------------------------------- |
| 0      | `uint64` | File handle from `OPEN_FILE`                              |
| 8      | `uint64` | `0` (`NFC_AIO_IO_WRITE`; read uses `1`)                   |
| 16     | `uint64` | Byte offset of the **whole** write                        |
| 24     | `uint32` | Total byte length                                         |
| 28     | `uint32` | Byte offset of this fragment (`0`, `65536`, …)            |
| 32     | `uint32` | This fragment’s uncompressed length                       |
| 36     | `uint32` | Extra size (same as 32, or FastLZ packed size)            |
| 40     | `uint32` | `0`                                                       |

This is the same 44-byte layout as a **read reply** fragment
(`docs/nfc_read.md`): writes stream request fragments, reads stream
reply fragments. A single-fragment write (≤ 64 KiB) still looks like a
`uint64` length at offset 24 because the fragment offset is 0.

FASTLZ writes use the same header. The opcode `uint64` high half is
`2`, offset 36 is the compressed size, and FastLZ bytes follow instead
of raw sectors. If compression does not shrink the fragment, VDDK
sends type `0` and raw extra. Each fragment is compressed on its own;
a 32 MiB FastLZ write is 512 independent FastLZ extras, not one.

Sector bytes follow the 44-byte payload and are **not** counted in AIO
`size`. The replacement sends header + payload + extra in one
`sendall` and sets `TCP_NODELAY` on the NFC socket so a small FastLZ
extra is not delayed behind Nagle / delayed ACK. Captured VDDK often
uses two `write()`s (`60` then `65536`) for a 64 KiB fragment and
coalesces only a 512-byte tail (`572` = 16 + 44 + 512).

A 1-sector VDDK write was 572 bytes on the wire: 16 + 44 + 512.

## Fragments and the single reply

`NfcAioInitSession` advertises a 64 KiB buffer. Extra per type-7
message is at most that size. VDDK does **not** issue a new `opId` per
chunk, and it does **not** coalesce separate `VixDiskLib_Write` calls
(eight 8 KiB writes stayed eight IOs). One public write becomes N
client type-7 messages with the **same** `opId`, then **one** 44-byte
reply (no extra) after the last fragment:

```
C: type=7 opId=14 size=44  total=66048 dest=0     chunk=65536  + 65536 data
C: type=7 opId=14 size=44  total=66048 dest=65536 chunk=512    + 512 data
S: type=7 opId=14 size=44  total=66048 dest=0     chunk=66048
```

A 32 MiB write is 512 client fragments and one ACK. The Python client
does the same. An earlier attempt that used a distinct `opId` per
64 KiB chunk and a sliding window of 4–512 outstanding IOs was waiting
for one reply per chunk; raising the window did not match VDDK
throughput because VDDK pays one RTT per `Write`, not per fragment.

`NfcAioFlushCoalescedWrites` is server-side (`nfcAioServer.c`), not a
client merge of API writes. OPEN_SESSION is 16 zero bytes both ways, so
the logged AIO buffer count of 4 is a VDDK client default
(`vixDiskLib.nfcAio.Session.BufCount`), not a server cap.

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
