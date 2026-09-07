# VDDK NFC disk read

This document records how VMware VDDK reads VMDK sectors over NBD/NFC
after the open in `docs/nfc_open.md`, and how `NfcDisk.read` in
`openvixdisklib/nfc_open.py` reproduces `VixDiskLib_Read`. Capture
method: `docs/reverse_engineering_procedure.md`.

## Mapping from VDDK

`VixDiskLib_Read(handle, startSector, numSectors, buf)` becomes one
`NFC_AIO_MSG_IO` (type 7) on the NFC socket. Units on the wire are
**bytes**, not sectors:

```
offset = startSector * sectorSize
length = numSectors * sectorSize
```

`sectorSize` is 512 from the `OPEN_FILE` reply on this lab disk.

| VDDK call                         | Wire effect                                      |
| --------------------------------- | ------------------------------------------------ |
| `VixDiskLib_Read(h, 0, 1, buf)`   | IO offset 0, length 512, one 512-byte fragment   |
| `VixDiskLib_Read(h, 1, 1, buf)`   | IO offset 512, length 512                        |
| `VixDiskLib_Read(h, 0, 128, buf)` | IO length 65536 (AIO buffer size), one fragment  |
| `VixDiskLib_Read(h, 0, 129, buf)` | One request of 66048; **two** reply fragments    |

VDDK does **not** split a `Read` larger than 64 KiB into multiple
requests. The client sends one AIO message; the server answers with
one or more same-`opId` replies, each carrying at most
`NFC_AIO_BUFFER_SIZE` (65536) data bytes. `NfcAioInitSession` logged
that buffer size and count 4 during open.

Sparse regions are still transferred as zeros. A read of 8 sectors at
LBA 8 on this disk was 4096 zero bytes on the wire, not a skip.

## Request (44 bytes)

Little-endian, after the usual 16-byte AIO header
(`magic 0xA100DA7A`, type 7, size 44, monotonic `opId`):

| Offset | Type     | VDDK `Read(start, n)`                                      |
| ------ | -------- | ---------------------------------------------------------- |
| 0      | `uint64` | File handle from `OPEN_FILE`                               |
| 8      | `uint64` | Direction in low 32 bits; FastLZ type `2` in high 32 bits  |
| 16     | `uint64` | Byte offset                                                |
| 24     | `uint64` | Byte length                                                |
| 32     | `uint32` | Byte length (same value)                                   |
| 36     | `uint32` | Byte length, or compressed extra size when type is FastLZ  |
| 40     | `uint32` | `0`                                                        |

An earlier guess that offset 36 was `NFC_DISK` (`2`) was wrong: a
1-sector VDDK read puts `512` in both `uint32` length fields. A Python
read that sent `(512, 2, 0)` still worked for one sector; the
replacement now matches VDDK.

`VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ` does not change OPEN_FILE
flags. The IO opcode at offset 8 is a `uint64`: low 32 bits are still
`0`/`1` (write/read), high 32 bits are the NFC compression type
(`2` = FastLZ). OPEN still uses handshake `PlainText`.

| Open flag / wire                         | Request extra                         | Reply extra                                      |
| ---------------------------------------- | ------------------------------------- | ------------------------------------------------ |
| No compression flag                      | Raw `length` bytes on write           | Raw fragment at offset 32                        |
| FASTLZ, data that shrinks                | FastLZ bytes; offset 36 = packed size | Opcode type `2`; extra is FastLZ of offset 32    |
| FASTLZ, incompressible                   | Raw bytes; opcode type `0`            | Opcode type `0`; extra is raw                    |

Reads with FASTLZ always *request* type `2`. The server may answer type
`2` or fall back to type `0`. Decompress into the uncompressed fragment
length at offset 32 and copy to the dest at offset 28.

64 KiB chunks use FastLZ level 2 (first byte has bit 5 set). Smaller
chunks use level 1. VDDK’s URL form is `FASTLZ-vpxa-nfc://…`; authd
`PROXY` is unchanged.

## Reply

Each fragment is: 16-byte AIO header (same `type` and `opId`) + 44-byte
payload + `chunkLength` data bytes.

Reply payload (handle is zeroed; lengths describe this fragment):

| Offset | Type     | Meaning                                         |
| ------ | -------- | ----------------------------------------------- |
| 0      | `uint64` | `0`                                             |
| 8      | `uint64` | `1` (read)                                      |
| 16     | `uint64` | Byte offset of the **request**                  |
| 24     | `uint32` | Total request length                            |
| 28     | `uint32` | Byte offset of this fragment (`0`, `65536`, …)  |
| 32     | `uint32` | This fragment’s byte length                     |
| 36     | `uint32` | Same as offset 32                               |
| 40     | `uint32` | `0`                                             |

When there is a single fragment, offsets 24–31 look like a `uint64`
length (the fragment offset is 0). The 129-sector capture shows why
they are two `uint32`s: fragment 0 has `(66048, 0)` then chunk 65536;
fragment 1 has `(66048, 65536)` then chunk 512. `0x00010000` at offset
28 is the byte offset, not a 0-based index.

Read loop: receive fragments with that `opId` until the concatenated
data length equals the request. Use the `uint32` at payload offset 32
as the extra-data size for that fragment, and copy it to the byte
offset at payload offset 28 — fragments are not always delivered in
order. Do not treat extra data as part of AIO `size` (that field stays
44).

129-sector example (one client request, two server fragments):

```
C: type=7 opId=18 size=44  offset=0 length=66048
S: type=7 opId=18 size=44  dest=0     chunk=65536  + 65536 data
S: type=7 opId=18 size=44  dest=65536 chunk=512    + 512 data
```

## Lab check

Integration tests create an empty 10 GiB thin disk, write a repeating
pattern at each captured range (including 129 sectors), and read it
back. An unwritten region is zeros.

Writes use the same 44-byte IO payload with opcode `2`; see
`docs/nfc_write.md`.

## Python replacement

`NfcDisk.read(start_sector, num_sectors)` in
`openvixdisklib/nfc_open.py`. Run:

```bash
.venv/bin/pytest tests/integration/test_nfc_read_write.py
```

The integration test writes and then reads the captured VDDK ranges
(including a 129-sector transfer that must assemble two read
fragments).

## What is still VDDK-only

- zlib and skipz NBD compression flags
- `VixDiskLib_ReadAsync` (same IO messages, different client threading)
- `VixDiskLib_QueryAllocatedBlocks` / allocation bitmaps
- `VixDiskLib_GetInfo` capacity (not required to read a known range)
