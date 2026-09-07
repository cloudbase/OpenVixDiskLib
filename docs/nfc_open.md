# VDDK NFC disk open

This document records how VMware VDDK opens a VMDK over NBD/NFC after
the authd handshake in `docs/nfc_auth.md`, and how
`openvixdisklib/nfc_open.py` reproduces that path. Findings come from
VDDK 8.0.2 verbose logs
(`vixDiskLib.nfc.LogLevel=4`) plus an `LD_PRELOAD` intercept of
`write` / `read` on the ESXi:902 file descriptor. Capture method:
`docs/reverse_engineering_procedure.md`.

Authentication is already done: VIM login, NFC ticket (`NfcGetVmFiles`
for read-only, `NfcRandomAccessOpenDisk` for write), TLS to authd,
`SESSION` / `BANNER` / `THUMBPRINT_SHA2 PlainText` / `PROXY`. This
stage starts at `200 Connect ha-nfc` (NBD) or `200 Connect ha-nfcssl`
(NBDSSL) and ends with an open file handle that can read and write
sectors. Flags `0x1a` require the writable ticket; the same flags on a
`GetVmFiles` ticket fail with `VIX_E_FILE_READ_ONLY`.

## Mapping from VDDK

| VDDK call / log                                               | Wire effect                                                |
| ------------------------------------------------------------- | ---------------------------------------------------------- |
| `VixDiskLib_Open`                                             | Ticket + authd (see `nfc_auth.md`), then this protocol     |
| `NBD_ClientOpen` `vpxa-nfc://[ds] path.vmdk@esxi:902`         | Datastore path is the NFC open argument, not the ticket    |
| `NBD_ClientOpen` `vpxa-nfcssl://…` / `useSSL=1`               | Same NFC after a second TLS handshake on the authd fd      |
| `useSSL=0`                                                    | NFC bytes are raw TCP, not `SSL_write`                     |
| `NfcProcessSessionParams` flags `0x3`                         | Classic 264-byte session messages                          |
| `SendConnectionDataMsg` payloadInfo 4 and 7                   | Client name `vddk` (4) and opId `nbdmode` (7)              |
| Server version 11                                             | Classic version message; 11 on this ESXi 8 lab             |
| `NfcAio_OpenSession`                                          | AIO framing after the classic handshake                    |
| `NfcUtil_PrintFileInfoOpenFlag` `NFC_DISK` `0x1e`             | `NFC_AIO_MSG_OPEN_FILE` (read-only)                        |
| Open without `VIXDISKLIB_FLAG_OPEN_READ_ONLY`                 | `OPEN_FILE` flags `0x1a` (read-write)                      |
| `VixDiskLib_Read` / `VixDiskLib_Write`                        | `NFC_AIO_MSG_IO` + sector bytes                            |
| `VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ`                     | IO opcode high bits `2`; extra data is FastLZ              |

`snapshot_ref` is still not on the wire. Integration tests pass the
flat VMDK created with the temporary lab VM.

## After PROXY: NBD plaintext vs NBDSSL wrap

`THUMBPRINT_SHA2 PlainText` is used for both transports. The PROXY
service name selects whether NFC gets a second TLS session.

NBD (`PROXY vpxa-nfc` → `200 Connect ha-nfc`, VDDK `useSSL=0`):

1. Authd commands stay inside the original TLS session (`SSL_write` /
   `SSL_read`).
2. After `200 Connect ha-nfc`, NFC is `write(SSL_get_fd(ssl), …)` /
   `read` on that descriptor. Those buffers are not TLS records
   (`0x17 0x03 …`).
3. An SSL hook that only interposes `SSL_write` / `SSL_read` goes
   silent after PROXY; a `write` / `read` hook on port 902 shows the
   frames.
4. Python must not use `SSLSocket.send` here: that would encrypt bytes
   the server now reads as NFC. `nfc_open.takeover_authd_socket` dups
   the fd. `unwrap()` / `SSL_shutdown` is not used.

NBDSSL (`PROXY vpxa-nfcssl` → `200 Connect ha-nfcssl`, `useSSL=1`):

1. Authd commands are the same, including `THUMBPRINT_SHA2 PlainText`.
2. After `200 Connect ha-nfcssl`, both sides abandon the authd TLS
   session. `ha-nfcssl` expects a new ClientHello on the same TCP
   connection.
3. `nfc_open.wrap_nfcssl_socket` dups the fd and
   `SSLContext.wrap_socket`s it. NFC then uses `SSLSocket.sendall` /
   `recv` (TLS application data). The classic 264-byte handshake still
   sends the ASCII body `PlainText`; that is NFC's own encoding, not
   the authd transport.

## Classic 264-byte messages

Before AIO, both peers send a **fixed 264-byte** struct, little-endian:

| Offset | Type      | Meaning                                      |
| ------ | --------- | -------------------------------------------- |
| 0      | `uint32`  | Message type                                 |
| 4      | remainder | Type-specific fields, zero-padded to 264     |

Types seen in this Open (names from `libvixDiskLib` strings matched to
the first `uint32`):

| Type | Name (inferred)        | Body                                              |
| ---- | ---------------------- | ------------------------------------------------- |
| 43   | `NFC_HANDSHAKE`        | ASCII `PlainText` at offset 4                     |
| 33   | `NFC_SESSION_PARAMS`   | zeros                                             |
| 36   | session-params reply   | `uint32` 1 at offset 16                           |
| 51   | version                | `uint32` protocol version (11) at offset 4        |
| 54   | `NFC_CONNECTION_DATA`  | `uint32` nameLen, `uint32` opIdLen                |
| 55   | session features       | `uint32` `0x3` (interruption \| switch)           |
| 52   | `NFC_AIO_SESSION_OPEN` | zeros                                             |
| 4    | `NFC_SESSION_COMPLETE` | zeros (sent on close)                             |

After type 54, VDDK writes the two connection-data payloads as **raw
strings**, not 264-byte frames: `vddk` then `nbdmode`. Lengths 4 and 7
are the `payloadInfo` values in the VDDK log.

Handshake order (client → server unless noted):

```
C: 43 PlainText
C: 33
S: 36
C: 51 version=11
S: 51 version=11
C: 54 nameLen=4 opIdLen=7
C: "vddk"
C: "nbdmode"
C: 55 features=3
C: 52
S: 52
```

Server version 11 is what this lab returned. VDDK logs that connection
info requires version ≥ 3.

## AIO framing

Once type 52 has been acknowledged, I/O uses a 16-byte header:

```
uint32 magic      # 0xA100DA7A, wire bytes 7a da 00 a1
uint32 type       # NfcAioSendMessage "type ="
uint32 size       # payload bytes that follow the header
uint32 opId       # monotonic, starting at 0
```

Then `size` bytes of payload. Variable-length extras (VMDK path, DDB
key name, read data) are **separate** `write`/`read` calls after that
payload, not counted in `size`.

The server echoes the same header (`magic`, `type`, `size`, `opId`)
and a payload of `size` bytes.

Magic mismatch is the `invalid msg hdr magic` string in VDDK. Type 1
is `NFC_AIO_MSG_ERROR`.

AIO types used for Open / Read / Close, correlated with the consecutive
`NFC_AIO_MSG_*` string table and VDDK logs:

| Type | Name                 | Payload size | Extra on the wire                             |
| ---- | -------------------- | ------------ | --------------------------------------------- |
| 2    | `OPEN_SESSION`       | 16           |                                               |
| 9    | `SET_SOCK_OPTS`      | 12           |                                               |
| 22   | `SET_RES_POOL`       | 4            |                                               |
| 4    | `OPEN_FILE`          | 60           | path string                                   |
| 11   | `DDB_GET`            | 16           | key name (VDDK only)                          |
| 7    | `IO`                 | 44           | sector bytes (read reply / write request)     |
| 5    | `CLOSE_FILE`         | 8            |                                               |
| 3    | `CLOSE_SESSION`      | 4            |                                               |

`opId` increases by one per client message. Replies reuse the request
`opId`.

VDDK Open also issues several `DDB_GET` queries (`resumeConsolidateSector`,
`isDigest`, `iofilters`, …). The server answered “key is not found”
(16 zero bytes) on this unencrypted disk. They are not required to
obtain a file handle or to read sector 0.

### OPEN_SESSION / sockopts / resource pool

VDDK sends 16 zero bytes (`OPEN_SESSION`), 12 zero bytes
(`SET_SOCK_OPTS`; server returns send/recv buffer sizes), then
`uint32` 1 (`SET_RES_POOL`, log: “Setting Resource Pool(1)”).

### OPEN_FILE

60-byte payload, little-endian:

| Offset | Type     | Value on a VDDK open                                           |
| ------ | -------- | -------------------------------------------------------------- |
| 0      | `uint32` | Path length in bytes                                           |
| 4      | `uint32` | 0                                                              |
| 8      | `uint32` | 0                                                              |
| 12     | `uint32` | 0                                                              |
| 16     | `uint32` | `2` (`NFC_DISK`)                                               |
| 20     | `uint32` | `0x0000001e` (read-only) or `0x1a` (read-write)                |
| 24     | 36 bytes | zeros                                                          |

Immediately afterwards the client writes the path, no NUL terminator
(for example `[datastore0] ovdl-test-…/ovdl-test-….vmdk`).

Reply payload (60 bytes), fields that matter:

| Offset | Type     | Meaning                         |
| ------ | -------- | ------------------------------- |
| 8      | `uint64` | File handle (opaque, per open)  |
| 16     | `uint32` | File type (`2` = `NFC_DISK`)    |
| 20     | `uint32` | Flags echoed (`0x1e` or `0x1a`) |
| 36     | `uint32` | Sector size (`512` on this VM)  |

Later AIO messages pass that handle as a `uint64`.

### IO (read / write)

Sector reads and writes are `NFC_AIO_MSG_IO` (type 7). Request layout,
read fragments, and write extras are documented in `docs/nfc_read.md`
and `docs/nfc_write.md`. `NfcDisk.read` / `NfcDisk.write` match
`VixDiskLib_Read` / `VixDiskLib_Write`.

### Close

`CLOSE_FILE` (handle as `uint64`), `CLOSE_SESSION` (`uint32` 0), then
classic type 4 `NFC_SESSION_COMPLETE`.

## Python replacement

| Piece                         | Module                                          |
| ----------------------------- | ----------------------------------------------- |
| VIM + authd                   | `openvixdisklib.nfc_auth.authenticate`          |
| Dup fd, skip TLS for NFC      | `openvixdisklib.nfc_open.takeover_authd_socket` |
| Second TLS for nbdssl         | `openvixdisklib.nfc_open.wrap_nfcssl_socket`    |
| FastLZ for NBD compression    | `openvixdisklib.fastlz`                         |
| Handshake + AIO + OPEN_FILE   | `openvixdisklib.nfc_open.open_disk`             |
| Sector read / write / close   | `openvixdisklib.nfc_open.NfcDisk`               |

Run:

```bash
.venv/bin/pytest tests/integration/test_nfc_open.py
```

The test opens the temporary lab VMDK, asserts an opaque handle and
`sector_size=512`, writes sector 0, and reads it back. Multi-sector
I/O: `docs/nfc_read.md`, `docs/nfc_write.md`, and
`tests/integration/test_nfc_read_write.py`.

## What is still VDDK-only

- `DDB_GET` / geometry / zlib and skipz compression / encryption keys
- `NFC_DELTA_DISK`, change-block tracking
- Host-switch (`NFC_AIO_SWITCH_HOST_*`)
- Direct ESXi `ha-nfc` without vCenter `vpxa-nfc`

Reads after open are in `docs/nfc_read.md`. Writes are in
`docs/nfc_write.md`.
