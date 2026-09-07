# Reverse-engineering procedure

This is the working method used to replace VDDK’s NBD path with Python.
Protocol details live in `docs/nfc_auth.md`, `docs/nfc_open.md`,
`docs/nfc_read.md`, and `docs/nfc_write.md`. The capture tool is
described in `docs/ssl_hook.md`.
This file is the **sequence of steps**, including dead ends, so later
NFC work can follow the same loop instead of rediscovering it.

Scope so far: `VixDiskLib_ConnectEx` + `VixDiskLib_Open` +
`VixDiskLib_Read` + `VixDiskLib_Write` against lab vCenter 8.0.1 /
ESXi 8, transports `nbd` and `nbdssl`. Driver: `tests/integration/` (the
session-scoped `lab` fixture creates a temporary empty VM with a 10 GiB
disk and destroys it when the pytest session ends).

Rule from `AGENTS.md`: reuse pyVmomi for every public VIM operation.
Only reimplement what pyVmomi does not expose.

## Loop

Each unknown stage (ticket SOAP, authd, NFC binary) went through:

1. **Name it** from VDDK logs and `strings` on the bundled libraries.
2. **See it** on the wire (or prove that tcpdump cannot).
3. **Replay** the smallest working subset in Python against the lab.
4. **Write** findings into a protocol doc and keep the hook out of the
   library path.

Do not skip (2). Log lines such as `SESSIONID` or `useSSL=0` named the
wrong wire command until the intercept existed.

## Lab and artifacts

| Item                    | Where / value                                                        |
| ----------------------- | -------------------------------------------------------------------- |
| VDDK 8.0.2              | `.vddk/` (`libvixDiskLib`, `libvddkVimAccess`, `libvim-types`)       |
| pyVmomi                 | `.venv`                                                              |
| Known-good VDDK client  | `tests/integration/test_vddk.py` / `tests/integration/vixdisklib.py` |
| Verbose NFC logs        | `vixDiskLib.nfc.LogLevel=4` in a temp VDDK config                    |
| ctypes Open+Read driver | `/tmp/vddk_open_trace.py` (not in the library)                       |
| SSL / `write` hook      | `/tmp/sslhook.c` → `/tmp/sslhook.so`                                 |

Always set `LD_LIBRARY_PATH` to `.vddk/` so VDDK uses its own
`libssl.so.3`. Unset `LD_PRELOAD` before running the Python replacement;
a leftover `write` hook will crash pyVmomi’s TLS.

## Step 1 — Map the public VDDK calls

`tests/integration/test_vddk.py` is the specification of what
“success” looks like: login, open the temporary VM’s VMDK, write a
known pattern, read it back.

Turn on VDDK verbose logging around `InitEx` / `ConnectEx` / `Open`. The
logs split the work that the Python API hides:

- `ConnectEx` → VIM login only.
- `Open` → NFC ticket, authd, NFC handshake, AIO open, then I/O.
- `transport_modes=nbd` → URL form `vpxa-nfc://[ds] path.vmdk@esxi:902`.
- `snapshot_ref` does not appear on the ticket SOAP call.

That mapping is the table at the top of `docs/nfc_auth.md`. It tells you
which stage to reverse next and which arguments belong there (VM moref
on the ticket, VMDK path on NFC `OPEN_FILE`).

## Step 2 — Strings and pyVmomi before any capture

`strings -a` on `.vddk/*.so` produced candidate tokens before a single
packet was decoded:

- SOAP: `NfcService`, `NfcGetVmFiles`, `nfcService`, `ha-nfc`,
  `HostServiceTicket`.
- authd: `SESSION`, `BANNER`, `THUMBPRINT_SHA2`, `PROXY`, `USER`,
  `PASS`, `SSL Required`.
- NFC: `NFC_HANDSHAKE`, `NFC_CONNECTION_DATA`, `NFC_AIO_MSG_*`,
  `NFC_DISK`.

Then check whether pyVmomi already has the type:

```python
from pyVmomi import vim
hasattr(vim, "NfcService")   # False
hasattr(vim, "HostServiceTicket")  # True
```

`ServiceManager.QueryServiceList` on the live vCenter does **not** list
NFC. `GET /sdk/nfcServiceVersions.xml` does (`urn:nfc` 7.0.3.2). The
moref is hardcoded in VDDK (`nfcService` on vCenter, `ha-nfc` on ESXi).

Anything public (`SmartConnect`, `vim.VirtualMachine`,
`HostServiceTicket`) stays in pyVmomi. Missing managed types are
registered with `CreateManagedType` on the same SOAP stub so cookies
and serialization are not reimplemented.

## Step 3 — Confirm tcpdump is the wrong tool for TLS stages

tcpdump on 443 and 902 shows TLS records only. That is enough to prove
“something talks to vCenter then to ESXi:902”, and not enough for SOAP
bodies, authd lines, or NFC headers.

VDDK logs name functions and AIO `opId` / `type` / `size`. They do not
give magic numbers, path placement, or command spacing (`BANNER \r\n`).

An ESXi-impersonating service was considered (`AGENTS.md`) and not
needed: the lab answers VDDK, so capturing the real client is simpler
than simulating the server.

## Step 4 — Interpose OpenSSL (authd and SOAP)

VDDK 8.0.2 still calls `SSL_write` / `SSL_read`. A small `LD_PRELOAD`
library logs those buffers as hex, tagged with the `SSL *` pointer.

Run a minimal ctypes program (`InitEx`, `ConnectEx`, `Open`, `Read`)
under:

```bash
export LD_LIBRARY_PATH=…/.vddk
export LD_PRELOAD=/tmp/sslhook.so
export SSLHOOK_LOG=/tmp/sslhook-open.log
python /tmp/vddk_open_trace.py
```

Parse offline:

1. Concatenate adjacent same-direction records (authd `SSL_read` is
   often one byte).
2. Split by `SSL *`. vCenter HTTPS contains `POST /sdk` and SOAP.
   ESXi:902 contains `SESSION` / `PROXY`.
3. An early hook without the pointer mixed both streams; always tag.

The vCenter stream identified the ticket as `NfcGetVmFiles` with moref
`nfcService` and `xmlns="urn:vim25"` (not a guess from strings alone).
The ESXi stream gave the authd command order, including the trailing
space on `BANNER` and `THUMBPRINT_SHA2 PlainText`.

Hook implementation notes: `docs/ssl_hook.md`.

## Step 5 — Probe SOAP, then replay only what VDDK sends

With a SmartConnect session, raw SOAP posts were used to learn
parameter names and which moref vCenter accepts:

- `ha-nfc` on vCenter → `ManagedObjectNotFound`.
- `NfcGetServerNfcLibVersion` without `hostForAccess` → invalid
  argument; with a host moref → `11`.
- `NfcGetVmFiles(vm)` → `HostServiceTicket` (VDDK read-only Open).
- `NfcRandomAccessOpenReadonly(vm, diskDeviceKey, host)` → same ticket
  type, disk-scoped read.
- `NfcRandomAccessOpenDisk(vm, diskDeviceKey, host)` → writable
  ticket. `GetVmFiles` plus `OPEN_FILE` flags `0x1a` fails with
  `VIX_E_FILE_READ_ONLY` (`0x0b`).

The replacement registers those methods and calls them through pyVmomi.
It does not ship a hand-rolled SOAP client for login or tickets.

## Step 6 — Probe authd; record dead ends

Plaintext banner (`220 … SSL Required`), then `ssl.wrap_socket`.
Commands before TLS drop the connection.

vCenter UID/password are **not** sent to port 902. Attempts that failed
and must not be retried for this ticket type:

| Attempt                               | Result                                |
| ------------------------------------- | ------------------------------------- |
| `USER` / `PASS` (vCenter account)     | `530 Login incorrect`                 |
| `USER` / `PASS` with `sessionId`      | `530 Login incorrect`                 |
| `SESSIONID <sessionId>`               | `530 Please login with USER and PASS` |
| `CONNECT_VPXA` after TLS              | `530 Please login with USER and PASS` |
| Wait for a reply after `SESSION`      | Hang until `BANNER` / `PROXY` follow  |
| `THUMBPRINT_SHA2` with SHA-1 digest   | `501 Invalid arguments`               |

The working sequence is in `docs/nfc_auth.md`. `useSSL=0` in the VDDK
log means skip a **second** NFCSSL wrap, not skip TLS on 902.

Replay: `openvixdisklib/nfc_auth.py` /
`tests/integration/test_nfc_auth.py`. Stop at `200 Connect`.

## Step 7 — NFC binary: extend the hook to `write` / `read`

After `PROXY`, `SSL_write` on the ESXi `SSL *` goes silent. VDDK logs
`useSSL=0` / “plain-text connection is deprecated” and then NFC
function names. The bytes are `write(SSL_get_fd(ssl), …)` / `read` on
peer port 902.

The hook was extended to those syscalls, filtered with `getpeername`
port 902, and mutex-locked (VDDK is multi-threaded). Skip TLS records
(`16 03` / `17 03`) left over from the authd phase.

Correlate each frame with the verbose log line that has the same
`type` and `size` (`NfcAioSendMessage: opId = … type = … size = …`).
Name the types from the consecutive `NFC_AIO_MSG_*` string table in
`libvixDiskLib.so`. Lengths 4 and 7 on the connection-data message are
the ASCII strings `vddk` and `nbdmode` sent in the next two writes.

Classic NFC uses a 264-byte padded struct; AIO uses a 16-byte header
(`magic 0xA100DA7A`) plus payload; path / DDB key / sector data are
extra writes not included in `size`.

## Step 8 — Replay the smallest subset, then compare to VDDK

Python must **dup the authd fd** and send NFC as raw TCP.
`SSLSocket.send` would encrypt; `unwrap()` would `SSL_shutdown`. VDDK
does neither.

`openvixdisklib/nfc_open.py` replays handshake + AIO `OPEN_SESSION` /
sockopts / resource pool / `OPEN_FILE`. VDDK’s extra `DDB_GET` keys
were omitted once a file handle was enough to read. Proof of open:
`tests/integration/test_nfc_open.py`.

Do not copy every VDDK message. Copy what the server requires for the
Python API you are replacing.

## Step 9 — Vary `VixDiskLib_Read` until IO fields stop moving

A single-sector read is not enough to decode `NFC_AIO_MSG_IO`. Drive
VDDK with several `(startSector, numSectors)` pairs in one Open
(including `n=128` = 64 KiB and `n=129`) under the `write`/`read` hook.

What that comparison showed:

- Wire units are bytes (`offset = start * 512`, `length = n * 512`).
- Request size stays 44; data is extra after the payload.
- VDDK sends **one** request even when `length > 65536`. The server
  replies with several type-7 messages that share `opId`, each with a
  chunk length at payload offset 32 (max 65536).
- Treating offset 36 as `NFC_DISK` (`2`) was a 1-sector coincidence;
  VDDK repeats the byte length there.
- Zeros on the wire are real transferred zeros, not a sparse skip.

Replay: `NfcDisk.read` places fragments at the byte offset in the
reply (they may arrive out of order) until `length` bytes are filled.
Proof: `tests/integration/test_nfc_read_write.py` writes a known pattern
(including a 129-sector read that must assemble two fragments) and
checks the bytes that came back.

## Step 10 — Writes from the same IO message

`VixDiskLib_Write` uses the same 44-byte `NFC_AIO_MSG_IO` layout as
read. The direction field at offset 8 is `0` instead of `1`, and the
sector bytes are sent after the payload (like the path on
`OPEN_FILE`). Writable `OPEN_FILE` flags are `0x1a` (the captured
read-only flags `0x1e` with bit `0x04` cleared, matching
`VIXDISKLIB_FLAG_OPEN_READ_ONLY` in `.vddk/vixDiskLib.h`).

Writable `OPEN_FILE` still failed with `VIX_E_FILE_READ_ONLY` until
the ticket switched from `NfcGetVmFiles` to `NfcRandomAccessOpenDisk`
(`libvim-types.so`: vmodl `randomAccessOpen` ↔ WSDL
`NfcRandomAccessOpenDisk`). Integration tests create a temporary empty
10 GiB VM for the run so writes cannot land on other lab disks.

The Python client splits writes larger than 64 KiB into AIO chunks and
keeps up to four in flight (`NfcAioInitSession` buffer count). Header
and extra go in one `sendall`, with `TCP_NODELAY`. Details:
`docs/nfc_write.md`. Proof: write then read in
`tests/integration/test_nfc_read_write.py` and the VDDK cross-check in
`tests/integration/test_crosscheck.py`.

## Step 11 — NBDSSL: second TLS after `PROXY vpxa-nfcssl`

VDDK strings name `nbdssl`, `vpxa-nfcssl://`, and `ha-nfcssl`. The NFC
ticket SOAP call is unchanged (`service` stays `vpxa-nfc`). Transport is
an authd/client choice:

1. Same `SESSION` / `BANNER` / `THUMBPRINT_SHA2 PlainText` as NBD.
2. `PROXY vpxa-nfcssl` → `200 Connect ha-nfcssl`.
3. A new TLS handshake on the **same TCP connection** (not TLS-in-TLS
   and not `THUMBPRINT_SHA2 <sha256>`). The colon thumbprint is still
   `501 Invalid arguments`.
4. Classic NFC handshake type 43 still sends ASCII `PlainText`. I/O
   framing is unchanged.

Replay: `connect_authd(..., nfc_ssl=True)` plus
`nfc_open.wrap_nfcssl_socket`. Sending NFC on the first authd
`SSLSocket` after `ha-nfcssl` fails (`BAD_RECORD_TYPE`); sending
plaintext NFC on the dup'd fd gets EOF. Dup + `wrap_socket` is the
working subset. Proof: `tests/integration/test_nfc_open.py` (`nbdssl`)
and `test_openvixdisklib.py` with `transport_modes="nbdssl"`.

Native `VixDiskLib_ConnectEx(..., transport_modes="nbdssl")` through
the old `VixDiskLibConnectParams` ctypes struct can still log nbdssl
and then fall back to `vpxa-nfc` / `useSSL=0`. Do not treat that log
line as a wire capture of NFCSSL.

## Step 12 — FASTLZ NBD compression

`VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ` (`1 << 5`) is an IO codec,
not an OPEN_FILE bit. Capture VDDK with that flag (NBD + the port-902
`write`/`read` hook):

- Handshake stays `PlainText`. `OPEN_FILE` flags stay `0x1a` / `0x1e`.
- VDDK’s URL is `FASTLZ-vpxa-nfc://…`; `PROXY` is still `vpxa-nfc`.
- IO opcode `uint64` = direction in the low half, compression type in
  the high half (`2` = FastLZ). Offset 32 is uncompressed length;
  offset 36 is compressed extra size when type is 2.
- Incompressible chunks fall back to type `0` and raw extra.
- 64 KiB chunks use FastLZ level 2; smaller chunks use level 1.

Replay: pip `pyfastlz` via `openvixdisklib/fastlz.py` (NFC extra is
raw FastLZ, without the wrapper's 4-byte length prefix) plus `NfcDisk`
compression on each IO. Proof:
`tests/integration/test_nfc_read_write.py` (`fastlz`) and
`tests/perf/test_compare.py`.

## What to write down

After a stage works:

| Document                                | Contents                                      |
| --------------------------------------- | --------------------------------------------- |
| `docs/nfc_auth.md`                      | Ticket SOAP + authd wire format               |
| `docs/nfc_open.md`                      | Classic NFC + AIO open                        |
| `docs/nfc_read.md`                      | AIO IO / `VixDiskLib_Read`                    |
| `docs/nfc_write.md`                     | AIO IO / `VixDiskLib_Write`                   |
| `docs/ssl_hook.md`                      | Capture tool only                             |
| `docs/reverse_engineering_procedure.md` | This procedure (update when the method changes) |

Keep the hook and ctypes driver under `/tmp`. They are not part of the
replacement library.

## Next stages (same procedure)

Not yet reversed, same loop as above:

- `DDB_GET` / disk geometry, zlib/skipz compression, encrypted disks
- `NFC_DELTA_DISK`, CBT / `QueryAllocatedBlocks`
- `VixDiskLib_GetInfo` capacity
- Host-switch AIO messages
- Direct ESXi `ha-nfc` without vCenter `vpxa-nfc`
