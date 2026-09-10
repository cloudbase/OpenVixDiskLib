# SSL hook for VDDK protocol capture

VDDK’s NBD path is TLS end to end: SOAP to vCenter on 443, then authd/NFC
to ESXi on 902. Packet captures on those ports are ciphertext, so they
cannot show command names, tickets, or NFC frames.

This project used a small `LD_PRELOAD` library (`sslhook.c`, built to
`sslhook.so`) to log OpenSSL plaintext while a ctypes wrapper ran
`VixDiskLib_ConnectEx` / `VixDiskLib_Open`. The authd sequence in
`docs/nfc_auth.md` was recovered from that log, not from VDDK source.

The hook is a reverse-engineering aid. It is not part of OpenVixDiskLib.

## Why not tcpdump or VDDK logs

| Approach                         | What it shows                                      | Gap                                              |
| -------------------------------- | -------------------------------------------------- | ------------------------------------------------ |
| tcpdump on 443 / 902             | TLS records                                        | No SOAP bodies, no authd lines, no NFC frames    |
| `strace` on `write` / `send*`    | Plaintext NFC **after** PROXY (`useSSL=0`)         | TLS still opaque; `-s` truncates large extras    |
| `vixDiskLib.nfc.LogLevel=4`      | Function names, `opId` / `type` / `size`           | Not the bytes on the wire                        |
| Strings in `libvixDiskLib.so`    | Command tokens (`SESSION`, `PROXY`, `BANNER`)      | Not order, spacing, or replies                   |
| SSL hook on `SSL_write`/`read`   | Exact buffers before encrypt / after decrypt       | Must split connections and reassemble 1-byte I/O |

VDDK logs were still useful to *name* AIO message types after the hex
dump showed `type` and `size`. The hook supplied the actual framing.

## How `LD_PRELOAD` interposition works

The hook exports `SSL_write` and `SSL_read` with OpenSSL’s signatures.
When the process starts with `LD_PRELOAD=/path/sslhook.so`, the dynamic
linker binds VDDK’s calls to those symbols instead of `libssl`.

Each wrapper:

1. Resolves the real OpenSSL function with `dlsym(RTLD_NEXT, ...)`.
2. Logs the plaintext buffer.
3. Calls the real function so the session is unchanged.

```
VixDiskLib  -->  SSL_write (hook)  -->  log hex  -->  SSL_write (libssl)
VixDiskLib  <--  SSL_read  (hook)  <--  log hex  <--  SSL_read  (libssl)
```

`SSL_write` logs **before** encryption. `SSL_read` calls OpenSSL first,
then logs `n` decrypted bytes when `n > 0`.

## Implementation notes

The working copy lived under `/tmp` during capture (`/tmp/sslhook.c`).
Behavior that mattered for parsing:

- Log path from `SSLHOOK_LOG`, default `/tmp/sslhook-open.log`.
- Unbuffered writes (`_IONBF`) so a crash still leaves a complete file.
- Each record tagged with the `SSL *` pointer so vCenter HTTPS and
  ESXi:902 are separable. An earlier version omitted the pointer and
  mixed both streams into one timeline.
- Payload stored as hex, not mixed ASCII, so binary NFC frames stay
  unambiguous.

Record layout:

```
==== W 0x7f8a1234 46 ====
53455353494f4e2035326364656263352d...0d0a
```

| Field   | Meaning                                              |
| ------- | ---------------------------------------------------- |
| `W`/`R` | Write (plaintext to encrypt) or read (decrypted)     |
| `%p`    | `SSL *` for this socket                              |
| length  | Byte count of this OpenSSL call                      |
| hex     | Buffer contents                                      |

`SSL_read` is often **one byte per call**. A 220 banner is therefore
dozens of `R 1` records. Adjacent records with the same `SSL *` and
direction must be concatenated before parsing lines or NFC headers.

OpenSSL 3 also has `SSL_write_ex` / `SSL_read_ex`. This VDDK 8.0.2
build still used `SSL_write` / `SSL_read`, so those two symbols were
enough. If a later library switches APIs, the hook would need matching
wrappers.

## How it was used for authd

A minimal ctypes program loaded `libvixDiskLib.so`, called
`VixDiskLib_InitEx`, `ConnectEx` (UID to vCenter, `nbd`), and `Open` on
the lab VMDK. The process was started as:

```bash
export LD_LIBRARY_PATH=/home/ubuntu/workspace/vmware_nbd_tests/.vddk
export LD_PRELOAD=/tmp/sslhook.so
export SSLHOOK_LOG=/tmp/sslhook-open.log
python /tmp/vddk_open_trace.py
```

`LD_LIBRARY_PATH` is required so VDDK uses its bundled `libssl.so.3`.
`LD_PRELOAD` still interposes that copy.

After the run, records were grouped by `SSL *`. The ESXi connection is
the one whose writes contain `SESSION ` and `PROXY `. Concatenating
that stream after the TLS handshake produced:

```
C -> SESSION <sessionId>\r\n
C -> BANNER \r\n
S -> 220 VMware Authentication Daemon Version 1.10: ...\r\n
C -> THUMBPRINT_SHA2 PlainText\r\n
S -> 200 <SHA-256 thumbprint>\r\n
C -> PROXY vpxa-nfc\r\n
S -> 200 Connect ha-nfc\r\n
```

The same log also showed the SOAP `NfcGetVmFiles` body on the vCenter
`SSL *` (`xmlns="urn:vim25"`, moref `nfcService`). That is how the
ticket call was identified as `NfcGetVmFiles` rather than guessing
from `libvim-types` strings alone.

Details that only the hex dump made obvious:

- `BANNER` includes a trailing space (`BANNER \r\n`).
- `THUMBPRINT_SHA2` argument is the literal `PlainText`, not the
  ticket SHA-1 thumbprint.
- `SESSION` has no reply; waiting for a line after it looks like a hang.
- Ticket `sessionId` is the UUID string on the `SESSION` line.

Those facts are written up in `docs/nfc_auth.md`. OpenVixDiskLib
(`openvixdisklib/nfc_auth.py`) replays this sequence; it does not use
the hook.

After `200 Connect`, NFC is **not** on `SSL_write`. VDDK uses
`write`/`read` on `SSL_get_fd` (`useSSL=0`). A later hook that also
interposed those syscalls, filtered to peer port 902, recovered the
264-byte handshake and AIO frames in `docs/nfc_open.md`. TLS record
bytes (`16 03` / `17 03`) on that fd are the authd phase and must be
skipped.

## Limits

- The hook sees every OpenSSL client in the process (VDDK and, if the
  same interpreter is used, anything else linked to OpenSSL). Filter by
  `SSL *`.
- It does not decode TLS handshakes, certificates, or SOAP envelopes;
  that is done offline on the hex log.
- It must not ship in OpenVixDiskLib. Keep it out of
  the library path used by `openvixdisklib/nfc_auth.py`.
