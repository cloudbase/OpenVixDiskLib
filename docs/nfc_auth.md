# VDDK NFC authentication

This document records how VMware VDDK authenticates for NBD/NFC disk
access, and how the Python replacement in `openvixdisklib/nfc_auth.py`
reproduces that path. Findings come from VDDK 8.0.2 libraries
(`libvixDiskLib`, `libvddkVimAccess`, `libvim-types`), live SOAP calls
against vCenter
8.0.1, and a TLS intercept of `VixDiskLib_ConnectEx` / `VixDiskLib_Open`.
The steps used to obtain those findings are in
`docs/reverse_engineering_procedure.md`.

The goal of this stage is authentication only: a logged-in VIM session
plus an authd TLS socket that has completed `200 Connect`. Opening a
VMDK and reading sectors is `docs/nfc_open.md`.

## Mapping from VDDK

The VDDK wrapper in `tests/integration/vixdisklib.py` calls
`VixDiskLib_ConnectEx` with UID credentials and `VixDiskLib_Open` on a
datastore path. VDDK does **not** send the vCenter username and
password to ESXi port 902. It:

1. Logs into vCenter over HTTPS 443 (SOAP / `urn:vim25`).
2. Asks vCenter for a one-time NFC ticket.
3. Connects to the ESXi **authd** daemon on TCP 902, upgrades to TLS,
   and presents that ticket.

| VDDK call                         | What actually happens                                      |
| --------------------------------- | ---------------------------------------------------------- |
| `VixDiskLib_InitEx`               | Load plugins, SSL, logging                                 |
| `VixDiskLib_ConnectEx`            | SOAP `SessionManager.Login` to vCenter                     |
| `VixDiskLib_Open` (read-only)     | `NfcGetVmFiles` ticket, then authd handshake, then NFC I/O |
| `VixDiskLib_Open` (read-write)    | `NfcRandomAccessOpenDisk` ticket (disk key + host)         |
| `transport_modes="nbd"`           | NBD over NFC (`vpxa-nfc://...@esxi:902`)                   |
| `vmxSpec=moref=vm-13098`          | VM managed object used as the ticket target                |
| `snapshot_ref`                    | Not consumed by the ticket call itself                     |
| `VIXDISKLIB_CRED_UID`             | Username/password for VIM only                             |

Lab topology used for capture:

- vCenter: `10.8.1.199` (VirtualCenter 8.0.1)
- VM: `vm-13098` on host `host-13001` (`10.8.1.250`)
- NFC service moref on vCenter: `nfcService`
- Authd: `10.8.1.250:902`

## Stage 1: VIM login

This is a public pyVmomi operation. Reuse `pyVim.connect.SmartConnect`
rather than crafting SOAP.

- Endpoint: `https://<vcenter>:443/sdk`
- Cookie: `vmware_soap_session`
- SOAPAction: `"urn:vim25/8.0.1.0"` (negotiated)

VDDK logs this as `Connected to VIM Server` / `Authenticating user` /
`Logged in!`. The Python replacement keeps that `ServiceInstance` and
its stub for the ticket call.

Direct ESXi login is the same SOAP login against hostd, but the NFC
moref and service name differ (`ha-nfc` instead of `nfcService` /
`vpxa-nfc`). The lab path is vCenter-mediated.

## Stage 2: NFC ticket

### Why this is not public pyVmomi

`vim.NfcService` is omitted from the public vim25 WSDL that pyVmomi
ships. vCenter still implements it:

- Version document: `GET /sdk/nfcServiceVersions.xml` → namespace
  `urn:nfc`, version `7.0.3.2`
- Methods also accept `urn:vim25` (that is what VDDK uses)
- Well-known moref on this vCenter: `nfcService`

`ServiceManager.QueryServiceList` does **not** list NFC. The moref is
hardcoded in VDDK as `nfcService` (vCenter) or `ha-nfc` (ESXi).

`openvixdisklib/nfc_auth.py` registers the missing type with
`pyVmomi.VmomiSupport.CreateManagedType` and invokes it on the existing
SmartConnect stub, so serialization, cookies, and `HostServiceTicket`
stay in pyVmomi.

### Methods VDDK actually calls

Intercepted SOAP for a **read-only** `VixDiskLib_Open` of a datastore
path:

```xml
<NfcGetVmFiles xmlns="urn:vim25">
  <_this type="NfcService">nfcService</_this>
  <vm type="VirtualMachine">vm-13098</vm>
</NfcGetVmFiles>
```

No disk path, snapshot, or host is in this request. The path
(`[datastore0] ...-000007.vmdk`) is used later on the NFC channel.

A `GetVmFiles` ticket is **not** writable. Opening the same path with
NFC flags `0x1a` returns AIO error `0x0b` (`VIX_E_FILE_READ_ONLY`).
Writable `ConnectEx(readOnly=FALSE)` uses a disk-scoped ticket instead.

`libvim-types.so` maps vmodl `randomAccessOpen` to WSDL
`NfcRandomAccessOpenDisk` (same arguments as the read-only sibling):

```xml
<NfcRandomAccessOpenDisk xmlns="urn:vim25">
  <_this type="NfcService">nfcService</_this>
  <vm type="VirtualMachine">vm-13098</vm>
  <diskDeviceKey>2000</diskDeviceKey>
  <hostForAccess type="HostSystem">host-13001</hostForAccess>
</NfcRandomAccessOpenDisk>
```

A disk-scoped **read** ticket also works and returns the same
`HostServiceTicket` type:

```xml
<NfcRandomAccessOpenReadonly xmlns="urn:nfc">
  <_this type="NfcService">nfcService</_this>
  <vm type="VirtualMachine">vm-13098</vm>
  <diskDeviceKey>2000</diskDeviceKey>
  <hostForAccess type="HostSystem">host-13001</hostForAccess>
</NfcRandomAccessOpenReadonly>
```

`diskDeviceKey` is `VirtualDisk.key` from `vm.config.hardware.device`
(2000 for Hard disk 1). The replacement resolves it from the datastore
path when `open` is given a VMDK rather than a key.

### Return value: `vim.HostServiceTicket`

Public pyVmomi type. Example from this lab:

| Field            | Example                                | Role                                      |
| ---------------- | -------------------------------------- | ----------------------------------------- |
| `host`           | `10.8.1.250`                           | ESXi management / NFC address             |
| `port`           | `902`                                  | authd TCP port                            |
| `sslThumbprint`  | `BE:22:58:...:76:29`                   | SHA-1 of the ESXi TLS cert                |
| `service`        | `vpxa-nfc`                             | authd `PROXY` argument                    |
| `serviceVersion` | `1.1`                                  | NFC hosted by hostd (ESX 3.0+ convention) |
| `sessionId`      | `52cdebc5-b7ee-359a-1dec-76f0bc105ac5` | One-time authd `SESSION` token            |

Tickets are single-use. Calling `GetVmFiles` twice issues two tickets;
only the one presented to authd is consumed.

### Other NfcService methods seen in VDDK

WSDL names are prefixed with `Nfc`. The vmodl names (from
`libvim-types.so`) include:

| WSDL name                     | Parameters (observed / from C++)       | Notes                          |
| ----------------------------- | -------------------------------------- | ------------------------------ |
| `NfcGetVmFiles`               | `vm`                                   | VDDK read-only Open path       |
| `NfcRandomAccessOpenReadonly` | `vm`, `diskDeviceKey`, `hostForAccess` | Disk-scoped read ticket        |
| `NfcRandomAccessOpenDisk`     | `vm`, `diskDeviceKey`, `hostForAccess` | Disk-scoped read-write ticket  |
| `NfcGetServerNfcLibVersion`   | `hostForAccess`                        | Lab returned `11`              |
| `NfcFileManagement`           | requires `ds` (datastore)              | File copy, not NBD             |
| `NfcSystemManagement`         | host moref                             | Not used for disk open         |

`NfcGetServerNfcLibVersion` without `hostForAccess` fails with
`A specified parameter was not correct: hostForAccess`. Using moref
`ha-nfc` on vCenter fails with `ManagedObjectNotFound`; `nfcService`
is the correct vCenter object.

## Stage 3: authd handshake (TCP 902)

authd is the VMware Authentication Daemon. Plaintext banner from ESXi
8:

```
220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , VMXARGS supported, NFCSSL supported/t, SHA256 supported
```

SSL is required. Sending commands before `wrap_socket` closes the
connection. After TLS there is **no** `USER` / `PASS` when the client
holds a vCenter NFC ticket.

### Sequence captured from VDDK

VDDK log line immediately before the socket:

```
Using proxy/session authentication, sessionId=..., useSSL=0
Plain-text connection is deprecated; use SSL to connect to NFC server
```

`useSSL=0` does **not** mean skip TLS on 902. It means skip a second
NFCSSL wrap after authd TLS (`THUMBPRINT_SHA2 PlainText`). The
management channel is still TLS.

Intercepted writes/reads after the TLS handshake:

```
C -> SESSION <sessionId>\r\n
C -> BANNER \r\n
S -> 220 VMware Authentication Daemon Version 1.10: ...\r\n
C -> THUMBPRINT_SHA2 PlainText\r\n
S -> 200 <SHA-256 thumbprint with colons>\r\n
C -> PROXY vpxa-nfc\r\n
S -> 200 Connect ha-nfc\r\n
```

Notes:

- `SESSION` does not get a reply of its own. Waiting for a line after
  `SESSION` looks like a hang.
- `BANNER` is the 7-byte command `BANNER` plus a trailing space. That
  space is part of the token; authd strips spaces when matching some
  commands, so `THUMBPRINT_SHA2 <colon-thumbprint>` is parsed as one
  token and returns `501 Invalid arguments`. `PlainText` has no extra
  spaces/colons and is the argument VDDK sends.
- `PROXY` uses `ticket.service` (`vpxa-nfc` via vCenter). The success
  line names the host-side NFC endpoint (`ha-nfc`).
- After `200 Connect`, the socket speaks binary NFC (not documented
  here).

### Commands that are not used for this ticket type

authd also implements FTP-style `USER` / `PASS` (and `XPAS`). Those
are for local ESXi credentials. With a vCenter ticket:

| Attempt                                      | Result                                  |
| -------------------------------------------- | --------------------------------------- |
| `USER` / `PASS` (vCenter account)            | `530 Login incorrect`                   |
| `USER *` / `PASS <sessionId>`                | `530 Login incorrect`                   |
| `USER <sessionId>` / `PASS <sessionId>`      | `530 Login incorrect`                   |
| `SESSIONID <sessionId>`                      | `530 Please login with USER and PASS`   |
| `CONNECT_VPXA <sessionId>` (after TLS)       | `530 Please login with USER and PASS`   |
| `SESSION <sessionId>` then wait for a reply  | No line until `BANNER` / `PROXY` follow |

`THUMBPRINT` / `THUMBPRINT_SHA2` with the SHA-1 ticket thumbprint as
argument is not what VDDK sends. The SHA-1 value is for verifying the
TLS certificate, not for the `THUMBPRINT_SHA2` command.

## Python replacement

| Piece                | Module                                   | Reuses pyVmomi?                    |
| -------------------- | ---------------------------------------- | ---------------------------------- |
| VIM login            | `openvixdisklib.nfc_auth.connect_vim`    | Yes — `SmartConnect`               |
| VM / host lookup     | `vim.VirtualMachine`                     | Yes                                |
| `HostServiceTicket`  | return type of ticket call               | Yes — public data object           |
| NFC ticket           | `openvixdisklib.nfc_auth.get_nfc_ticket` | Same stub; type registered locally |
| authd TLS + commands | `openvixdisklib.nfc_auth.connect_authd`  | No public API                      |
| End-to-end           | `openvixdisklib.nfc_auth.authenticate`   | `NfcAuthSession`                   |

Management SHA-1 thumbprints are read with
`openvixdisklib.nfc_auth.get_ssl_cert_thumbprint` (stdlib `ssl` and
`hashlib`; no pyOpenSSL). Integration tests call that instead of
hard-coding the lab certificate.

Run:

```bash
.venv/bin/pytest tests/integration/test_nfc_auth.py
```

The test completes VIM login and the authd handshake (`200 Connect`)
and asserts an established TLS socket on `ticket.host:ticket.port`.

## What comes after authentication

Authentication stops at `200 Connect ha-nfc`. Opening the VMDK and
reading or writing sectors is documented in `docs/nfc_open.md` and
implemented in `openvixdisklib/nfc_open.py`. The datastore path is
consumed there (and, for writes, as `diskDeviceKey` on the ticket).
