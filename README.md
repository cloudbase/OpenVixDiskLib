# openvixdisklib

A Python replacement for VMware VDDK's `vixDiskLib` NBD path. It reads
and writes VMDK contents over vSphere NFC without the proprietary VDDK
SDK.

VIM login and inventory use [pyVmomi](https://github.com/vmware/pyvmomi).
The NFC ticket, ESXi authd handshake, and disk I/O were reverse-engineered
from VDDK 8 NBD traffic; see `docs/`.

## Status

Implemented against vCenter 8 / ESXi 8. Default transport is `nbdssl`
(`nbd` is still available):

- `VixDiskLib_ConnectEx` (UID credentials)
- `VixDiskLib_Open` (datastore path, read-only or read-write)
- `VixDiskLib_Read`
- `VixDiskLib_Write`

Not implemented: compression open flags other than FastLZ, CBT /
allocated-block queries, disk geometry (`DDB_GET`), encrypted disks,
and direct ESXi `ha-nfc` without vCenter `vpxa-nfc`.

## Install

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .
```

## Usage

```python
from openvixdisklib import nfc_auth
from openvixdisklib import openvixdisklib as vixdisklib

handle = vixdisklib.VixDiskLibHandle(
    vixdisklib_compatibility_version="8.0")
buf = vixdisklib.get_buffer(vixdisklib.VIXDISKLIB_SECTOR_SIZE)
thumbprint = nfc_auth.get_ssl_cert_thumbprint("vcenter.example.com")

with handle.connect(
        server_name="vcenter.example.com",
        thumbprint=thumbprint,
        username="administrator@vsphere.local",
        password="secret",
        vmx_spec="moref=vm-1234",
        transport_modes="nbdssl",
        read_only=False) as conn:
    with handle.open(conn, "[datastore] vm/vm.vmdk", flags=0) as disk:
        handle.write(disk, 0, 1, buf)
        handle.read(disk, 0, 1, buf)
```

Lower-level NFC helpers live in `openvixdisklib.nfc_auth` and
`openvixdisklib.nfc_open` if you need the ticket or socket without the
VDDK-shaped handle.

## Layout

| Path                               | Role                                                   |
| ---------------------------------- | ------------------------------------------------------ |
| `openvixdisklib/openvixdisklib.py` | Drop-in handle (`connect` / `open` / `read` / `write`) |
| `openvixdisklib/nfc_auth.py`       | VIM login, NFC ticket, authd on 902                    |
| `openvixdisklib/nfc_open.py`       | Classic NFC handshake, AIO open, sector read/write     |
| `openvixdisklib/fastlz.py`         | FastLZ NFC adapter (pip `pyfastlz`)                    |
| `tests/integration/`               | Live pytest suite against a lab vCenter                |
| `tests/perf/`                      | Throughput comparison of openvixdisklib vs VDDK        |
| `tests/integration/vixdisklib.py`  | Native VDDK wrapper used only to cross-check           |
| `docs/`                            | Protocol notes and reverse-engineering steps           |

VDDK shared libraries, if present for cross-check, belong in `.vddk/`
(gitignored). They are not required to use `openvixdisklib`.

## Tests

Lab connection settings live in `.test_config.yaml` at the repo root
(gitignored). Copy:

```yaml
host: vcenter.example.com
port: 443
username: administrator@vsphere.local
password: secret
allow_untrusted: true
datacenter: Datacenter
datastore: datastore0
```

A session-scoped pytest fixture creates an empty VM with a 10 GiB thin
disk on that datastore and tears it down when the session ends. Tests
write known patterns and read them back.

```bash
tox -e integration
# or
.venv/bin/pytest tests/integration
```

Compare write/read throughput of openvixdisklib and native VDDK
(`64KiB`, 129-sector, and `32MiB` transfers):

```bash
tox -e perf
```

VDDK cross-check tests skip when `libvixDiskLib` is not loadable from
`.vddk`. `tox -e integration` sets `LD_LIBRARY_PATH` to that directory
and clears `LD_PRELOAD`. For a direct pytest run, do the same.

Lint and typecheck: `tox -e pep8`, `tox -e mypy`.

## Documentation

| Document                                | Contents                         |
| --------------------------------------- | -------------------------------- |
| `docs/nfc_auth.md`                      | Ticket SOAP and authd handshake  |
| `docs/nfc_open.md`                      | Classic NFC and AIO open         |
| `docs/nfc_read.md`                      | AIO IO / `VixDiskLib_Read`       |
| `docs/nfc_write.md`                     | AIO IO / `VixDiskLib_Write`      |
| `docs/ssl_hook.md`                      | TLS intercept used for capture   |
| `docs/reverse_engineering_procedure.md` | How the protocol was recovered   |
