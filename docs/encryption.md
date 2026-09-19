# Encrypted VM disks

This is not a reverse-engineered NFC feature. When the ESXi host
serving an NFC session already holds the target disk's encryption key
— the common case, and the only one testable without a second ESXi
host (see "What this does not cover" below) — VM/VMDK encryption is
handled entirely by ESXi's storage stack, **below and invisible to the
NFC protocol**. `openvixdisklib` already reads and writes encrypted
disks correctly with no encryption-specific code at all; this was
verified, not implemented.

## Investigation

The backlog item was "encrypted disks" (VDDK supports VM/VMDK
encryption; OpenVixDiskLib had no code path for it and no lab evidence
either way). `strings` on `libvddkVimAccess.so` found suggestive
tokens — `"cannot cast the crypto manager to CryptoManagerHostKMS"`,
`"Cannot push crypto key to host"` — implying VDDK does some kind of
key-provisioning VIM call before NFC I/O on an encrypted disk. Testing
this needed an actual encrypted VM, which needed vCenter (VM
encryption / Key Management Server configuration is a vCenter-only
concept — a bare standalone ESXi host's `cryptoManager` is the base
`vim.encryption.CryptoManagerHost`, not `CryptoManagerHostKMS`, and
`AddKey` fails with `InvalidState`/"crypto state incapable": no KMS
trust relationship is possible without vCenter). Building that lab
(vCenter Server Appliance + a vSphere Native Key Provider + an
encrypted test VM) is documented separately in
`docs/encryption_lab_setup.md`.

With a real encrypted disk in hand, the same SSL-hook technique as
every other NFC feature (`docs/ssl_hook.md`) captured native VDDK
8.0.2 opening it, compared against an identical capture against an
unencrypted disk on the same host. Findings:

- VDDK's own log makes the branch explicit. Unencrypted:
  `VddkVimAccess_HandleDiskCryptoKey: Handle the key of disk ...`
  immediately followed by
  `HandleDiskCryptoKey: Disk '...' is not encrypted. No need to handle
  disk crypto key.` Encrypted: the same `HandleDiskCryptoKey` line
  fires, but that second message is absent — it goes straight to
  `VddkVimAccess_FreeNfcTicket` with no further narration.
- The encrypted-disk capture (844 SSL/socket records covering both the
  vCenter SOAP session and the ESXi NFC session) contains **no**
  `AddKey`, `ConfigureCryptoKey`, `EnableCrypto`, `PrepareCrypto`, or
  `QueryCryptoKeyStatus` calls — the VIM methods that looked like
  candidates for "push key to host" from the binary strings. The only
  crypto-related SOAP content anywhere in the capture is routine
  `RetrieveServiceContent` boilerplate (`cryptoManager
  type="CryptoManagerKmip"` at vCenter, `type="CryptoManagerHostKMS"`
  at the host) that appears on every connection, encrypted disk or not.

That's negative evidence (no extra call *seen*), which only proves the
happy path. The decisive test was positive: used `openvixdisklib`
itself — no crypto-specific code — to write a known byte pattern to
an encrypted disk's sector 0 through normal `VixDiskLib_Write`-equivalent
NFC I/O, read it back through a **separate** `open()` (avoiding the
same-handle staleness class of bug noted in `docs/nfc_read.md`), and
got an exact match: a completely ordinary, transparent NFC round-trip.
Then fetched the same byte range directly from the disk's
`-flat.vmdk` file over ESXi's datastore-browser HTTP API
(`Range: bytes=0-511`) and confirmed the raw bytes on disk are genuine
ciphertext — the plaintext pattern does not appear. Real
encryption-at-rest is happening (confirmed independently at the wire
level too: the `.vmdk` descriptor carries `keyID=`, an `encryptionKeys=`
wrapped-key blob, and `ddb.iofilters = "vmwarevmcrypt"`), and it is
completely invisible to any NFC client, VDDK or otherwise.

## Why this is the expected result

VDDK's "push crypto key to host" logic exists for *provisioning*: the
case where the ESXi host about to serve NFC I/O does **not** already
have the disk's key cached locally — for example, right after a
cross-host vMotion, clone, or restore places the encrypted VM on a
host that has never served it before. In that case VDDK (running with
appropriate vCenter privileges) fetches the key and pushes it to the
target host via `CryptoManagerHostKMS.AddKey` before NFC can succeed.
Once the host has the key — which it always will for a VM that has
simply been encrypted and left in place, the scenario this lab's
single ESXi host can produce — ESXi's storage stack decrypts/encrypts
transparently at the IOFilter layer for every client, with nothing
encryption-specific in the NFC wire protocol at all.

## Validated in this lab

Single-ESXi-host lab (`docs/encryption_lab_setup.md`), VM
`ovdl-crypto-test` with both its home directory and its virtual disk
encrypted via a vSphere Native Key Provider:

- Read/write round-trip via `openvixdisklib.openvixdisklib` over the
  vCenter-managed path (`server_name=<vcenter>`, `vmx_spec="moref=vm-N"`)
  — matches the pattern written, confirmed as genuine ciphertext at
  rest as described above.
- Native VDDK 8.0.2 (`ConnectEx` + `Open` + `Read`) succeeds against
  the same disk with no special handling required, decrypting
  correctly (a freshly-created 1 GiB disk reads back as zeros, as
  expected for an unwritten region).

## What this does not cover

- **A host that does not already have the disk's key cached.** This is
  the actual scenario the `CryptoManagerHostKMS.AddKey`
  ("push crypto key to host") binary strings exist for, and it is the
  one case this investigation could not exercise — it needs a second
  ESXi host to migrate/clone the encrypted VM to, which this lab does
  not have. If a real gap exists anywhere in encrypted-disk support,
  this is where it would be: OpenVixDiskLib has no code today to fetch
  and push a disk's encryption key to a host that lacks it, and no VIM
  call for doing so has been identified or captured. Until that's
  tested, treat single-host-served encrypted disks as confirmed
  working and cross-host key provisioning as an open question, not a
  confirmed gap.
- Standard/KMIP external Key Management Servers were not tested — only
  vSphere Native Key Provider. The NFC-transparency conclusion should
  hold regardless of which KMS variant provisioned the key (the
  key-caching-on-host mechanism is the same either way), but this
  wasn't independently verified.
- Direct-ESXi (no vCenter) access to an encrypted disk was attempted
  but not completed — hit an unrelated, reproducible pyVmomi issue
  (a bare `vim.VirtualMachine("vm-N", stub)` construction raising
  `ManagedObjectNotFound` against this specific host, independent of
  encryption) that wasn't investigated further. Worth retrying if this
  recurs elsewhere.
