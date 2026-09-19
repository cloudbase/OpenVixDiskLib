# Building a VM-encryption test lab from a bare ESXi host

This project's lab is a single standalone ESXi host (no vCenter — see
`docs/reverse_engineering_procedure.md`'s "Lab and artifacts"). VM/VMDK
encryption is a vCenter-only feature: a bare ESXi host's `cryptoManager`
is the base `vim.encryption.CryptoManagerHost`, not
`CryptoManagerHostKMS`, and pushing a key to it fails with
`InvalidState`/"crypto state incapable" — there is no way to test
encryption without standing up vCenter first. This document is that
procedure, distilled from doing it once. It assumes only what the base
lab already has: one ESXi host with spare RAM/CPU/datastore headroom
and a VCSA installer ISO (Broadcom-account-gated; not something this
procedure can supply).

Runnable, credential-parameterized versions of every script referenced
here live in `.lab/` (gitignored — see `.lab/README.md`), not in this
doc.

## 0. Size the host

vCenter Server Appliance's smallest deployment size ("tiny") needs
**2 vCPUs and ~14 GiB RAM** on its own. If the ESXi host is itself a
nested VM (as in this lab — a KubeVirt VM on a Harvester cluster), its
own memory allocation may need to grow first. Check headroom on
whatever hosts the nested ESXi VM before resizing; growing a shared
VM's memory allocation is a shared-infrastructure change worth
confirming before doing it, not something to script unattended.

## 1. Deploy VCSA to the ESXi host

Use the CLI installer (`vcsa-cli-installer/lin64/vcsa-deploy`) from the
VCSA ISO, with a JSON template based on
`vcsa-cli-installer/templates/install/embedded_vCSA_on_ESXi.json`.
Two template gotchas that aren't obvious from VMware's own docs:

- Use `"os": {"time_tools_sync": true}` instead of `"ntp_servers"`
  pointed at a LAN router. Home-lab routers usually aren't real NTP
  servers, and VCSA's firstboot hard-fails deployment entirely on an
  NTP sync error (`err_ntp_sync_failed`). `time_tools_sync` syncs off
  the ESXi host's own clock via VMware Tools instead — no NTP
  dependency at all.
- `deployment_option: "tiny"` is enough for a throwaway test VM; verify
  the target datastore has at least the ~25 GB free space VMware's own
  docs require (thin-provisioned, so actual usage is much less
  initially).

**Environment gotcha**: the bundled `ovftool`/`vcsa-deploy.bin` are
old enough to need `libnsl.so.1` and `libcrypt.so.1`, which current
openSUSE (and likely other rolling-release distros) no longer ship by
default. Rather than hunt for compatible system packages, run the
whole CLI installer inside a throwaway `rockylinux:9` podman container,
which has the exact sonames needed:

```bash
podman run --rm --network=host \
  -v /path/to/mounted/vcsa-iso:/mnt/vcsa-iso:ro \
  -v "$(pwd)":/work:rw \
  rockylinux:9 bash -c "
    dnf install -y libnsl which ncurses libxcrypt-compat glibc-langpack-en
    /mnt/vcsa-iso/vcsa-cli-installer/lin64/vcsa-deploy install \
      --accept-eula --no-ssl-certificate-verification --acknowledge-ceip \
      /work/vcsa-deploy-config.json
  "
```

`--network=host` is needed so the container can reach the ESXi host
and the appliance's own IP directly on the LAN.

## 2. Add the host to vCenter — and into a cluster

Adding the host as a standalone host under a new datacenter is the
obvious first step (`Folder.CreateDatacenter` +
`HostFolder.AddStandaloneHost`), but **it is not enough**: Native Key
Provider setup fails at the point of actually encrypting a VM with

```
vim.vpxd.encryption.NativeKeyProviderNotSupported.NotInCluster
```

if the host is standalone rather than in a cluster, even though
earlier checks (`CryptoManagerKmip.IsKmsClusterActive`) may already
report the provider as active. Create an empty cluster
(`HostFolder.CreateClusterEx` with a bare `vim.cluster.ConfigSpecEx()`
— no DRS/HA needed) and move the host into it
(`ClusterComputeResource.MoveInto_Task`) before going further.

**Side effect worth knowing about**: creating a cluster makes vCenter
automatically try to deploy its own vSphere Cluster Services (vCLS)
agent VMs onto it — unconditionally, even with DRS/HA both off. On a
nested-virtualization host that doesn't expose certain CPU features at
that nesting depth (this lab saw `Feature 'MWAIT' was 0, but must be 1`
and `Extended APIC register space was absent`), these VMs fail to
power on and vCenter retries indefinitely (~every 30s), cluttering
Recent Tasks. Harmless for testing purposes; can be silenced via the
cluster's "Retreat Mode" advanced setting if the noise becomes a
problem.

## 3. Create a Native Key Provider

No external KMIP server needed — vSphere's built-in Native Key
Provider (NKP) manages keys itself. The catch: **NKP creation is not
exposed over classic VIM SOAP at all.**
`CryptoManagerKmip.RegisterKmsCluster`'s `managementType` parameter
looks like it should do this, but it's read-only/reporting-only —
passing it raises `InvalidArgument`. NKP can only be *created* through
vCenter's newer REST/vAPI (`/api/vcenter/crypto-manager/kms/providers`).

The official Python client for that API
(`vsphere-automation-sdk-python` on GitHub, or `vsphere-automation-sdk`
on PyPI) may not be installable in every environment — the PyPI sdist
is broken (missing `LICENSE.txt`) as of this writing, and installing
the GitHub version's own dependencies (`vapi-runtime`,
`vapi-common-client`) may trip a sandboxed environment's
package-installation safeguards. The 3 REST calls actually needed are
simple enough to hand-roll with plain `requests`:

1. `POST /api/session` with HTTP Basic auth → a session-id string, sent
   back as the `vmware-api-session-id` header on every later call.
2. `POST /api/vcenter/crypto-manager/kms/providers` with
   `{"provider": "<name>", "constraints": {"tpm_required": false}}` —
   creates the provider, but it comes back `"health": "ERROR"`
   ("requires backup") until step 3.
3. `POST /api/vcenter/crypto-manager/kms/providers?action=export`
   (**the query param must be on the providers *collection* URL, not
   the per-provider URL** — `.../providers/<name>?action=export`
   404s) with `{"provider": "<name>", "password": "<any>"}`. The
   response's `location.url` may carry vCenter's own (possibly stale)
   reverse-DNS hostname instead of its real address — substitute
   before using it. `POST` that URL with
   `Authorization: Bearer <download_token.token>` to actually download
   the backup blob. This step is what flips `health` to `OK` — for a
   Native Key Provider, "back it up" is not an optional safety step,
   it's what activates the provider in the first place.

Mark it default afterward with plain VIM SOAP (this part *does* work
classically): `CryptoManagerKmip.SetDefaultKmsCluster(clusterId=...)`.

## 4. Create and encrypt a test VM

Two separate operations, in order:

1. **Encrypt the VM's home directory** — a `ReconfigVM_Task` with
   `VirtualMachineConfigSpec.crypto = CryptoSpecEncrypt(cryptoKeyId=...)`.
   This alone is not enough on a VM with no vTPM or existing encryption
   storage profile — it fails with
   `encryptForbiddenWithoutEncryptedProfile`. Add a
   `vim.vm.device.VirtualTPM()` device in the **same** `ReconfigVM_Task`
   call as the crypto spec to satisfy this.
   For a Native Key Provider specifically, leave
   `CryptoKeyId.keyId = ""` and let vCenter auto-generate the actual
   key — `CryptoManagerKmip.GenerateKey()` explicitly rejects native
   providers ("Key provider ... is managed by ... or is a native key
   provider").
2. **Encrypt the disk itself** — step 1 does *not* encrypt attached
   virtual disks; `backing.keyId` stays `None` and the `.vmdk`
   descriptor is unchanged. A raw device-edit attempt
   (`VirtualDeviceSpec.backing = BackingSpec(crypto=CryptoSpecEncrypt(...))`,
   `operation=edit`) fails with `badPolicy` /
   "Invalid storage policy for encryption operation" — disk encryption
   is only reachable through SPBM (Storage Policy-Based Management),
   which is yet another separate SOAP endpoint (`/pbm/sdk`).
   Driving SPBM programmatically hit an unresolved
   `vmodl.fault.SecurityError` on `PbmQueryProfile` even after
   correctly copying the vCenter session cookie to the PBM stub (the
   standard pyvmomi-community-samples pattern); not worth further
   debugging time for a one-off lab setup. **Working fallback: the
   vSphere Client UI** — right-click the VM → **VM Policies → Edit VM
   Storage Policies** → set the storage policy to the built-in
   **"VM Encryption Policy"** (a system-created profile every vCenter
   ships; don't confuse it with "Management Storage Policy -
   Encryption", a different profile for infrastructure objects) → OK.
   This silently relocates the disk file (e.g. `foo.vmdk` →
   `foo_1.vmdk`) — re-read the VM's device list afterward.

## 5. Verify it's actually encrypted

Don't trust `backing.keyId` alone — confirm at the wire level by
reading the raw `.vmdk` descriptor over ESXi's datastore-browser HTTP
API:

```
GET https://<esxi-host>/folder/<vm>/<disk>.vmdk?dcPath=ha-datacenter&dsName=<datastore>
```

**Gotcha**: this legacy per-host API still uses `ha-datacenter` (the
standalone-host pseudo-datacenter name) even after the host becomes
vCenter-managed under a real datacenter name — not the vCenter
datacenter name. A genuinely encrypted disk's descriptor has
`keyID=...`, an `encryptionKeys="vmware:key/list/..."` line, and
`ddb.iofilters = "vmwarevmcrypt"`. For the strongest possible proof,
write a known byte pattern through normal NFC I/O and fetch the same
byte range from the `-flat.vmdk` file directly (`Range:
bytes=<offset>-<offset+len-1>`) — it should not contain the plaintext
pattern.

## What this lab cannot test

Nothing here provisions a *second* ESXi host, so the "host doesn't
already have this disk's key" scenario — cross-host vMotion/clone/
restore of an encrypted VM — cannot be exercised. See
`docs/encryption.md`'s "What this does not cover" for why that matters.
