# AI agent guidelines

## Overview

- This is a project meant to bypass/replace VDDK, which is no longer
  publicly available.
- The end goal is to have a Python library that can be used as a VDDK replacement
  to retrieve VMware disk contents.
- Integration tests under `tests/integration/` are a good starting point for
  interacting with the VMware NBD / NFC APIs. They take a session-scoped
  `lab` fixture from `tests/conftest.py` (credentials and VM
  settings in `tests.integration.base.LabEnv`). The fixture creates a
  temporary empty VM for the pytest session. We can make use of
  them to reverse engineer the VMware protocol, for example making various
  calls, capturing the request and replies and then trying to determine the
  structures used by the protocol.
- tcpdump may be used to intercept the communication with ESXI
- if deemed helpful, we may write a simple service that impersonates ESXI,
  capturing the information sent by VDDK
- we should reuse pyVmomi for any operation that it supports. It's publicly
  available and safe to use.
- `docs/` contains various documents that describe the reverse engineered
  vmware APIs and resulting modules.
- Use `docs/reverse_engineering_procedure.md` to best describe the steps that
  were undertaken to reverse engineer the Vmware APIs. Make sure to cover the
  tools that were used (e.g. tcpdump, strace), when and how Python pickled objects
  were stored.
- `docs/probing_samples` contains examples of scripts that were used for
  reverse engineering purposes. The goal is to provide a better insight over
  the reverse engineering procedure. Those scripts, like all other committed
  files, must follow the Sensitive information rules below.


## Architecture

- The project uses Python and must be Python 3.12 and Python 3.10 compatible.
- Library code lives in the `openvixdisklib` package (`nfc_auth`, `nfc_open`,
  `openvixdisklib`).
- The `.vddk` dir contains the VDDK libraries and their dependencies, including
  `libvixDiskLib`. These files shouldn't be included in git commits due to
  licensing constrains.
- `tests/integration/vixdisklib.py` is a Python wrapper on top of
  `libvixDiskLib`, used to cross-check the replacement against native VDDK.
- Integration tests live under `tests/integration/` and use pytest.
  Lab vCenter credentials, datacenter, and datastore come from repo-root
  `.test_config.yaml` (gitignored; sample in `README.md`). A session-scoped
  fixture creates one temporary empty VM with a 10 GiB disk for the whole
  run and destroys it at session end. Run them with
  `tox -e integration` or
  `.venv/bin/pytest tests/integration`. Throughput comparison against
  native VDDK lives under `tests/perf/` (`tox -e perf`). Repeated
  connect/open/close leak checks live under `tests/stress/`
  (`tox -e stress`).


## Sensitive information

Lab topology and credentials live only in gitignored `.test_config.yaml`.
Do not copy live values from it (or from ssh, vim, tcpdump, strace, or
sslhook output) into anything that will be committed.

Sanitize before committing. This applies to `README.md` sample YAML,
`docs/`, `docs/probing_samples/`, comments, tests, and log excerpts — not
only probing scripts. Strip or replace:

- IPs and hostnames (vCenter, ESXi, HotAdd proxy, iSCSI portal)
- Usernames, passwords, SSH identity paths, and home directories
  (e.g. `/home/ubuntu/...`)
- VM / datastore names that are unique to the lab, morefs, SSL
  thumbprints, session tokens, and NAA / WWN identifiers of lab LUNs
- Pickle files, sslhook logs, strace dumps, and packet captures (keep
  those under `/tmp`; they contain lab host and credentials)

Use placeholders that match existing docs:

- Hostnames: `vcenter.example.com`, `hotadd-proxy.example.com`
- IPs: RFC 5737 documentation addresses (`192.0.2.0/24`) or `<vcenter>` /
  `<esxi>`
- ConnectEx fields and tickets: `<sanitized>` (see `vddk_san_trace.py`)
- Sample passwords: generic `secret`, not a lab password

README / `docs/*.md` YAML is a template, not a dump of `.test_config.yaml`.
Before finishing a docs or sample-config change, grep the diff for RFC1918
addresses, `/home/`, and values that appear in `.test_config.yaml`.

## Other rules

- AI agents should ignore folders that start with a dot, e.g. .mypy_cache, .ruff_cache, .tox
- AI agents may use the `.venv/` virtual env, it is expected to have
  all project dependencies, including the `pyVmomi` vmware client
- AI agents should not generate unit or integration tests unless asked to.
- When modifying Markdown tables, the columns should be properly aligned.
- If an agent regenerates a file, avoid appending the new content, but instead
  replace the file contents. We don't want duplicate definitions.
- Empty __init__.py files should not contain license headers.
- Use Linux style line endings.
- All public methods should include docstrings. Subclasses may reuse the ones
  from the parent class.
- Avoid defining new methods for trivial checks such as `server.power_status == "RUNNING"`,
  make the checks inline.
- Avoid removing inline comments that are still applicable.
- Agents should use type hints when the argument type can be determined.
- When writing unit tests, assert_has_calls is preferred instead of checking
  the call cound and call parameters separately.
- When writing unit tests, mock decorators are preferred instead of context
  managers.
- If a folder or file under this directory is inaccessible, ask for permissions.
- Use "tox -e fmt" to apply code formatting, "tox -e pep8" and "tox -e fmt"
  and "tox -e mypy" for liniting / static code analysis.
