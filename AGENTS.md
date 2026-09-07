# AI agent guidelines

## Overview

- This is a test project meant to bypass/replace VDDK, which is no longer
  publicly available.
- The end goal is to have a Python library that can be used as a VDDK replacement
  to retrieve VMware disk contents.
- Integration tests under `tests/integration/` are a good starting point for
  interacting with the VMware NBD / NFC APIs. They take a session-scoped
  `lab` fixture from `tests/integration/conftest.py` (credentials and VM
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
  were undertaken to reverse engineer the Vmware APIs.


## Architecture

- The project uses Python and must be Python 3.12 compatible.
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
  `.venv/bin/pytest tests/integration`.


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
