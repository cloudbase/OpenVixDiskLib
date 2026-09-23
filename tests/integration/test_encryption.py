# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Confirm encrypted VM disks work transparently, with no code changes.

See ``docs/encryption.md``. Unlike the rest of ``tests/integration``,
this does not use the session-scoped ``lab`` fixture: creating and
encrypting a VM needs a vCenter with a Native Key Provider and a
manual storage-policy assignment step (``docs/encryption_lab_setup.md``
-- the SPBM API needed to automate the last step did not work), so this
test instead points at a pre-existing encrypted VM/disk. It reuses the
vCenter settings from ``.test_config.yaml`` (see ``README.md``) and needs
two extra keys, ``encrypted_vm_moref`` and ``encrypted_disk_path``. It is
skipped if those keys are absent.
"""

import os
from typing import Any

import pytest
import yaml

from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import SECTOR_SIZE, pattern_bytes

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_CONFIG_PATH = os.path.join(_REPO_ROOT, ".test_config.yaml")
_ENCRYPTION_CONFIG_KEYS = ("encrypted_vm_moref", "encrypted_disk_path")


def _load_encryption_config() -> dict[str, Any]:
    if not os.path.isfile(_CONFIG_PATH):
        pytest.skip(f"{_CONFIG_PATH} not found; see docs/encryption_lab_setup.md")
    with open(_CONFIG_PATH, encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    missing = [key for key in _ENCRYPTION_CONFIG_KEYS if key not in data]
    if missing:
        pytest.skip(
            "encrypted-disk test needs an already-encrypted VM; "
            f"missing .test_config.yaml keys: {', '.join(missing)} "
            "(see docs/encryption_lab_setup.md)"
        )
    return data


class TestEncryption:
    def test_read_write_encrypted_disk(self) -> None:
        """Write a known pattern to an encrypted disk and read it back.

        No encryption-specific code path exists in openvixdisklib --
        this is exactly the same connect/open/write/read sequence as
        any other disk. See docs/encryption.md for the wire-level proof
        that the bytes are genuinely ciphertext at rest.
        """
        cfg = _load_encryption_config()
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        expected = pattern_bytes(SECTOR_SIZE, b"OVDL-CRYPTO-")

        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        write_buf[:SECTOR_SIZE] = expected
        with (
            handle.connect(
                server_name=cfg["host"],
                port=int(cfg.get("port", 443)),
                thumbprint=None,
                username=cfg["username"],
                password=cfg["password"],
                vmx_spec=str(cfg["encrypted_vm_moref"]),
                read_only=False,
                allow_untrusted=bool(cfg.get("allow_untrusted", True)),
            ) as conn,
            handle.open(conn, str(cfg["encrypted_disk_path"]), flags=0) as disk,
        ):
            handle.write(disk, 0, 1, write_buf)

        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
        with (
            handle.connect(
                server_name=cfg["host"],
                port=int(cfg.get("port", 443)),
                thumbprint=None,
                username=cfg["username"],
                password=cfg["password"],
                vmx_spec=str(cfg["encrypted_vm_moref"]),
                read_only=True,
                allow_untrusted=bool(cfg.get("allow_untrusted", True)),
            ) as conn,
            handle.open(
                conn,
                str(cfg["encrypted_disk_path"]),
                flags=vixdisklib.VIXDISKLIB_FLAG_OPEN_READ_ONLY,
            ) as disk,
        ):
            handle.read(disk, 0, 1, read_buf)

        assert read_buf.raw[:SECTOR_SIZE] == expected
