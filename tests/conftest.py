# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Session-scoped lab fixtures for live vSphere tests."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from tests.integration.base import (
    LabEnv,
    create_lab_vm,
    destroy_lab_vm,
    ensure_vddk_library_path,
    require_vddk,
)


@pytest.fixture(scope="session")
def lab() -> Iterator[LabEnv]:
    """Create one temporary lab VM for the whole pytest session."""
    os.environ.pop("LD_PRELOAD", None)
    ensure_vddk_library_path()
    env = create_lab_vm()
    try:
        yield env
    finally:
        destroy_lab_vm(env)


@pytest.fixture(scope="session")
def vddk() -> None:
    """Skip VDDK-backed tests when ``libvixDiskLib`` cannot be loaded."""
    require_vddk()
