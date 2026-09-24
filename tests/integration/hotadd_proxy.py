# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""SSH helpers for running OpenVixDiskLib HotAdd on the Linux proxy."""

from __future__ import annotations

import os
import subprocess

from tests.integration.base import load_hotadd_proxy_config

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REMOTE_DIR = "/tmp/openvixdisklib-hotadd"
REMOTE_VENV = f"{REMOTE_DIR}/.venv"
REMOTE_PYTHON = f"{REMOTE_VENV}/bin/python"
SSH_CONNECT_TIMEOUT_S = 15
DEFAULT_SSH_TIMEOUT_S = 300


def ssh_base(proxy: dict[str, str]) -> list[str]:
    """Return the ``ssh user@host`` prefix for ``proxy``."""
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={SSH_CONNECT_TIMEOUT_S}",
    ]
    if proxy.get("identity_file"):
        cmd.extend(["-i", proxy["identity_file"]])
    cmd.append(f"{proxy['user']}@{proxy['host']}")
    return cmd


def ssh_proxy(
    proxy: dict[str, str],
    remote: str,
    *,
    stdin: bytes | None = None,
    timeout: int = DEFAULT_SSH_TIMEOUT_S,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``remote`` on the HotAdd proxy and return the completed process."""
    return subprocess.run(
        [*ssh_base(proxy), remote],
        input=stdin,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def prepare_hotadd_proxy(
    extra_files: dict[str, str] | None = None,
) -> dict[str, str]:
    """Probe SSH, sync ``openvixdisklib``, and return proxy settings.

    ``extra_files`` maps a remote basename under ``REMOTE_DIR`` to a
    local path that is copied after the package. Raises ``RuntimeError``
    when the proxy is missing or unreachable.
    """
    proxy = load_hotadd_proxy_config()
    if proxy is None:
        raise RuntimeError("hotadd_proxy missing from .test_config.yaml")
    probe = ssh_proxy(proxy, "echo ok")
    if probe.returncode != 0:
        raise RuntimeError(
            f"cannot ssh to {proxy['user']}@{proxy['host']}: "
            f"{probe.stderr.decode(errors='replace').strip()}"
        )
    _sync_package(proxy, extra_files or {})
    return proxy


def _sync_package(proxy: dict[str, str], extra_files: dict[str, str]) -> None:
    mkdir = ssh_proxy(proxy, f"mkdir -p {REMOTE_DIR}/openvixdisklib")
    if mkdir.returncode != 0:
        raise RuntimeError(
            f"mkdir on proxy failed: {mkdir.stderr.decode(errors='replace')}"
        )
    archive = subprocess.run(
        [
            "tar",
            "-C",
            os.path.join(_REPO_ROOT, "openvixdisklib"),
            "-czf",
            "-",
            ".",
        ],
        capture_output=True,
        check=False,
    )
    if archive.returncode != 0:
        raise RuntimeError(
            f"tar package failed: {archive.stderr.decode(errors='replace')}"
        )
    unpack = ssh_proxy(
        proxy,
        f"rm -rf {REMOTE_DIR}/openvixdisklib && mkdir -p {REMOTE_DIR}/openvixdisklib "
        f"&& tar -C {REMOTE_DIR}/openvixdisklib -xzf -",
        stdin=archive.stdout,
    )
    if unpack.returncode != 0:
        raise RuntimeError(
            f"copy package to proxy failed: {unpack.stderr.decode(errors='replace')}"
        )
    for remote_name, local_path in extra_files.items():
        with open(local_path, "rb") as handle:
            contents = handle.read()
        copy = ssh_proxy(proxy, f"cat > {REMOTE_DIR}/{remote_name}", stdin=contents)
        if copy.returncode != 0:
            raise RuntimeError(
                f"copy {remote_name} to proxy failed: "
                f"{copy.stderr.decode(errors='replace')}"
            )
    venv = ssh_proxy(
        proxy,
        f"test -x {REMOTE_PYTHON} || python3 -m venv {REMOTE_VENV}",
    )
    if venv.returncode != 0:
        raise RuntimeError(
            f"could not create proxy venv: {venv.stderr.decode(errors='replace')}"
        )
    deps = ssh_proxy(
        proxy,
        f"{REMOTE_PYTHON} -c 'import pyVmomi, pyVim, fastlz'",
    )
    if deps.returncode != 0:
        install = ssh_proxy(
            proxy,
            f"{REMOTE_PYTHON} -m pip install 'pyVmomi>=7.0' pyOpenSSL pyfastlz",
        )
        if install.returncode != 0:
            raise RuntimeError(
                "proxy venv pip install failed: "
                f"{install.stderr.decode(errors='replace')}"
            )
