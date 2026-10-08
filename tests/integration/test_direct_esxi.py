# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Direct ESXi (HostAgent) NFC path, using the lab VM's host from vCenter."""

import pytest
from pyVim.connect import Disconnect

from openvixdisklib import nfc_auth
from openvixdisklib import openvixdisklib as vixdisklib
from tests.integration.base import (
    SECTOR_AT_1GB,
    SECTOR_SIZE,
    LabEnv,
    _connect_vim,
    pattern_bytes,
)


class TestDirectEsxi:
    def test_nfc_service_moref_is_host_agent(self, esxi_lab: LabEnv) -> None:
        """RetrieveInternalContent must yield the ESXi NfcService moref."""
        si = _connect_vim(
            esxi_lab.host,
            esxi_lab.username,
            esxi_lab.password,
            esxi_lab.port,
            esxi_lab.thumbprint,
            esxi_lab.allow_untrusted,
        )
        try:
            assert si.content.about.apiType == "HostAgent"
            moref = nfc_auth.nfc_service(si)._moId
            assert moref != "nfcService"
            assert moref == "ha-nfc-service"
        finally:
            Disconnect(si)

    @pytest.mark.parametrize("nfc_ssl", [True, False], ids=["nbdssl", "nbd"])
    def test_authd_handshake_omits_ticket_host(
        self, esxi_lab: LabEnv, nfc_ssl: bool
    ) -> None:
        """Direct-ESXi tickets omit ``host`` and PROXY ``nfc``, not ``vpxa-nfc``."""
        with esxi_lab.authenticate(nfc_ssl=nfc_ssl) as session:
            assert not session.ticket.host
            assert session.ticket.service == "nfc"
            assert session.ticket.sessionId
            assert session.nfc_ssl is nfc_ssl
            assert session.authd_sock.getpeername()[0]
            assert session.authd_sock.version()
            assert session.authd_sock.cipher()

    @pytest.mark.parametrize("transport_mode", ["nbdssl", "nbd"])
    def test_write_and_read_sector_zero_and_one_gib(
        self, esxi_lab: LabEnv, transport_mode: str
    ) -> None:
        """ConnectEx + Open + Write/Read against hostd, not vCenter."""
        handle = vixdisklib.VixDiskLibHandle(
            vixdisklib_compatibility_version="8.0", config_path=None
        )
        write_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        read_buf = vixdisklib.get_buffer(SECTOR_SIZE)
        connect_kwargs = esxi_lab.vixdisklib_connect_kwargs(
            {
                "allow_untrusted": esxi_lab.allow_untrusted,
                "transport_modes": transport_mode,
            }
        )
        patterns = {
            0: pattern_bytes(SECTOR_SIZE, b"OVDL-ESX0"),
            SECTOR_AT_1GB: pattern_bytes(SECTOR_SIZE, b"OVDL-ESX1"),
        }
        with (
            handle.connect(**connect_kwargs) as conn,
            handle.open(conn, esxi_lab.disk_path, flags=0) as disk,
        ):
            assert handle.get_transport_mode(disk) == transport_mode
            for start, expected in patterns.items():
                write_buf[:SECTOR_SIZE] = expected
                handle.write(disk, start, 1, write_buf)
                read_buf[:SECTOR_SIZE] = b"\xa5" * SECTOR_SIZE
                handle.read(disk, start, 1, read_buf)
                assert read_buf.raw[:SECTOR_SIZE] == expected
