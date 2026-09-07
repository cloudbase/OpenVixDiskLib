# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise VDDK-compatible NFC authentication against the lab vCenter."""

from tests.integration.base import LabEnv


class TestNfcAuth:
    def test_authd_handshake_completes(self, lab: LabEnv) -> None:
        """Complete VIM login and authd PROXY through ``200 Connect``."""
        with lab.authenticate() as session:
            ticket = session.ticket
            assert ticket.host
            assert ticket.port
            assert ticket.sessionId
            assert session.nfc_ssl is True
            assert session.authd_sock.version()
            assert session.authd_sock.cipher()

    def test_authd_nbd_handshake_completes(self, lab: LabEnv) -> None:
        """Complete authd with plaintext NFC after PROXY (nbd)."""
        with lab.authenticate(nfc_ssl=False) as session:
            assert session.nfc_ssl is False
            assert session.ticket.sessionId
            assert session.authd_sock.version()
            assert session.authd_sock.cipher()
