# Copyright 2026 Cloudbase Solutions Srl
# All Rights Reserved.

"""Exercise VDDK-compatible NFC authentication against the lab vCenter."""

from tests.integration.base import TestBase


class NfcAuthTest(TestBase):
    def test_authd_handshake_completes(self) -> None:
        """Complete VIM login and authd PROXY through ``200 Connect``."""
        with self.authenticate() as session:
            ticket = session.ticket
            self.assertTrue(ticket.host)
            self.assertTrue(ticket.port)
            self.assertTrue(ticket.sessionId)
            self.assertTrue(session.authd_sock.version())
            self.assertTrue(session.authd_sock.cipher())
