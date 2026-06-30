"""dns_control output parsing (the most safety-critical macOS module).

Only the pure parsing of networksetup output is exercised here; the stateful
install()/restore() flow touches the live system DNS and needs root, so it is out
of scope for unit tests. networksetup (dns_control._run) is faked.
"""

from __future__ import annotations

import unittest
from unittest import mock

from dohproxy.macos import dns_control


class ListServicesTest(unittest.TestCase):
    def test_skips_header_and_disabled_services(self):
        out = ("An asterisk (*) denotes that a network service is disabled.\n"
               "Wi-Fi\n"
               "*Thunderbolt Bridge\n"   # disabled -> skipped
               "Ethernet\n")
        with mock.patch.object(dns_control, "_run", return_value=out):
            self.assertEqual(dns_control._list_services(), ["Wi-Fi", "Ethernet"])

    def test_get_dns_none_set_returns_empty(self):
        msg = "There aren't any DNS Servers set on Wi-Fi.\n"
        with mock.patch.object(dns_control, "_run", return_value=msg):
            self.assertEqual(dns_control._get_dns("Wi-Fi"), [])

    def test_get_dns_returns_servers(self):
        with mock.patch.object(dns_control, "_run", return_value="1.1.1.1\n8.8.8.8\n"):
            self.assertEqual(dns_control._get_dns("Wi-Fi"), ["1.1.1.1", "8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
