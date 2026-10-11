"""Round-trip the zone exporter through real netbox_dns models and dnspython.

format_txt_value had three defects, all fixed in 9dfc468 and all covered by
the framework-free tests in tests_engine/. Those call the function directly.
This module exercises the same values through the path production uses -
netbox_dns Record rows, export_bind_zone_file, a file on disk, reparsed by
dnspython - because that is where the original failure actually showed: an
unescapable quote aborted the whole zone transfer, not one record.
"""

import tempfile
from pathlib import Path

import dns.rdatatype
import dns.zone
from django.test import TestCase

from netbox_dns.models import NameServer, Record, Zone

from netbox_dns_bridge.utils import export_bind_zone_file

ZONE_NAME = "bridge-export.example.com"

# name -> the exact value a client should get back
TXT_CASES = {
    "plain": "v=spf1 -all",
    # An embedded quote. Hand-rolled quoting produced "has"quote", which
    # dnspython refused with UnexpectedEnd - and request_handler.py had no
    # local guard, so one bad record killed the entire AXFR.
    "quoted": 'has"quote',
    # An embedded backslash. Hand-rolled quoting let dnspython read it as an
    # escape and silently drop it, so the served value differed from NetBox.
    "backslash": "back\\slash",
    # 200 two-byte characters = 400 octets. Chunking on CHARACTERS left a
    # single 400-octet character-string, over the RFC 1035 255-octet limit.
    "multibyte": "é" * 200,
}


class ZoneExportTXTTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.zone = Zone.objects.create(
            name=ZONE_NAME,
            soa_mname=NameServer.objects.create(name="ns1.example.com"),
            soa_rname=f"hostmaster.{ZONE_NAME}",
        )
        for name, value in TXT_CASES.items():
            Record.objects.create(
                name=name,
                zone=cls.zone,
                type="TXT",
                value=value,
                ttl=300,
            )

    def _export(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / f"db.{ZONE_NAME}"
        export_bind_zone_file(self.zone, file_path=str(path))
        return path

    def test_zone_file_is_parseable(self):
        """The whole-zone assertion. A single unescapable value used to make
        the entire file unparseable, which is why this is separate."""
        path = self._export()
        zone = dns.zone.from_file(str(path), origin=ZONE_NAME, relativize=True)
        self.assertIsNotNone(zone)

    def test_every_txt_value_round_trips(self):
        path = self._export()
        zone = dns.zone.from_file(str(path), origin=ZONE_NAME, relativize=True)

        for name, expected in TXT_CASES.items():
            with self.subTest(case=name):
                rdataset = zone.get_rdataset(name, dns.rdatatype.TXT)
                self.assertIsNotNone(rdataset, f"no TXT rdataset for {name}")
                rdata = list(rdataset)[0]
                got = b"".join(rdata.strings).decode("utf-8")
                self.assertEqual(got, expected)

    def test_long_value_is_chunked_within_the_octet_limit(self):
        """RFC 1035 counts a character-string in OCTETS. Every chunk must fit,
        and the chunks must still reassemble to the original value."""
        path = self._export()
        zone = dns.zone.from_file(str(path), origin=ZONE_NAME, relativize=True)

        rdata = list(zone.get_rdataset("multibyte", dns.rdatatype.TXT))[0]
        self.assertGreater(len(rdata.strings), 1, "400 octets must not be one string")
        for chunk in rdata.strings:
            self.assertLessEqual(len(chunk), 255)
        self.assertEqual(
            b"".join(rdata.strings).decode("utf-8"), TXT_CASES["multibyte"]
        )
