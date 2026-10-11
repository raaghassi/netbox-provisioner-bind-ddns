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
from django.core.exceptions import ValidationError
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
    # 400 ASCII characters. netbox_dns rewrites anything over 255 with its
    # own _split_text_value into `"chunk" "chunk"`, so this exercises BOTH
    # its chunking and the reassembly in format_txt_value, which must strip
    # that quoting before re-chunking on octets.
    "long_ascii": "".join(chr(97 + i % 26) for i in range(400)),
}

# NOT a case above, and the reason is load-bearing. netbox_dns refuses a TXT
# value that is not printable ASCII (validators/dns_value.py: `if not
# (record.value.isascii() and record.value.isprintable())`), so a multibyte
# value cannot reach the exporter through a validated write. That is also why
# netbox_dns can safely chunk on CHARACTERS: for values it accepts,
# characters and octets are the same. format_txt_value still chunks on
# octets, which matters only for rows that bypassed validation - bulk_create,
# raw SQL, or data predating the check. NonAsciiRejectedTestCase pins the
# assumption so it fails loudly if upstream relaxes it.


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

    def test_long_value_is_chunked_within_the_limit(self):
        """Every character-string must fit in 255 octets, and the chunks must
        still reassemble to the original value."""
        path = self._export()
        zone = dns.zone.from_file(str(path), origin=ZONE_NAME, relativize=True)

        rdata = list(zone.get_rdataset("long_ascii", dns.rdatatype.TXT))[0]
        self.assertGreater(len(rdata.strings), 1, "400 chars must not be one string")
        for chunk in rdata.strings:
            self.assertLessEqual(len(chunk), 255)
        self.assertEqual(
            b"".join(rdata.strings).decode("utf-8"), TXT_CASES["long_ascii"]
        )


class NonAsciiRejectedTestCase(TestCase):
    """Pin the netbox_dns constraint the exporter leans on.

    If this starts failing, upstream now accepts non-ASCII TXT values, so
    multibyte data can reach the exporter and the octet-vs-character
    distinction in format_txt_value stops being merely defensive.
    """

    @classmethod
    def setUpTestData(cls):
        cls.zone = Zone.objects.create(
            name="ascii-guard.example.com",
            soa_mname=NameServer.objects.create(name="ns2.example.com"),
            soa_rname="hostmaster.ascii-guard.example.com",
        )

    def test_non_ascii_txt_is_refused(self):
        with self.assertRaises(ValidationError):
            Record.objects.create(
                name="multibyte",
                zone=self.zone,
                type="TXT",
                value="\u00e9" * 200,
                ttl=300,
            )
