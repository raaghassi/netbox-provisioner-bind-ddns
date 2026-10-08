"""format_txt_value must emit presentation text dnspython can parse back.

Every case here is a value that reached a real zone. The quote case took down
an entire zone's AXFR: request_handler.py builds the zone with no local try, so
one bad record aborted the whole transfer. The backslash case was quieter - it
parsed, but dnspython read the backslash as an escape and served a different
value than NetBox held.
"""

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest


def _parse(text: str) -> bytes:
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, text)
    return b"".join(rdata.strings)


@pytest.mark.parametrize(
    "value",
    [
        "plain value",
        "v=spf1 include:_spf.example.com ~all",
        'has"quote',
        "back\\slash",
        'both"and\\slash',
        "",
        "a b  c",
        "x" * 300,
        "é" * 200,
    ],
)
def test_round_trips_to_the_original_bytes(utils, value):
    assert _parse(utils.format_txt_value(value)) == value.encode("utf-8")


@pytest.mark.parametrize("value", ['has"quote', 'both"and\\slash'])
def test_embedded_quote_is_escaped_not_emitted_raw(utils, value):
    # The defect emitted '"has"quote"', which dnspython rejects outright.
    assert utils.format_txt_value(value).count('"') > 2
    _parse(utils.format_txt_value(value))


def test_backslash_survives(utils):
    # The defect emitted '"back\\slash"', which parses but silently loses the
    # backslash because \s is read as an escape.
    assert _parse(utils.format_txt_value("back\\slash")) == b"back\\slash"


def test_long_value_is_split_into_valid_character_strings(utils):
    rendered = utils.format_txt_value("x" * 300)
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, rendered)
    assert len(rdata.strings) == 2
    assert all(len(s) <= 255 for s in rdata.strings)


def test_multibyte_value_is_split_on_octets_not_characters(utils):
    # 200 two-byte characters is 400 octets, so it must split even though the
    # string is shorter than 255 characters.
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.TXT, utils.format_txt_value("é" * 200)
    )
    assert len(rdata.strings) == 2
    assert all(len(s) <= 255 for s in rdata.strings)
