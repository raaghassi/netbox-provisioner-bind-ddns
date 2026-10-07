import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.zone
import netbox_dns.models


def format_txt_value(value: str) -> str:
    """Format a TXT record value for dnspython, chunking per RFC 1035 §3.3.14.

    NetBox stores TXT values as bare strings or already-quoted strings.
    A character-string is at most 255 OCTETS and is quoted, with any embedded
    quote or backslash escaped. dnspython renders that form.
    """
    # Strip existing quoting that NetBox may have added
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('" "', "").replace('"', '')

    # Split on BYTES, not characters. RFC 1035 counts a character-string in
    # octets, so a 200-character value of two-byte characters is 400 octets and
    # must still be split.
    data = value.encode("utf-8")
    chunks = [data[i : i + 255] for i in range(0, len(data), 255)] or [b""]

    # Let dnspython render the presentation form. Wrapping the value in quotes
    # by hand does not escape an embedded quote or backslash, and dnspython
    # then either fails to parse the result or reads the backslash as an escape
    # and drops it.
    return dns.rdtypes.ANY.TXT.TXT(
        dns.rdataclass.IN, dns.rdatatype.TXT, strings=chunks
    ).to_text()


def export_bind_zone_file(nb_zone: netbox_dns.models.Zone, file_path: str):

    # Create dnspython zone object
    dp_zone = dns.zone.Zone(origin=dns.name.from_text(nb_zone.name))

    for record in nb_zone.records.all():
        rname = record.name or "@"
        rdclass = dns.rdataclass.IN
        rdatatype = dns.rdatatype.from_text(record.type)

        value = record.value
        if rdatatype == dns.rdatatype.TXT:
            value = format_txt_value(value)

        rdata = dns.rdata.from_text(
            rdclass, rdatatype, value,
            relativize=False, origin=dp_zone.origin,
        )

        ttl = record.ttl or nb_zone.default_ttl
        rdataset = dns.rdataset.Rdataset(rdclass, rdatatype)
        rdataset.add(rdata, ttl)

        node = dp_zone.find_node(rname, create=True)
        node.rdatasets.append(rdataset)

    # Write zone to file in BIND format
    try:
        with open(file_path, "w") as f:
            dp_zone.to_file(f, sorted=True)
    except IOError as e:
        raise IOError(f"Failed to write zone file to {file_path}: {e}")
