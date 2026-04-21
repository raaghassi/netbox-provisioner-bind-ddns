import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.zone
import netbox_dns.models


def format_txt_value(value: str) -> str:
    """Format a TXT record value for dnspython, chunking per RFC 1035 §3.3.14.

    NetBox stores TXT values as bare strings or already-quoted strings.
    dnspython requires each character-string to be <=255 chars and quoted.
    """
    # Strip existing quoting that NetBox may have added
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('" "', "").replace('"', '')

    if len(value) > 255:
        chunks = [
            '"{}"'.format(value[i : i + 255])
            for i in range(0, len(value), 255)
        ]
        return " ".join(chunks)
    return f'"{value}"'


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
