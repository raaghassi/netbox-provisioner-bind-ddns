"""
DNS NOTIFY sender.

After a DDNS update modifies zone data in NetBox, this sends a NOTIFY
to BIND so it re-transfers the affected zone promptly rather than
waiting for the SOA refresh interval.
"""
import logging

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

logger = logging.getLogger("netbox_bind_ddns.notify")


def send_notify(zone_name, target, port):
    """
    Send a DNS NOTIFY message for the given zone.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        target: IP address of BIND server (e.g. "127.0.0.1")
        port: DNS port of BIND (typically 53)
    """
    try:
        qname = dns.name.from_text(zone_name + ".")

        # Build NOTIFY message: opcode NOTIFY, AA flag, SOA question
        notify_msg = dns.message.Message()
        notify_msg.flags = dns.flags.AA | dns.opcode.to_flags(dns.opcode.NOTIFY)
        notify_msg.find_rrset(
            dns.message.QUESTION,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            create=True,
        )

        response = dns.query.udp(notify_msg, target, port=port, timeout=5.0)

        logger.info(
            "NOTIFY %s -> %s:%d rcode=%s",
            zone_name,
            target,
            port,
            dns.rcode.to_text(response.rcode()),
        )
    except Exception:
        logger.exception("NOTIFY %s -> %s:%d failed", zone_name, target, port)
