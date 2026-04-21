"""
DNS NOTIFY sender.

Sends NOTIFY messages to secondary DNS servers so they re-transfer
zones promptly rather than waiting for the SOA refresh interval.

Notify targets are derived from SeenTransferClient records — IPs that
have previously performed a successful zone transfer (AXFR/IXFR).
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


def resolve_notify_targets(zone_name):
    """
    Look up SeenTransferClient entries for a zone to find NOTIFY targets.

    Returns a list of (ip, port) tuples for all clients that have
    previously transferred this zone. Port is always 53 (standard DNS).

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
    """
    from django.db import close_old_connections
    from netbox_bind_ddns.models import SeenTransferClient

    close_old_connections()

    targets = list(
        SeenTransferClient.objects.filter(
            zone__name=zone_name,
        ).values_list("address", flat=True).distinct()
    )

    if not targets:
        logger.debug("No transfer clients recorded for zone %s", zone_name)
        return []

    result = [(ip, 53) for ip in targets]
    logger.debug(
        "Resolved %d NOTIFY targets for zone %s: %s",
        len(result), zone_name, result,
    )
    return result


def notify_zone(zone_name, tsig_keyring=None):
    """
    Send DNS NOTIFY to all known transfer clients for a zone.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
    """
    targets = resolve_notify_targets(zone_name)
    if not targets:
        return

    for target, port in targets:
        send_notify(zone_name, target, port, tsig_keyring)


def send_notify(zone_name, target, port, tsig_keyring=None):
    """
    Send a DNS NOTIFY message for the given zone to a single target.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        target: IP address of secondary DNS server (e.g. "127.0.0.1")
        port: DNS port of secondary (typically 53)
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
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

        if tsig_keyring:
            notify_msg.use_tsig(tsig_keyring)

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
