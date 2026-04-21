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

logger = logging.getLogger("netbox_dns_bridge.notify")


def resolve_notify_targets(zone_name):
    """
    Look up SeenTransferClient entries for a zone to find NOTIFY targets.

    Returns a list of (ip, port, view_name) tuples for all clients that have
    previously transferred this zone. Port is always 53 (standard DNS).

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
    """
    from django.db import close_old_connections
    from netbox_dns_bridge.models import SeenTransferClient

    close_old_connections()

    targets = list(
        SeenTransferClient.objects.filter(
            zone__name=zone_name,
        ).values_list("address", "view__name").distinct()
    )

    if not targets:
        logger.debug("No transfer clients recorded for zone %s", zone_name)
        return []

    result = [(ip, 53, view_name) for ip, view_name in targets]
    logger.debug(
        "Resolved %d NOTIFY targets for zone %s: %s",
        len(result), zone_name, result,
    )
    return result


def notify_zone(zone_name, tsig_keyring=None, tsig_view_map=None):
    """
    Send DNS NOTIFY to all known transfer clients for a zone.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        tsig_view_map: Optional dict of {view_name_str: dns.name.Name} mapping
            view names to TSIG key names for per-target key selection.
    """
    targets = resolve_notify_targets(zone_name)
    if not targets:
        return

    for target, port, view_name in targets:
        # Select the TSIG key matching this target's view
        keyname = None
        if tsig_view_map and view_name:
            keyname = tsig_view_map.get(view_name)

        send_notify(zone_name, target, port, tsig_keyring, keyname=keyname)


def send_notify(zone_name, target, port, tsig_keyring=None, keyname=None):
    """
    Send a DNS NOTIFY message for the given zone to a single target.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        target: IP address of secondary DNS server (e.g. "127.0.0.1")
        port: DNS port of secondary (typically 53)
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        keyname: Optional dns.name.Name specifying which key from the keyring to use.
            If None and the keyring has exactly one key, that key is used.
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
            if keyname and keyname in tsig_keyring:
                # Use the specific key for this target's view
                notify_msg.use_tsig(tsig_keyring, keyname=keyname)
            elif len(tsig_keyring) == 1:
                # Single key — no ambiguity
                notify_msg.use_tsig(tsig_keyring)
            else:
                logger.warning(
                    "NOTIFY %s -> %s:%d: multiple TSIG keys but no view mapping; "
                    "sending unsigned",
                    zone_name, target, port,
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
