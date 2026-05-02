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
import dns.rdata
import dns.rdataclass
import dns.rdatatype

logger = logging.getLogger("netbox_dns_bridge.notify")


def resolve_notify_targets(zone_id):
    """
    Look up SeenTransferClient entries for a zone to find NOTIFY targets.

    Returns a list of (ip, port, view_name) tuples for all clients that have
    previously transferred this zone. Port is always 53 (standard DNS).

    Args:
        zone_id: NetBox zone primary key
    """
    from django.db import close_old_connections
    from netbox_dns_bridge.models import SeenTransferClient

    close_old_connections()

    targets = list(
        SeenTransferClient.objects.filter(
            zone_id=zone_id,
        ).values_list("address", "view__name").distinct()
    )

    if not targets:
        logger.debug("No transfer clients recorded for zone_id=%s", zone_id)
        return []

    result = [(ip, 53, view_name) for ip, view_name in targets]
    logger.debug(
        "Resolved %d NOTIFY targets for zone_id=%s: %s",
        len(result), zone_id, result,
    )
    return result


def _build_soa_rdata(zone):
    """
    Build a dns.rdata SOA from a NetBox Zone, or None if the zone is missing.

    The Answer-section SOA in a NOTIFY message tells the secondary the new
    serial without it needing a follow-up SOA query. RFC 1996 § 3.7
    recommends including it for that reason; secondaries without it (bind
    logs "no serial") fall back to an SOA query, which works but is slower
    and noisier in logs.
    """
    if zone is None:
        return None

    # NetBox stores the SOA fields as zone.soa_mname / .soa_rname / etc.
    # (see netbox_dns/models/zone.py). Construct the wire-format SOA
    # using these values.
    mname = str(zone.soa_mname.fqdn).rstrip(".") + "."
    rname = zone.soa_rname.rstrip(".") + "."
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        f"{mname} {rname} {zone.soa_serial} {zone.soa_refresh} "
        f"{zone.soa_retry} {zone.soa_expire} {zone.soa_minimum}",
    )


def notify_zone(zone_id, zone_name, tsig_keyring=None, tsig_view_map=None):
    """
    Send DNS NOTIFY to all known transfer clients for a zone.

    Args:
        zone_id: NetBox zone primary key
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        tsig_view_map: Optional dict of {view_name_str: dns.name.Name} mapping
            view names to TSIG key names for per-target key selection.
    """
    targets = resolve_notify_targets(zone_id)
    if not targets:
        return

    # Fetch the Zone once and pass its SOA into every send. The SOA is
    # included in the Answer section so secondaries don't need to follow
    # up with an SOA query (RFC 1996 § 3.7). Best-effort: if the zone
    # lookup fails, fall back to a question-only NOTIFY.
    soa_rdata = None
    try:
        from django.db import close_old_connections
        from netbox_dns.models import Zone

        close_old_connections()
        zone = Zone.objects.only(
            "soa_mname", "soa_rname", "soa_serial", "soa_refresh",
            "soa_retry", "soa_expire", "soa_minimum",
        ).select_related("soa_mname").get(pk=zone_id)
        soa_rdata = _build_soa_rdata(zone)
    except Exception:
        logger.exception("Could not load SOA for zone_id=%s; sending question-only NOTIFY", zone_id)

    for target, port, view_name in targets:
        # Select the TSIG key matching this target's view
        keyname = None
        if tsig_view_map and view_name:
            keyname = tsig_view_map.get(view_name)

        send_notify(zone_name, target, port, tsig_keyring, keyname=keyname, soa_rdata=soa_rdata)


def send_notify(zone_name, target, port, tsig_keyring=None, keyname=None, soa_rdata=None):
    """
    Send a DNS NOTIFY message for the given zone to a single target.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        target: IP address of secondary DNS server (e.g. "127.0.0.1")
        port: DNS port of secondary (typically 53)
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        keyname: Optional dns.name.Name specifying which key from the keyring to use.
            If None and the keyring has exactly one key, that key is used.
        soa_rdata: Optional dns.rdata SOA placed in the Answer section so the
            secondary learns the new serial without a follow-up SOA query.
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

        # Answer section: SOA RR with the new serial (RFC 1996 § 3.7).
        # Without this, secondaries fall back to a separate SOA query
        # ("no serial" in bind's log). The query still works but is
        # slower and double-the-roundtrips.
        if soa_rdata is not None:
            answer_rrset = notify_msg.find_rrset(
                dns.message.ANSWER,
                qname,
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
                create=True,
            )
            answer_rrset.add(soa_rdata, ttl=0)

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
