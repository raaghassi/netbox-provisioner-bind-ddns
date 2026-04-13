"""
DNS NOTIFY sender.

Sends NOTIFY messages to secondary DNS servers so they re-transfer
zones promptly rather than waiting for the SOA refresh interval.

Notify targets are resolved automatically from NS records in NetBox.
"""
import logging
import socket

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
    Look up NS records for a zone in NetBox and resolve each to IP addresses.

    Returns a list of (ip, port) tuples for all reachable nameservers.
    Port is always 53 (standard DNS).

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
    """
    from django.db import close_old_connections
    from netbox_dns.models import Record

    close_old_connections()

    targets = []

    # Find all active NS records for this zone
    ns_records = Record.objects.filter(
        zone__name=zone_name,
        type="NS",
        status="active",
    ).values_list("value", flat=True)

    if not ns_records:
        logger.warning("No NS records found in NetBox for zone %s", zone_name)
        return targets

    for ns_hostname in ns_records:
        ns_hostname = ns_hostname.rstrip(".")
        ips = _resolve_ns_hostname(ns_hostname)
        for ip in ips:
            targets.append((ip, 53))

    logger.debug(
        "Resolved %d NOTIFY targets for zone %s: %s",
        len(targets), zone_name, targets,
    )
    return targets


def _resolve_ns_hostname(hostname):
    """
    Resolve an NS hostname to IP addresses.

    Tries NetBox A/AAAA records first, falls back to system DNS resolution.
    Returns a list of IP address strings.
    """
    from netbox_dns.models import Record

    ips = []

    # Try all possible name/zone splits of the FQDN.
    # For "ns1.mgmt.aghassi.net", try name="ns1" zone="mgmt.aghassi.net",
    # then name="ns1.mgmt" zone="aghassi.net", etc.
    parts = hostname.split(".")
    for i in range(1, len(parts)):
        name = ".".join(parts[:i])
        zone_name = ".".join(parts[i:])
        nb_addrs = Record.objects.filter(
            zone__name=zone_name,
            name=name,
            type__in=["A", "AAAA"],
            status="active",
        ).values_list("value", flat=True)
        if nb_addrs:
            ips.extend(nb_addrs)
            logger.debug("Resolved NS %s via NetBox: %s", hostname, list(nb_addrs))
            return ips

    # Fall back to system DNS
    try:
        addrinfo = socket.getaddrinfo(hostname, 53, proto=socket.IPPROTO_UDP)
        for family, _type, _proto, _canon, sockaddr in addrinfo:
            ips.append(sockaddr[0])
        if ips:
            logger.debug("Resolved NS %s via DNS: %s", hostname, ips)
    except socket.gaierror:
        logger.warning("Could not resolve NS hostname %s", hostname)

    return ips


def notify_zone(zone_name, tsig_keyring=None):
    """
    Send DNS NOTIFY to all NS servers for a zone.

    Resolves targets automatically from NS records in NetBox.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
    """
    targets = resolve_notify_targets(zone_name)
    if not targets:
        logger.warning("No NOTIFY targets for zone %s — skipping", zone_name)
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
