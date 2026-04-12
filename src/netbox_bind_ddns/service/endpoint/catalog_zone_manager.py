import logging
import threading
from typing import Optional
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes
import dns.renderer
import dns.tsigkeyring
import dns.zone
from netbox_dns.models import Zone
from netbox_dns.choices import ZoneStatusChoices
from netbox_bind_ddns.models import IntegerKeyValueSetting, CatalogZoneMemberIdentifier
from uuid import uuid4
from base64 import b32encode

logger = logging.getLogger("netbox_bind_ddns.catz")

_LOCK = threading.Lock()
_SERIAL_MAX = 0xFFFFFFFF
_SERIAL_OBJ: Optional[IntegerKeyValueSetting] = None
_PREVIOUS_LAST_ZONE_UPDATE = None


def init() -> None:
    _init_serial()
    _create_missing_member_identifiers()


def _init_serial() -> None:
    global _SERIAL_OBJ

    try:
        obj = IntegerKeyValueSetting.objects.get(key="catalog-zone-soa-serial")
        logger.debug(
            f"Catalog zone SOA serial number {obj.value} loaded from database"
        )
    except IntegerKeyValueSetting.DoesNotExist:
        obj = IntegerKeyValueSetting.objects.create(
            key="catalog-zone-soa-serial", value=1
        )
        logger.debug(
            f"Catalog zone SOA serial number was not set in the database. Set to {obj.value}"
        )
    _SERIAL_OBJ = obj


def _increment_serial() -> None:
    assert _SERIAL_OBJ is not None, "_init_serial() must be called before _increment_serial()"
    obj = _SERIAL_OBJ
    current = obj.value
    if 0 < current < _SERIAL_MAX:
        obj.value = current + 1
        obj.save()
    else:
        logger.warning(
            f"Failed to increment catalog serial {current}. Will overflow serial back to 1"
        )
        obj.value = 1
        obj.save()
        logger.debug(
            f"Catalog zone SOA serial number incremented to {obj.value}"
        )


def _create_missing_member_identifiers() -> None:
   existing_zone_ids = CatalogZoneMemberIdentifier.objects.values_list(
       "zone_id", flat=True
   )

   missing_zones = Zone.objects.exclude(id__in=existing_zone_ids)

   new_objects = [
       CatalogZoneMemberIdentifier(
           zone=zone,
           name=_generate_member_identifier(),
       )
       for zone in missing_zones
   ]

   for identifier in new_objects:
       logger.debug(f"Zone {identifier.zone} has no catz member identifier. Creating...")

   CatalogZoneMemberIdentifier.objects.bulk_create(
       new_objects,
       ignore_conflicts=False,
   )


def create_zone(name, view_name) -> dns.zone.Zone:
    global _PREVIOUS_LAST_ZONE_UPDATE
    with _LOCK:
        latest_zone = (
            Zone.objects.filter(status=ZoneStatusChoices.STATUS_ACTIVE)
            .order_by("-last_updated")
            .first()
        )

        last_zone_update = latest_zone.last_updated if latest_zone is not None else None

        if _PREVIOUS_LAST_ZONE_UPDATE != last_zone_update:
            if latest_zone is not None:
                logger.debug(
                    f"Zone {latest_zone.name} was updated in view {latest_zone.view.name}"
                )
            _PREVIOUS_LAST_ZONE_UPDATE = last_zone_update
            _increment_serial()

    # Zone origin
    origin = dns.name.from_text(name, dns.name.root)

    # Create a new empty zone
    zone = dns.zone.Zone(origin)
    zone.rdclass = dns.rdataclass.IN

    # get zones from netbox
    nb_zones = Zone.objects.filter(
        view__name=view_name, status=ZoneStatusChoices.STATUS_ACTIVE
    ).select_related("catz_identifier")

    ptr_base = dns.name.from_text("zones", origin)

    for nb_zone in nb_zones:
        ttl = 0
        qname = dns.name.from_text(nb_zone.name, dns.name.root)

        p_name = nb_zone.catz_identifier.name

        ptr_name = dns.name.from_text(p_name, ptr_base)
        if not ptr_name.is_subdomain(origin):
            raise ValueError(
                f"Catalog zone member identifier {ptr_name.to_text()} not a subdomain"
            )
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.PTR, qname.to_text()
        )
        rdataset = zone.find_rdataset(ptr_name, dns.rdatatype.PTR, create=True)
        rdataset.add(rdata, ttl)

        # Configure DNSSec Policy for member Zone if DNSSec is enabled
        if nb_zone.dnssec_policy:
            rid = dns.name.from_text("group", ptr_name)
            policy_name = nb_zone.dnssec_policy.name.rstrip(" ")
            group_name = f"dnssec-policy-{policy_name}"
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.TXT, group_name
            )
            rdataset = zone.find_rdataset(rid, dns.rdatatype.TXT, create=True)
            rdataset.add(rdata, ttl)

    # SOA Record
    ttl = 0
    rclass = dns.rdataclass.IN
    rtype = dns.rdatatype.SOA
    mname = dns.name.from_text("invalid", dns.name.root)
    rname = dns.name.from_text("invalid", dns.name.root)
    assert _SERIAL_OBJ is not None, "_init_serial() must be called before create_zone()"
    serial = _SERIAL_OBJ.value
    refresh = 60
    retry = 10
    expire = 1209600
    minimum = 0

    soa_rdata = dns.rdata.from_text(
        rclass,
        rtype,
        f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
    )

    soa_rdataset = dns.rdataset.Rdataset(rclass, rtype)
    soa_rdataset.add(soa_rdata, ttl)

    node = zone.find_node(origin, create=True)
    node.rdatasets.append(soa_rdataset)

    # NS record
    ns_name = dns.name.from_text("invalid", dns.name.root)
    ns_rdata = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.NS, str(ns_name)
    )
    ns_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.NS)
    ns_rdataset.add(ns_rdata, 0)

    ns_node = zone.find_node(origin, create=True)
    ns_node.rdatasets.append(ns_rdataset)

    # TXT record for version
    version_name = dns.name.from_text("version", origin)
    txt_rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"2"')

    txt_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.TXT)
    txt_rdataset.add(txt_rdata, 0)

    txt_node = zone.find_node(version_name, create=True)
    txt_node.rdatasets.append(txt_rdataset)

    return zone


def _generate_member_identifier() -> str:
    return b32encode(uuid4().bytes)[0:26].lower().decode('UTF-8')


def update_member_identifier(zone: Zone) -> None:
    CatalogZoneMemberIdentifier.objects.update_or_create(
        zone=zone,
        defaults={"name": _generate_member_identifier()},
    )
