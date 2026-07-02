"""IXFR changelog signal handlers — tracks record changes for incremental zone transfers."""
import logging
import threading

from django.db.models.signals import pre_save, post_save, pre_delete, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record

from ..models import ZoneChangelog

logger = logging.getLogger("netbox_dns_bridge.signals.changelog")

# Zone pks currently being deleted, per thread. Django's deletion collector fires
# pre_delete for EVERY collected instance (the zone included) before it deletes any
# row, so by the time a cascading Record post_delete runs, the doomed zone is already
# marked here — regardless of whether the delete started at the zone itself, a
# queryset of zones, or a parent object (e.g. a View) cascading down. A zone-existence
# query cannot detect this: the collector deletes child Records BEFORE the zone row,
# so the zone still exists while the records' post_delete handlers run.
_deleting_zones = threading.local()


def _zones_being_deleted():
    ids = getattr(_deleting_zones, "ids", None)
    if ids is None:
        ids = _deleting_zones.ids = set()
    return ids


@receiver(pre_delete, sender=Zone)
def zone_pre_delete_mark(sender, instance, **kwargs):
    """Mark the zone as being deleted so record handlers skip journaling into it."""
    _zones_being_deleted().add(instance.pk)


@receiver(post_delete, sender=Zone)
def zone_post_delete_unmark(sender, instance, **kwargs):
    _zones_being_deleted().discard(instance.pk)


@receiver(post_save, sender=Zone)
def zone_post_save_unmark(sender, instance, **kwargs):
    """A zone that saves is not being deleted — clears a stale marker left behind
    if a delete attempt rolled back before its post_delete fired."""
    _zones_being_deleted().discard(instance.pk)


def _is_soa_record(record):
    """SOA records are IXFR protocol-level delimiters, not zone data.

    netbox_dns auto-creates an `@ SOA` Record alongside each Zone and bumps
    its serial as part of zone.update_serial(). Those saves fire post_save
    on Record exactly like any other record edit, and our changelog
    handlers used to pick them up as DELETE/ADD entries — making every
    serial transition produce a stray pair of SOA delete/add records in
    the IXFR difference sequence. RFC 1995 § 4 reserves SOA records for
    the open/close markers and the per-sequence boundary delimiters; the
    extra SOA inside the sequence body confuses bind ("failed while
    receiving responses: extra input data") and dnspython's IXFR client
    ("IXFR base serial mismatch"), forcing every IXFR to fall back to
    AXFR.

    Skip SOAs here — the IXFR builder constructs the delimiter SOAs
    itself from the zone's current/old serial, and the changelog
    journal carries only user-visible record changes.
    """
    return getattr(record, "type", None) == "SOA"


@receiver(pre_save, sender=Record)
def record_pre_save(sender, instance, **kwargs):
    """Cache old record values so post_save can detect changes for IXFR changelog."""
    if instance.pk:
        try:
            old = sender.objects.only("name", "type", "value", "ttl", "zone").get(pk=instance.pk)
            instance._old_record = {
                "name": old.name,
                "type": old.type,
                "value": old.value,
                "ttl": old.ttl or (old.zone.default_ttl if old.zone else 0),
                "zone_id": old.zone_id,
            }
        except sender.DoesNotExist:
            instance._old_record = None
    else:
        instance._old_record = None


@receiver(post_save, sender=Record)
def record_post_save(sender, instance, created, **kwargs):
    """Write IXFR changelog entries for incremental zone transfers.

    Entries are written with serial=0 (sentinel) because netbox_dns increments
    the zone SOA serial *after* post_save fires.  The zone_post_save_backfill_serial
    handler fills in the real serial once update_serial() saves.
    """
    if _is_soa_record(instance):
        return
    # A row journaled into a zone that is being deleted survives the cascade cleanup
    # (which already ran) and only fails the deferred FK check at COMMIT, rolling
    # back the whole delete — see record_post_delete.
    if instance.zone_id in _zones_being_deleted():
        return
    try:
        ttl = instance.ttl or instance.zone.default_ttl

        if created:
            ZoneChangelog.objects.create(
                zone=instance.zone,
                serial=0,
                action=ZoneChangelog.Action.ADD,
                name=instance.name,
                rdtype=instance.type,
                value=instance.value,
                ttl=ttl,
            )
        else:
            old = getattr(instance, "_old_record", None)
            if old:
                changed = (
                    old["name"] != instance.name
                    or old["type"] != instance.type
                    or old["value"] != instance.value
                    or old["ttl"] != ttl
                    or old["zone_id"] != instance.zone_id
                )
                if changed:
                    if old["zone_id"] not in _zones_being_deleted():
                        ZoneChangelog.objects.create(
                            zone_id=old["zone_id"],
                            serial=0,
                            action=ZoneChangelog.Action.DELETE,
                            name=old["name"],
                            rdtype=old["type"],
                            value=old["value"],
                            ttl=old["ttl"],
                        )
                    ZoneChangelog.objects.create(
                        zone=instance.zone,
                        serial=0,
                        action=ZoneChangelog.Action.ADD,
                        name=instance.name,
                        rdtype=instance.type,
                        value=instance.value,
                        ttl=ttl,
                    )
    except Exception:
        logger.exception("Failed to write IXFR changelog entry (post_save)")


@receiver(post_delete, sender=Record)
def record_post_delete(sender, instance, **kwargs):
    """Write IXFR changelog DELETE entry (serial=0 sentinel, backfilled by zone handler)."""
    if _is_soa_record(instance):
        return
    # Skip when the parent Zone is being deleted in the same transaction. The deletion
    # collector fast-deletes the zone's changelog rows first, then deletes its Records
    # (firing this handler) BEFORE the zone row itself — so the zone still exists here
    # and an existence query passes, but a row inserted now survives the cascade
    # cleanup and orphans once the zone row goes. Because the FK is DEFERRABLE
    # INITIALLY DEFERRED, the violation ("Key (zone_id)=N is not present in
    # netbox_dns_zone") only surfaces at COMMIT, rolling back the WHOLE delete and
    # leaving the zone undeletable via the UI. Hence the pre_delete marker instead of
    # an existence check. There's no IXFR diff to journal against a vanishing zone
    # anyway (bind drops the whole zone; its changelog rows cascade away with it).
    if instance.zone_id in _zones_being_deleted():
        return
    # Defensive: the zone can also be genuinely gone already on paths that delete
    # records outside a zone-delete cascade; nothing to journal against then either.
    if not Zone.objects.filter(pk=instance.zone_id).exists():
        return
    try:
        ttl = instance.ttl or instance.zone.default_ttl
        ZoneChangelog.objects.create(
            zone=instance.zone,
            serial=0,
            action=ZoneChangelog.Action.DELETE,
            name=instance.name,
            rdtype=instance.type,
            value=instance.value,
            ttl=ttl,
        )
    except Exception:
        logger.exception("Failed to write IXFR changelog entry (post_delete)")


@receiver(post_save, sender=Zone)
def zone_post_save_backfill_serial(sender, instance, **kwargs):
    """Backfill sentinel serial (0) in changelog entries with the real soa_serial.

    netbox_dns calls zone.update_serial() after Record.save(), which triggers
    Zone post_save with update_fields containing 'soa_serial'.  At that point
    instance.soa_serial holds the new value and we can update any pending
    changelog entries that were written with serial=0.
    """
    update_fields = kwargs.get("update_fields")
    if not update_fields or "soa_serial" not in update_fields:
        return

    try:
        updated = ZoneChangelog.objects.filter(
            zone=instance, serial=0
        ).update(serial=instance.soa_serial)
        if updated:
            logger.debug(
                "Backfilled %d changelog entries to serial %d for zone %s",
                updated, instance.soa_serial, instance.name,
            )
    except Exception:
        logger.exception("Failed to backfill changelog serials for zone %s", instance.name)
