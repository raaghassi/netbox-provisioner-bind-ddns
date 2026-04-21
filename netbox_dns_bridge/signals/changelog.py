"""IXFR changelog signal handlers — tracks record changes for incremental zone transfers."""
import logging

from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record

from ..models import ZoneChangelog

logger = logging.getLogger("netbox_dns_bridge.signals.changelog")


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
