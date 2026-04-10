import logging

from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record
from .models import ZoneChangelog
from .service.endpoint import catalog_zone_manager as catzm

logger = logging.getLogger("netbox_bind_ddns.signals")


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
    """Write IXFR changelog entries for incremental zone transfers."""
    try:
        serial = instance.zone.soa_serial
        ttl = instance.ttl or instance.zone.default_ttl

        if created:
            ZoneChangelog.objects.create(
                zone=instance.zone,
                serial=serial,
                action="ADD",
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
                        serial=serial,
                        action="DELETE",
                        name=old["name"],
                        rdtype=old["type"],
                        value=old["value"],
                        ttl=old["ttl"],
                    )
                    ZoneChangelog.objects.create(
                        zone=instance.zone,
                        serial=serial,
                        action="ADD",
                        name=instance.name,
                        rdtype=instance.type,
                        value=instance.value,
                        ttl=ttl,
                    )
    except Exception:
        logger.exception("Failed to write IXFR changelog entry (post_save)")


@receiver(post_delete, sender=Record)
def record_post_delete(sender, instance, **kwargs):
    """Write IXFR changelog DELETE entry."""
    try:
        serial = instance.zone.soa_serial
        ttl = instance.ttl or instance.zone.default_ttl
        ZoneChangelog.objects.create(
            zone=instance.zone,
            serial=serial,
            action="DELETE",
            name=instance.name,
            rdtype=instance.type,
            value=instance.value,
            ttl=ttl,
        )
    except Exception:
        logger.exception("Failed to write IXFR changelog entry (post_delete)")


@receiver(pre_save, sender=Zone)
def zone_pre_save(sender, instance, **kwargs):
    """
    Cache the old name so post_save can see if it changed.
    """
    if instance.pk:
        try:
            instance._old_name = (
                sender.objects
                .only("name")
                .get(pk=instance.pk)
                .name
            )
        except sender.DoesNotExist:
            instance._old_name = None
    else:
        instance._old_name = None


@receiver(post_save, sender=Zone)
def sync_catalog_zone_identifier(sender, instance, created, **kwargs):
    """
    Ensure CatalogZoneMemberIdentifier exists for each Zone
    and keep its identifier in sync.
    """
    if created:
        catzm.update_member_identifier(instance)
    else:
        old_name = getattr(instance, "_old_name", None)

        if old_name == instance.name:
            return

        catzm.update_member_identifier(instance)
