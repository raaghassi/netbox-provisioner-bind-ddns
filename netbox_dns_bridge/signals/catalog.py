"""Catalog zone signal handlers — sync CatalogZoneMemberIdentifier on zone changes."""
import logging
import zlib

from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone

from .. import catalog_zone_manager as catzm
from ..models import NotifyConfig
from ..notify_dispatcher import schedule_notify

logger = logging.getLogger("netbox_dns_bridge.signals.catalog")


@receiver(pre_save, sender=Zone)
def zone_pre_save(sender, instance, **kwargs):
    """Cache the old name so post_save can see if it changed."""
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


def _notify_catalog_zones():
    """NOTIFY bind for each configured catalog zone so it re-AXFRs the catalog
    promptly on a membership change instead of waiting for the catalog SOA refresh.

    No-op unless NotifyConfig.catalog_zones is set. The catalog zone is not a NetBox
    Zone (no pk/view), so we use a stable NEGATIVE debounce key per name — which never
    collides with real positive zone PKs and coalesces a burst of membership changes
    into one NOTIFY — and the NOTIFY goes unsigned to the no-view static targets
    (notify_zone resolves an absent zone to no view, hence no TSIG).
    """
    try:
        raw = NotifyConfig.get_solo().catalog_zones or ""
    except Exception:
        logger.exception("Failed to read catalog_zones config")
        return
    for name in (n.strip().rstrip(".") for n in raw.split(",")):
        if not name:
            continue
        sentinel_id = -(zlib.crc32(name.encode()) & 0x7FFFFFFF) - 1
        try:
            schedule_notify(sentinel_id, name)
        except Exception:
            logger.exception("Failed to schedule catalog NOTIFY for %s", name)


@receiver(post_save, sender=Zone)
def zone_catalog_notify_on_save(sender, instance, created, **kwargs):
    """NOTIFY the catalog zone(s) on zone add / rename / status / dnssec-policy edits
    (all change catalog content). Skip the per-record soa_serial bump — netbox saves
    the zone with update_fields={'soa_serial', ...} on every record change, which does
    NOT change catalog membership."""
    update_fields = kwargs.get("update_fields")
    if not created and update_fields and set(update_fields) <= {"soa_serial", "last_updated"}:
        return
    _notify_catalog_zones()


@receiver(post_delete, sender=Zone)
def zone_catalog_notify_on_delete(sender, instance, **kwargs):
    """NOTIFY the catalog zone(s) on zone deletion so bind deprovisions the removed
    member promptly (paired with the count-aware catalog serial bump in
    catalog_zone_manager.create_zone)."""
    _notify_catalog_zones()
