import threading

from django.conf import settings as django_settings
from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record
from .service.endpoint import catalog_zone_manager as catzm


def _notify_bind_for_record(record):
    """
    Send a NOTIFY to BIND for the zone containing this record.

    Called on REST API record create/update/delete so BIND re-transfers
    the zone promptly rather than waiting for the SOA refresh interval.
    notify_target/notify_port are read from PLUGINS_CONFIG at call time.
    """
    try:
        ddns_config = django_settings.PLUGINS_CONFIG.get("netbox_bind_ddns", {}).get("ddns", {})
        notify_target = ddns_config.get("notify_target")
        notify_port = int(ddns_config.get("notify_port", 53))
    except Exception:
        return

    if not notify_target:
        return

    try:
        zone_name = record.zone.name.rstrip(".")
    except Exception:
        return

    from .service.endpoint import notify
    threading.Thread(
        target=notify.send_notify,
        args=(zone_name, notify_target, notify_port),
        daemon=True,
    ).start()


@receiver(post_save, sender=Record)
def record_post_save(sender, instance, **kwargs):
    """Send NOTIFY to BIND when a DNS record is created or updated."""
    _notify_bind_for_record(instance)


@receiver(post_delete, sender=Record)
def record_post_delete(sender, instance, **kwargs):
    """Send NOTIFY to BIND when a DNS record is deleted."""
    _notify_bind_for_record(instance)


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
