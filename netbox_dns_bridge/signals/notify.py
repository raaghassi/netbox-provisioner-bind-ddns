"""DNS NOTIFY signal handlers — schedule NOTIFY to secondaries on record changes."""
import logging

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record

from ..notify_dispatcher import schedule_notify

logger = logging.getLogger("netbox_dns_bridge.signals.notify")


@receiver(post_save, sender=Record)
def record_post_save_notify(sender, instance, created, **kwargs):
    """Schedule DNS NOTIFY when records are created or modified."""
    try:
        if created:
            schedule_notify(instance.zone_id, instance.zone.name)
        else:
            old = getattr(instance, "_old_record", None)
            if old:
                ttl = instance.ttl or instance.zone.default_ttl
                changed = (
                    old["name"] != instance.name
                    or old["type"] != instance.type
                    or old["value"] != instance.value
                    or old["ttl"] != ttl
                    or old["zone_id"] != instance.zone_id
                )
                if changed:
                    schedule_notify(instance.zone_id, instance.zone.name)
                    # Zone move — notify old zone too
                    if old["zone_id"] != instance.zone_id:
                        try:
                            old_zone = Zone.objects.only("id", "name").get(pk=old["zone_id"])
                            schedule_notify(old_zone.id, old_zone.name)
                        except Zone.DoesNotExist:
                            pass
    except Exception:
        logger.exception("Failed to schedule NOTIFY (post_save)")


@receiver(post_delete, sender=Record)
def record_post_delete_notify(sender, instance, **kwargs):
    """Schedule DNS NOTIFY when records are deleted."""
    try:
        schedule_notify(instance.zone_id, instance.zone.name)
    except Exception:
        logger.exception("Failed to schedule NOTIFY (post_delete)")
