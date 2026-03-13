import threading

import dns.name
import dns.tsig
from django.conf import settings as django_settings
from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from netbox_dns.models import Zone, Record
from .service.endpoint import catalog_zone_manager as catzm


def _build_tsig_keyring(tsig_config):
    """
    Build a {dns.name.Name: dns.tsig.Key} keyring from the tsig_keys plugin config.

    tsig_config is a dict keyed by view name:
      { "default": { "keyname": "mykey", "secret": "...", "algorithm": "hmac-sha512" }, ... }

    Returns None if config is missing or all entries are malformed.
    """
    if not tsig_config:
        return None
    keyring = {}
    for _view_name, data in tsig_config.items():
        try:
            raw_name = data["keyname"]
            secret = data["secret"]
            algorithm = data.get("algorithm", "hmac-sha256")
            key_name = dns.name.from_text(raw_name, origin=None).canonicalize()
            if not key_name.is_absolute():
                key_name = key_name.concatenate(dns.name.root)
            keyring[key_name] = dns.tsig.Key(name=key_name, secret=secret, algorithm=algorithm)
        except Exception:
            continue
    return keyring or None


def _notify_bind_for_record(record):
    """
    Send a TSIG-signed NOTIFY to BIND for the zone containing this record.

    Called on REST API record create/update/delete so BIND re-transfers
    the zone promptly rather than waiting for the SOA refresh interval.
    Config is read from PLUGINS_CONFIG at call time.
    """
    try:
        ddns_config = django_settings.PLUGINS_CONFIG.get("netbox_bind_ddns", {}).get("ddns", {})
        notify_target = ddns_config.get("notify_target")
        notify_port = int(ddns_config.get("notify_port", 53))
        tsig_config = django_settings.PLUGINS_CONFIG.get("netbox_bind_ddns", {}).get("tsig_keys", [])
    except Exception:
        return

    if not notify_target:
        return

    try:
        zone_name = record.zone.name.rstrip(".")
    except Exception:
        return

    tsig_keyring = _build_tsig_keyring(tsig_config)

    from .service.endpoint import notify
    threading.Thread(
        target=notify.send_notify,
        kwargs={
            "zone_name": zone_name,
            "target": notify_target,
            "port": notify_port,
            "tsig_keyring": tsig_keyring,
        },
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
