"""
Debounced DNS NOTIFY dispatcher.

Provides schedule_notify() for signal handlers and a suppress_notify
context manager for the DDNS handler to prevent double-firing.
"""
import logging
import threading

import dns.name
import dns.tsig

from . import notify

logger = logging.getLogger("netbox_bind_ddns.notify_dispatcher")

_lock = threading.Lock()
_pending: dict[str, threading.Timer] = {}
_tsig_keyring = None
_suppress = threading.local()

DEBOUNCE_SECONDS = 2.0


def get_tsig_keyring():
    """Lazy-build TSIG keyring from plugin settings, cached after first call."""
    global _tsig_keyring
    if _tsig_keyring is not None:
        return _tsig_keyring

    from django.conf import settings

    plugin_cfg = settings.PLUGINS_CONFIG.get("netbox_bind_ddns", {})
    tsig_keys = plugin_cfg.get("tsig_keys", {})
    keyring = {}

    for _view_name, data in tsig_keys.items():
        raw_key_name = data.get("keyname")
        secret = data.get("secret")
        algorithm_str = data.get("algorithm", "hmac-sha256")

        if not raw_key_name or not secret:
            continue

        key_name_obj = dns.name.from_text(raw_key_name, origin=None).canonicalize()
        if not key_name_obj.is_absolute():
            key_name_obj = key_name_obj.concatenate(dns.name.root)

        keyring[key_name_obj] = dns.tsig.Key(
            name=key_name_obj, secret=secret, algorithm=algorithm_str
        )

    _tsig_keyring = keyring
    return _tsig_keyring


def schedule_notify(zone_name: str):
    """Schedule a debounced NOTIFY for a zone. Safe to call from signal handlers."""
    if getattr(_suppress, "active", False):
        return

    with _lock:
        existing = _pending.pop(zone_name, None)
        if existing:
            existing.cancel()
        timer = threading.Timer(DEBOUNCE_SECONDS, _fire_notify, args=(zone_name,))
        timer.daemon = True
        timer.start()
        _pending[zone_name] = timer


def _fire_notify(zone_name: str):
    """Called when debounce timer expires. Sends NOTIFY in a background thread."""
    with _lock:
        _pending.pop(zone_name, None)

    logger.debug("Debounce expired for zone %s — sending NOTIFY", zone_name)
    threading.Thread(
        target=notify.notify_zone,
        kwargs={"zone_name": zone_name, "tsig_keyring": get_tsig_keyring()},
        daemon=True,
    ).start()


class suppress_notify:
    """Context manager to suppress schedule_notify() calls on the current thread."""

    def __enter__(self):
        _suppress.active = True
        return self

    def __exit__(self, *exc):
        _suppress.active = False
