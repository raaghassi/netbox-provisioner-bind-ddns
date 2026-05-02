"""
Debounced DNS NOTIFY dispatcher.

Provides schedule_notify() for signal handlers and a suppress_notify
context manager for the DDNS handler to prevent double-firing.

flush_pending() drains any debounced timers synchronously — registered
as an atexit hook so short-lived callers (one-shot management commands,
PostSync workflow scripts) don't lose NOTIFYs when the process exits
before the 2s debounce expires.
"""
import atexit
import logging
import threading

import dns.name
import dns.tsig

from . import notify

logger = logging.getLogger("netbox_dns_bridge.notify_dispatcher")

_lock = threading.Lock()
_pending: dict[int, tuple[threading.Timer, str]] = {}
_tsig_keyring = None
_tsig_view_map = None
_suppress = threading.local()
_atexit_registered = False

DEBOUNCE_SECONDS = 2.0
SHUTDOWN_NOTIFY_TIMEOUT_SECONDS = 10.0


def get_tsig_keyring():
    """Lazy-build TSIG keyring from plugin settings, cached after first call."""
    global _tsig_keyring
    with _lock:
        if _tsig_keyring is not None:
            return _tsig_keyring

        from django.conf import settings

        plugin_cfg = settings.PLUGINS_CONFIG.get("netbox_dns_bridge", {})
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


def get_tsig_view_map():
    """Lazy-build mapping from view name -> TSIG keyname, cached after first call.

    Returns a dict of {view_name_str: dns.name.Name} so callers can look up
    which TSIG key to use for a given DNS view.
    """
    global _tsig_view_map
    with _lock:
        if _tsig_view_map is not None:
            return _tsig_view_map

        from django.conf import settings

        plugin_cfg = settings.PLUGINS_CONFIG.get("netbox_dns_bridge", {})
        tsig_keys = plugin_cfg.get("tsig_keys", {})
        view_map = {}

        for view_name, data in tsig_keys.items():
            raw_key_name = data.get("keyname")
            if not raw_key_name:
                continue

            key_name_obj = dns.name.from_text(raw_key_name, origin=None).canonicalize()
            if not key_name_obj.is_absolute():
                key_name_obj = key_name_obj.concatenate(dns.name.root)

            view_map[view_name] = key_name_obj

        _tsig_view_map = view_map
        return _tsig_view_map


def schedule_notify(zone_id: int, zone_name: str):
    """Schedule a debounced NOTIFY for a zone. Safe to call from signal handlers."""
    if getattr(_suppress, "active", False):
        return

    global _atexit_registered
    with _lock:
        existing = _pending.pop(zone_id, None)
        if existing:
            existing[0].cancel()
        timer = threading.Timer(DEBOUNCE_SECONDS, _fire_notify, args=(zone_id, zone_name))
        timer.daemon = True
        timer.start()
        _pending[zone_id] = (timer, zone_name)

        # Register the atexit drain on first use. Doing this lazily means
        # processes that never schedule a NOTIFY (e.g. read-only management
        # commands) don't pay any registration cost. The flag avoids
        # double-registration when many records change in one process.
        if not _atexit_registered:
            atexit.register(flush_pending)
            _atexit_registered = True


def _fire_notify(zone_id: int, zone_name: str):
    """Called when debounce timer expires. Sends NOTIFY in a background thread."""
    with _lock:
        _pending.pop(zone_id, None)

    logger.debug("Debounce expired for zone %s — sending NOTIFY", zone_name)
    threading.Thread(
        target=notify.notify_zone,
        kwargs={
            "zone_id": zone_id,
            "zone_name": zone_name,
            "tsig_keyring": get_tsig_keyring(),
            "tsig_view_map": get_tsig_view_map(),
        },
        daemon=True,
    ).start()


def flush_pending():
    """
    Cancel any debounced timers and send their NOTIFYs synchronously.

    Registered as an atexit hook so short-lived callers (one-shot
    management commands, the PostSync workflow's `manage.py shell -c`)
    finish their NOTIFY work before the process exits and daemon
    threads die.

    Each NOTIFY is dispatched on its own thread so a single unreachable
    target doesn't stall the others; the function joins all of them
    with a per-target timeout cap.
    """
    with _lock:
        pending = list(_pending.values())
        _pending.clear()

    if not pending:
        return

    logger.info("Flushing %d pending NOTIFY(s) at shutdown", len(pending))

    threads = []
    for timer, zone_name in pending:
        # The timer may already have fired between the lock release and
        # cancel(); cancel() is a no-op in that case.
        timer.cancel()
        # Re-resolve the zone_id from the canceled timer's args so the
        # synchronous dispatch matches what _fire_notify would have done.
        zone_id = timer.args[0]
        t = threading.Thread(
            target=notify.notify_zone,
            kwargs={
                "zone_id": zone_id,
                "zone_name": zone_name,
                "tsig_keyring": get_tsig_keyring(),
                "tsig_view_map": get_tsig_view_map(),
            },
            daemon=False,  # block process exit until NOTIFY completes
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=SHUTDOWN_NOTIFY_TIMEOUT_SECONDS)


class suppress_notify:
    """Context manager to suppress schedule_notify() calls on the current thread."""

    def __enter__(self):
        _suppress.active = True
        return self

    def __exit__(self, *exc):
        _suppress.active = False
