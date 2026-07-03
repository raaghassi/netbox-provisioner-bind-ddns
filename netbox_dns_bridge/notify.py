"""
DNS NOTIFY sender.

Sends NOTIFY messages to secondary DNS servers so they re-transfer
zones promptly rather than waiting for the SOA refresh interval.

Notify targets come from two sources, unioned:

  1. SeenTransferClient records — IPs that have previously performed a
     successful zone transfer (AXFR/IXFR). This is the PRIMARY mechanism: it
     discovers a *dynamic* population of secondaries with zero NetBox-side
     bookkeeping. That population churns — a secondary registers by transferring
     and may later disappear (it is restarted, replaced, renumbered, or
     decommissioned) — so a target being unreachable is an EXPECTED, routine
     condition, not an error. The
     NOTIFY path therefore degrades gracefully: failures are isolated per
     target (one dead target never blocks or starves a live one), sends are
     retried within a short window, and dead entries are pruned per a
     configurable strategy so the population self-cleans (a returning secondary
     simply re-registers on its next transfer).

  2. StaticNotifyTarget rows — operator-defined fixed targets managed in NetBox
     (UI/REST), e.g. a stable Service VIP or an out-of-band secondary that never
     transfers through this endpoint. These are ADDITIVE to (not a replacement
     for) the dynamic discovery, are notified on every cycle, and are never
     pruned (the operator owns their lifecycle).

Tuning and pruning options are read from the NotifyConfig singleton model
(also managed in NetBox UI/REST); when no row exists yet the model's field
defaults apply. NetBox is the sole source of truth for both static targets and
tuning — these are NOT read from PLUGINS_CONFIG. See models.NotifyConfig /
models.StaticNotifyTarget.
"""
import ipaddress
import logging
import socket
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeout,
    as_completed,
)

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype

logger = logging.getLogger("netbox_dns_bridge.notify")

# Last-resort defaults, used only if the NotifyConfig read itself raises (e.g. a
# transient DB error). These mirror the NotifyConfig model field defaults so the
# sender stays functional rather than letting a settings-read failure abort an
# entire NOTIFY cycle (which would silently lose NOTIFY for the live targets).
_FALLBACK_SETTINGS = {
    "timeout": 2.0,
    "attempts": 2,
    "backoff": 0.5,
    "max_workers": 16,
    "prune_strategy": "ttl",
    "prune_max_failures": 5,
    "prune_ttl": 604800,
}


def _notify_settings():
    """
    Read NOTIFY tuning from the NotifyConfig singleton (NetBox DB).

    When no row exists, NotifyConfig.get_solo() returns a transient instance
    carrying the model field defaults (no write), so the sender behaves sanely
    on a fresh install until the config is seeded/edited in NetBox. Never raises:
    a read failure falls back to _FALLBACK_SETTINGS so it can't abort a cycle.
    """
    from django.db import close_old_connections
    from netbox_dns_bridge.models import NotifyConfig

    try:
        close_old_connections()
        c = NotifyConfig.get_solo()
        return {
            "timeout": float(c.timeout),
            "attempts": max(1, int(c.attempts)),
            "backoff": max(0.0, float(c.retry_backoff)),
            "max_workers": max(1, int(c.max_workers)),
            "prune_strategy": str(c.prune_strategy or "").lower(),
            "prune_max_failures": max(1, int(c.prune_max_failures)),
            "prune_ttl": max(0, int(c.prune_ttl)),
        }
    except Exception:
        logger.exception("Could not read NotifyConfig; using fallback defaults")
        return dict(_FALLBACK_SETTINGS)


def resolve_notify_targets(zone_id):
    """
    Look up SeenTransferClient entries for a zone to find dynamic NOTIFY targets.

    Returns a list of (client_id, ip, port, view_name) tuples — one per recorded
    transfer client for this zone. client_id is the SeenTransferClient pk, used
    later for per-target liveness bookkeeping and pruning. Port is always 53.

    Args:
        zone_id: NetBox zone primary key
    """
    from django.db import close_old_connections
    from netbox_dns_bridge.models import SeenTransferClient

    try:
        close_old_connections()
        rows = list(
            SeenTransferClient.objects.filter(
                zone_id=zone_id,
            ).values_list("pk", "address", "view__name")
        )
    except Exception:
        logger.exception("Could not resolve dynamic NOTIFY targets for zone_id=%s", zone_id)
        return []

    if not rows:
        logger.debug("No transfer clients recorded for zone_id=%s", zone_id)
        return []

    result = [(pk, ip, 53, view_name) for pk, ip, view_name in rows]
    logger.debug(
        "Resolved %d dynamic NOTIFY targets for zone_id=%s: %s",
        len(result), zone_id, result,
    )
    return result


def _resolve_static_address(address):
    """
    Resolve a static target's address to one or more IP literals.

    dns.query.udp() requires an IP, not a hostname — so a static target given as
    a DNS name (e.g. "ns2.example.com") is resolved here to its current
    address(es); an IP literal is returned as-is. Resolution failure is
    expected-and-tolerated (the name may be transiently unresolvable): it logs a
    warning and returns [] so the cycle simply skips that target gracefully.
    """
    try:
        ipaddress.ip_address(address)
        return [address]  # already an IP literal
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(address, None, proto=socket.IPPROTO_UDP)
        ips = sorted({info[4][0] for info in infos})
        if not ips:
            logger.warning("Static NOTIFY target %s resolved to no addresses; skipping", address)
        return ips
    except Exception as exc:
        logger.warning("Static NOTIFY target %s could not be resolved (%s); skipping", address, exc)
        return []


def _static_notify_targets(zone_view_name):
    """
    Build static (operator-defined) NOTIFY targets for a zone from the DB.

    Reads enabled StaticNotifyTarget rows (managed in NetBox UI/REST) and
    returns UNRESOLVED targets (None, address, port, view_name). Any hostname in
    `address` is resolved later, inside the per-target worker (see _send), so a
    slow/unreachable resolver for one static target cannot stall the rest of the
    cycle (dynamic OR static). A view-bound target only applies to zones in that
    view (so the correct per-view TSIG key is selected); a target with no view
    applies to every zone. client_id is None — static targets carry no
    SeenTransferClient row, so they're notified every cycle and never pruned.
    Never raises: a DB read failure logs and returns [] so it can't abort a
    cycle (the dynamic targets must still fire).

    Args:
        zone_view_name: the view name of the zone being notified (may be None)
    """
    from django.db import close_old_connections
    from netbox_dns_bridge.models import StaticNotifyTarget

    try:
        close_old_connections()
        rows = list(
            StaticNotifyTarget.objects.filter(enabled=True).values_list(
                "address", "port", "view__name"
            )
        )
    except Exception:
        logger.exception("Could not read static NOTIFY targets")
        return []

    out = []
    seen = set()
    for address, port, target_view in rows:
        if not address:
            continue
        # A view-bound target only applies to zones in that view.
        if target_view and target_view != zone_view_name:
            continue
        if (address, port) in seen:
            continue
        seen.add((address, port))
        # Sign with the zone's own view key (resolution deferred to the worker).
        out.append((None, address, port, zone_view_name))
    return out


def _build_soa_rdata(zone):
    """
    Build a dns.rdata SOA from a NetBox Zone, or None if the zone is missing.

    The Answer-section SOA in a NOTIFY message tells the secondary the new
    serial without it needing a follow-up SOA query. RFC 1996 § 3.7
    recommends including it for that reason; secondaries without it (bind
    logs "no serial") fall back to an SOA query, which works but is slower
    and noisier in logs.
    """
    if zone is None:
        return None

    # NetBox stores the SOA fields as zone.soa_mname (FK to NameServer)
    # and .soa_rname (str). NameServer's __str__ returns the FQDN
    # without trailing dot; rstrip+re-append handles either form.
    mname = str(zone.soa_mname).rstrip(".") + "."
    rname = zone.soa_rname.rstrip(".") + "."
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        f"{mname} {rname} {zone.soa_serial} {zone.soa_refresh} "
        f"{zone.soa_retry} {zone.soa_expire} {zone.soa_minimum}",
    )


def _load_zone_meta(zone_id):
    """
    Fetch a zone's SOA rdata and view name in one query.

    Best-effort: returns (soa_rdata, view_name); either may be None if the
    lookup fails. The SOA feeds the Answer-section optimization (RFC 1996 §3.7);
    the view name selects the per-view TSIG key for static targets.
    """
    try:
        from django.db import close_old_connections
        from netbox_dns.models import Zone

        close_old_connections()
        zone = Zone.objects.only(
            "soa_mname", "soa_rname", "soa_serial", "soa_refresh",
            "soa_retry", "soa_expire", "soa_minimum", "view",
        ).select_related("soa_mname", "view").get(pk=zone_id)
        view_name = zone.view.name if zone.view_id else None
        return _build_soa_rdata(zone), view_name
    except Exception:
        logger.exception(
            "Could not load zone meta for zone_id=%s; sending question-only NOTIFY", zone_id
        )
        return None, None


def notify_zone(zone_id, zone_name, tsig_keyring=None, tsig_view_map=None):
    """
    Send DNS NOTIFY to all known targets for a zone, concurrently.

    Targets are the union of the dynamic SeenTransferClient population and any
    operator-defined static targets. Every target is notified on its own worker
    so one unreachable target can never block or delay another. After the cycle,
    per-target liveness is recorded and dead dynamic targets are pruned per the
    configured strategy. Static targets are notified but never pruned.

    Args:
        zone_id: NetBox zone primary key
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        tsig_view_map: Optional dict of {view_name_str: dns.name.Name} mapping
            view names to TSIG key names for per-target key selection.
    """
    try:
        _notify_zone_cycle(zone_id, zone_name, tsig_keyring, tsig_view_map)
    finally:
        # notify_zone is a dedicated-thread target (notify_dispatcher's
        # _fire_notify / flush_pending). The thread dies on return, but its
        # ORM connections would survive it: CONN_MAX_AGE=300 means
        # close_old_connections() treats them as current, and no later call
        # ever runs on a dead thread. Close them unconditionally — this was
        # one of the leak paths that exhausted postgres max_connections in
        # dev. (The _send pool workers do network only, no ORM.)
        from django.db import connections
        connections.close_all()


def _notify_zone_cycle(zone_id, zone_name, tsig_keyring, tsig_view_map):
    """One NOTIFY cycle; see notify_zone. Split out so the thread-exit
    connection cleanup wraps every return path in one place."""
    # Target construction is deliberately fault-isolated: each helper catches
    # its own errors and returns a safe value, so a failure building static
    # targets / reading config / loading SOA can never abort the dynamic NOTIFY.
    cfg = _notify_settings()
    dynamic = resolve_notify_targets(zone_id)
    soa_rdata, zone_view_name = _load_zone_meta(zone_id)
    static = _static_notify_targets(zone_view_name)

    targets = dynamic + static
    if not targets:
        return

    def _send(target):
        client_id, address, port, view_name = target
        keyname = None
        if tsig_view_map and view_name:
            keyname = tsig_view_map.get(view_name)
        # Resolve INSIDE the worker — passthrough for IP literals (dynamic
        # targets are always IPs), getaddrinfo for static hostnames. A slow
        # resolver thus ties up only this worker, never the whole cycle. A
        # static hostname may yield several IPs; notify each.
        ok = False
        for ip in _resolve_static_address(address):
            if send_notify(
                zone_name, ip, port, tsig_keyring,
                keyname=keyname, soa_rdata=soa_rdata,
                timeout=cfg["timeout"], attempts=cfg["attempts"], backoff=cfg["backoff"],
            ):
                ok = True
        return (client_id, address, view_name, ok)

    # Bound the whole cycle: one full send costs roughly
    # attempts*timeout + (attempts-1)*backoff; allow that plus slack, then stop
    # waiting and abandon stragglers. This keeps a zone with many dead targets
    # from blowing the atexit flush budget / running unbounded.
    overall_deadline = (
        cfg["attempts"] * cfg["timeout"]
        + max(0, cfg["attempts"] - 1) * cfg["backoff"]
        + 5.0
    )
    results = []
    max_workers = min(len(targets), cfg["max_workers"])
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nb-notify")
    try:
        futures = [executor.submit(_send, t) for t in targets]
        try:
            for fut in as_completed(futures, timeout=overall_deadline):
                try:
                    results.append(fut.result())
                except Exception:
                    logger.exception("NOTIFY worker crashed for zone %s", zone_name)
        except FuturesTimeout:
            logger.warning(
                "NOTIFY %s: cycle exceeded %.1fs deadline; recorded %d/%d targets, "
                "abandoning the rest (likely unreachable)",
                zone_name, overall_deadline, len(results), len(targets),
            )
    finally:
        # Cancel not-yet-started sends; don't block on running ones. A large
        # batch of dead targets thus can't run unbounded or hang shutdown.
        executor.shutdown(wait=False, cancel_futures=True)

    _record_notify_results(zone_id, zone_name, results, cfg)


def _record_notify_results(zone_id, zone_name, results, cfg):
    """
    Record per-target NOTIFY outcomes and prune dead dynamic targets.

    For each dynamic target (client_id is not None):
      - success → last_notify_ok = now, notify_failures = 0
      - failure → notify_failures += 1, then prune if the configured strategy
        says this target is dead.

    Updates use QuerySet.update()/F() so the model's auto_now `last_transfer`
    field is NOT touched — it must keep meaning "last real transfer", not "last
    NOTIFY". Static targets (client_id is None) are skipped here entirely.

    Prune strategies:
      "ttl"      — prune when there has been no successful NOTIFY (or, if a
                   target never ACKed one, no transfer) within notify_prune_ttl
                   seconds. Tolerates long-lived but quiet targets; only sheds
                   ones that have actually gone silent.
      "failures" — prune after notify_prune_max_failures consecutive failed
                   cycles. Faster shedding; one transient outage of that many
                   cycles will evict an otherwise-live target (it re-registers
                   on its next transfer).
      "none"     — never prune; just log. Combined with the per-send retry
                   window this gives "retry, never evict" behavior, leaning on
                   the secondary's own SOA-refresh as the backstop.
    """
    from django.db import close_old_connections
    from django.db.models import F
    from django.utils import timezone
    from netbox_dns_bridge.models import SeenTransferClient

    strategy = cfg["prune_strategy"]
    failed = [r for r in results if not r[3]]
    if failed:
        logger.info(
            "NOTIFY %s: %d/%d target(s) unreachable this cycle: %s",
            zone_name, len(failed), len(results), [r[1] for r in failed],
        )

    close_old_connections()
    now = timezone.now()

    for client_id, ip, view_name, ok in results:
        if client_id is None:
            continue  # static target — no bookkeeping, never pruned
        try:
            if ok:
                SeenTransferClient.objects.filter(pk=client_id).update(
                    last_notify_ok=now, notify_failures=0
                )
                continue

            SeenTransferClient.objects.filter(pk=client_id).update(
                notify_failures=F("notify_failures") + 1
            )
            client = SeenTransferClient.objects.filter(pk=client_id).first()
            if client is None:
                continue
            if _should_prune(client, strategy, cfg, now):
                logger.warning(
                    "Pruning dead NOTIFY target %s (zone_id=%s view=%s): "
                    "strategy=%s failures=%d last_notify_ok=%s",
                    ip, zone_id, view_name, strategy,
                    client.notify_failures, client.last_notify_ok,
                )
                client.delete()
        except Exception:
            logger.exception("Failed to record NOTIFY result for client_id=%s", client_id)


def _should_prune(client, strategy, cfg, now):
    """Decide whether a failed dynamic target should be pruned now."""
    if strategy == "failures":
        return (client.notify_failures or 0) >= cfg["prune_max_failures"]
    if strategy == "ttl":
        if cfg["prune_ttl"] <= 0:
            return False
        baseline = client.last_notify_ok or client.last_transfer
        if baseline is None:
            return False
        return (now - baseline).total_seconds() >= cfg["prune_ttl"]
    return False  # "none" or unknown — never prune


def send_notify(zone_name, target, port, tsig_keyring=None, keyname=None, soa_rdata=None,
                timeout=2.0, attempts=2, backoff=0.5):
    """
    Send a DNS NOTIFY message for the given zone to a single target.

    Retries up to `attempts` times within a short window (sleeping `backoff`
    between tries) before giving up — this absorbs transient unreachability so a
    momentarily-busy secondary isn't treated as dead. A target being unreachable
    is expected in a churning population, so the final give-up is logged as a
    clean WARNING (not an exception traceback) and the function returns False;
    the caller isolates this so it never affects other targets.

    Returns:
        True  if the target acknowledged the NOTIFY (any rcode — it's reachable).
        False if the target was unreachable after all attempts.

    Args:
        zone_name: Zone name without trailing dot (e.g. "mgmt.aghassi.net")
        target: IP address of secondary DNS server (e.g. "127.0.0.1")
        port: DNS port of secondary (typically 53)
        tsig_keyring: Optional dict of {dns.name.Name: dns.tsig.Key} for TSIG signing.
        keyname: Optional dns.name.Name specifying which key from the keyring to use.
            If None and the keyring has exactly one key, that key is used.
        soa_rdata: Optional dns.rdata SOA placed in the Answer section so the
            secondary learns the new serial without a follow-up SOA query.
        timeout: Per-attempt UDP timeout in seconds.
        attempts: Number of send attempts before declaring the target unreachable.
        backoff: Seconds to sleep between attempts.
    """
    try:
        notify_msg = _build_notify_message(zone_name, tsig_keyring, keyname, target, port, soa_rdata)
    except Exception:
        # A build failure (bad zone name, TSIG construction) is a real bug, not
        # an unreachable target — log it loudly and report failure.
        logger.exception("NOTIFY %s -> %s:%d could not be built", zone_name, target, port)
        return False

    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            response = dns.query.udp(notify_msg, target, port=port, timeout=timeout)
            rcode = response.rcode()
            if rcode == dns.rcode.NOERROR:
                logger.info(
                    "NOTIFY %s -> %s:%d rcode=NOERROR (attempt %d/%d)",
                    zone_name, target, port, attempt, attempts,
                )
            else:
                # Reachable, but the secondary rejected the NOTIFY (e.g. not
                # configured for this zone, ACL, or TSIG). This is NOT a
                # departed/unreachable target, so it still counts as reachable
                # (no failure, no prune) — surfaced as a warning so a persistent
                # misconfiguration is visible rather than silently "successful".
                logger.warning(
                    "NOTIFY %s -> %s:%d answered rcode=%s (reachable but rejected) "
                    "(attempt %d/%d)",
                    zone_name, target, port, dns.rcode.to_text(rcode), attempt, attempts,
                )
            return True
        except Exception as exc:
            last_err = exc
            if attempt < attempts:
                logger.debug(
                    "NOTIFY %s -> %s:%d attempt %d/%d failed (%s); retrying in %.1fs",
                    zone_name, target, port, attempt, attempts, exc, backoff,
                )
                if backoff:
                    time.sleep(backoff)

    logger.warning(
        "NOTIFY %s -> %s:%d unreachable after %d attempt(s): %s",
        zone_name, target, port, attempts, last_err,
    )
    return False


def _build_notify_message(zone_name, tsig_keyring, keyname, target, port, soa_rdata):
    """Construct the NOTIFY dns.message for a target (raises on malformed input)."""
    qname = dns.name.from_text(zone_name + ".")

    # Build NOTIFY message: opcode NOTIFY, AA flag, SOA question
    notify_msg = dns.message.Message()
    notify_msg.flags = dns.flags.AA | dns.opcode.to_flags(dns.opcode.NOTIFY)
    notify_msg.find_rrset(
        dns.message.QUESTION,
        qname,
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        create=True,
    )

    # Answer section: SOA RR with the new serial (RFC 1996 § 3.7).
    # Without this, secondaries fall back to a separate SOA query
    # ("no serial" in bind's log). The query still works but is
    # slower and double-the-roundtrips.
    if soa_rdata is not None:
        answer_rrset = notify_msg.find_rrset(
            dns.message.ANSWER,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            create=True,
        )
        answer_rrset.add(soa_rdata, ttl=0)

    if tsig_keyring:
        if keyname and keyname in tsig_keyring:
            # Use the specific key for this target's view
            notify_msg.use_tsig(tsig_keyring, keyname=keyname)
        elif len(tsig_keyring) == 1:
            # Single key — no ambiguity
            notify_msg.use_tsig(tsig_keyring)
        else:
            logger.warning(
                "NOTIFY %s -> %s:%d: multiple TSIG keys but no view mapping; "
                "sending unsigned",
                zone_name, target, port,
            )

    return notify_msg
