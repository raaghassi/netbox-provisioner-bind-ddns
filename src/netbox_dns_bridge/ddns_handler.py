"""
RFC 2136 Dynamic DNS UPDATE handler for NetBox.

Accepts DNS UPDATE messages (opcode 5), authenticated via TSIG,
and translates them into netbox_dns Record create/delete operations.
"""
import logging
import socket
import socketserver
import threading
import uuid
from typing import TYPE_CHECKING, Union

import dns.flags
import dns.message

if TYPE_CHECKING:
    from .dns_server import ThreadingUDPDNSServer, ThreadingTCPDNSServer
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
from django.db import close_old_connections, transaction

from netbox_dns.choices import RecordStatusChoices, ZoneStatusChoices
from netbox_dns.models import Record, Zone

from . import notify
from .notify_dispatcher import suppress_notify

logger = logging.getLogger("netbox_dns_bridge.ddns")


def _netbox_event_context():
    """
    Enter NetBox's request-processor stack so that Record.save() and
    .delete() trigger EventRules (webhooks).  Without this context,
    the core signal handlers see current_request == None and skip
    event enqueueing entirely.

    Uses NetBox's own apply_request_processors() context manager
    which handles all registered request processors.
    """
    from django.contrib.auth import get_user_model
    from utilities.request import NetBoxFakeRequest, apply_request_processors

    User = get_user_model()
    user = User.objects.filter(is_superuser=True).first()
    if user is None:
        user = User.objects.filter(is_staff=True).first()
    if user is None:
        raise RuntimeError(
            "netbox_dns_bridge: DDNS requires at least one superuser or staff user"
        )
    request = NetBoxFakeRequest({
        "META": {},
        "POST": {},
        "GET": {},
        "FILES": {},
        "COOKIES": {},
        "method": "POST",
        "path": "/ddns-update/",
        "user": user,
        "id": uuid.uuid4(),
    })

    return apply_request_processors(request)


class DDNSBaseHandler(socketserver.BaseRequestHandler):
    """
    Handles RFC 2136 DNS UPDATE messages.

    Server attributes expected:
      self.server.keyring        - dict of dns.tsig.Key objects
      self.server.tsig_view_map  - dict mapping key name str -> View object
      self.server.allowed_zones  - set of zone name strings (without trailing dot)
      self.server.ddns_tag       - Tag object for tagging DDNS records
    """
    if TYPE_CHECKING:
        server: Union["ThreadingUDPDNSServer", "ThreadingTCPDNSServer"]  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Transport (override in subclasses)
    # ------------------------------------------------------------------

    def _send_response(self, data):
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def _handle_update(self, wire):
        close_old_connections()
        peer = self.client_address[0]

        # ---- Parse with TSIG validation ----
        try:
            message = dns.message.from_wire(
                wire,
                keyring=self.server.keyring,
                continue_on_error=False,
                ignore_trailing=True,
            )
        except dns.tsig.BadSignature:
            logger.warning("DDNS REFUSED from %s: bad TSIG signature", peer)
            self._deny_bad_tsig(wire, dns.tsig.BADSIG)  # type: ignore[attr-defined]
            return
        except dns.message.UnknownTSIGKey:
            logger.warning("DDNS REFUSED from %s: unknown TSIG key", peer)
            self._deny_bad_tsig(wire, dns.tsig.BADKEY)  # type: ignore[attr-defined]
            return
        except dns.tsig.BadAlgorithm:
            logger.warning("DDNS REFUSED from %s: bad TSIG algorithm", peer)
            self._deny_bad_tsig(wire, dns.tsig.BADKEY)  # type: ignore[attr-defined]
            return
        except Exception:
            logger.exception("DDNS: failed to parse message from %s", peer)
            return

        # ---- Verify opcode is UPDATE ----
        if message.opcode() != dns.opcode.UPDATE:
            logger.warning("DDNS FORMERR from %s: opcode %s (expected UPDATE)", peer, dns.opcode.to_text(message.opcode()))
            self._send_rcode(message, dns.rcode.FORMERR)
            return

        # ---- Zone section (RFC 2136 Section 3.1.1) ----
        # The zone section re-uses the question section of the message.
        if len(message.question) != 1:
            self._send_rcode(message, dns.rcode.FORMERR)
            return

        zone_rrset = message.question[0]
        if zone_rrset.rdtype != dns.rdatatype.SOA:
            self._send_rcode(message, dns.rcode.FORMERR)
            return
        if zone_rrset.rdclass != dns.rdataclass.IN:
            self._send_rcode(message, dns.rcode.FORMERR)
            return

        zone_name = zone_rrset.name.to_text().rstrip(".")

        # ---- TSIG -> View mapping ----
        if not message.had_tsig or message.keyname is None:
            logger.warning("DDNS REFUSED from %s: no TSIG", peer)
            self._send_rcode(message, dns.rcode.REFUSED)
            return

        key_name = message.keyname.canonicalize().to_text()
        nb_view = self.server.tsig_view_map.get(key_name)
        if nb_view is None:
            logger.warning("DDNS REFUSED from %s: no view for key %s", peer, key_name)
            self._send_rcode(message, dns.rcode.REFUSED)
            return

        # ---- allowed_zones check ----
        if self.server.allowed_zones and zone_name not in self.server.allowed_zones:
            logger.warning("DDNS NOTAUTH from %s: zone %s not in allowed_zones", peer, zone_name)
            self._send_rcode(message, dns.rcode.NOTAUTH)
            return

        # ---- Look up zone in NetBox ----
        try:
            nb_zone = Zone.objects.get(
                name=zone_name,
                view=nb_view,
                status=ZoneStatusChoices.STATUS_ACTIVE,
            )
        except Zone.DoesNotExist:
            logger.warning("DDNS NOTAUTH from %s: zone %s (view %s) not in NetBox", peer, zone_name, nb_view.name)
            self._send_rcode(message, dns.rcode.NOTAUTH)
            return

        # ---- Per-zone DDNS toggle (custom field) ----
        if not nb_zone.cf.get("ddns_enabled", True):
            logger.warning("DDNS REFUSED from %s: zone %s has ddns_enabled=False", peer, zone_name)
            self._send_rcode(message, dns.rcode.REFUSED)
            return

        # ---- Process within a transaction ----
        # Suppress signal-based NOTIFY (we send it explicitly after commit).
        # Keep _netbox_event_context so other user-defined EventRules still fire.
        try:
            with suppress_notify():
                with _netbox_event_context():
                    with transaction.atomic():
                        # Section 3.2: Prerequisites
                        rcode = self._check_prerequisites(message, nb_zone)
                        if rcode != dns.rcode.NOERROR:
                            logger.info("DDNS prerequisite failed for %s from %s: %s", zone_name, peer, dns.rcode.to_text(rcode))
                            self._send_rcode(message, rcode)
                            return

                        # Section 3.4: Update
                        self._process_updates(message, nb_zone)

            logger.info("DDNS UPDATE %s from %s: OK", zone_name, peer)
            self._send_rcode(message, dns.rcode.NOERROR)

            # Send NOTIFY directly (no debounce — one UPDATE = one NOTIFY)
            threading.Thread(
                target=notify.notify_zone,
                kwargs={
                    "zone_name": zone_name,
                    "tsig_keyring": self.server.keyring,
                    "tsig_view_map": {
                        v.name: dns.name.from_text(k)
                        for k, v in self.server.tsig_view_map.items()
                    },
                },
                daemon=True,
            ).start()

        except Exception:
            logger.exception("DDNS UPDATE %s from %s: SERVFAIL", zone_name, peer)
            self._send_rcode(message, dns.rcode.SERVFAIL)

    # ------------------------------------------------------------------
    # RFC 2136 Section 3.2 — Prerequisite checking
    # ------------------------------------------------------------------

    def _check_prerequisites(self, message, nb_zone):
        """
        Check all prerequisites in the message.  Returns an rcode.

        Prerequisite encoding (RFC 2136 Section 3.2.4):

          class ANY,  type ANY,  empty rdata -> Name is in use          (fail: NXDOMAIN)
          class NONE, type ANY,  empty rdata -> Name is not in use      (fail: YXDOMAIN)
          class ANY,  type T,    empty rdata -> RRset exists (any val)  (fail: NXRRSET)
          class NONE, type T,    empty rdata -> RRset does not exist    (fail: YXRRSET)
          class IN,   type T,    rdata       -> RRset exists (exact)    (fail: NXRRSET)
        """
        # The prerequisite section re-uses the answer section.
        for rrset in message.answer:
            rel_name = self._relative_name(rrset.name.to_text().rstrip("."), nb_zone.name)
            rdtype_text = dns.rdatatype.to_text(rrset.rdtype)

            if rrset.rdclass == dns.rdataclass.ANY:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is in use
                    if not Record.objects.filter(
                        zone=nb_zone, name=rel_name,
                        status=RecordStatusChoices.STATUS_ACTIVE,
                    ).exists():
                        return dns.rcode.NXDOMAIN
                else:
                    # RRset exists (value independent)
                    if not Record.objects.filter(
                        zone=nb_zone, name=rel_name, type=rdtype_text,
                        status=RecordStatusChoices.STATUS_ACTIVE,
                    ).exists():
                        return dns.rcode.NXRRSET

            elif rrset.rdclass == dns.rdataclass.NONE:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is not in use
                    if Record.objects.filter(
                        zone=nb_zone, name=rel_name,
                        status=RecordStatusChoices.STATUS_ACTIVE,
                    ).exists():
                        return dns.rcode.YXDOMAIN
                else:
                    # RRset does not exist
                    if Record.objects.filter(
                        zone=nb_zone, name=rel_name, type=rdtype_text,
                        status=RecordStatusChoices.STATUS_ACTIVE,
                    ).exists():
                        return dns.rcode.YXRRSET

            elif rrset.rdclass == dns.rdataclass.IN:
                # RRset exists (value dependent)
                for rdata in rrset:
                    value = rdata.to_text()
                    if not Record.objects.filter(
                        zone=nb_zone, name=rel_name, type=rdtype_text, value=value,
                        status=RecordStatusChoices.STATUS_ACTIVE,
                    ).exists():
                        return dns.rcode.NXRRSET

            else:
                return dns.rcode.FORMERR

        return dns.rcode.NOERROR

    # ------------------------------------------------------------------
    # RFC 2136 Section 3.4 — Update processing
    # ------------------------------------------------------------------

    def _process_updates(self, message, nb_zone):
        """
        Process the update section of the message.

        Update encoding (RFC 2136 Section 3.4.2):

          class IN,   rdata present -> Add to RRset
          class ANY,  type T,  empty -> Delete RRset
          class ANY,  type ANY, empty -> Delete all RRsets from name
          class NONE, rdata present  -> Delete individual RR
        """
        ddns_tag = self.server.ddns_tag

        # The update section re-uses the authority section.
        for rrset in message.authority:
            rel_name = self._relative_name(rrset.name.to_text().rstrip("."), nb_zone.name)
            rdtype_text = dns.rdatatype.to_text(rrset.rdtype)

            # Section 3.4.2.4: Never touch SOA or NS at the zone apex
            if rel_name == "@" and rrset.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS):
                continue

            if rrset.rdclass == dns.rdataclass.IN:
                # Add RRs
                ttl = rrset.ttl if rrset.ttl > 0 else None
                for rdata in rrset:
                    value = rdata.to_text()
                    self._add_record(nb_zone, rel_name, rdtype_text, value, ttl, ddns_tag)

            elif rrset.rdclass == dns.rdataclass.ANY:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Delete all RRsets from a name
                    self._delete_records_by_name(nb_zone, rel_name)
                else:
                    # Delete an RRset
                    self._delete_records_by_name_type(nb_zone, rel_name, rdtype_text)

            elif rrset.rdclass == dns.rdataclass.NONE:
                # Delete individual RR
                for rdata in rrset:
                    value = rdata.to_text()
                    self._delete_record(nb_zone, rel_name, rdtype_text, value)

    # ------------------------------------------------------------------
    # Record CRUD helpers
    # ------------------------------------------------------------------

    def _add_record(self, zone, name, rdtype, value, ttl, ddns_tag):
        """Create or update a DNS record.

        For A/AAAA records, any existing record with the same name and type
        is replaced (upsert) — DHCP lease renewals change the value and
        should not create duplicates.  For other types, exact-match
        deduplication is preserved so that multi-value RRsets (MX, NS, etc.)
        work correctly.
        """
        is_address = rdtype in ("A", "AAAA")

        if is_address:
            # Upsert: find by name+type, update value if changed
            existing = Record.objects.filter(
                zone=zone, name=name, type=rdtype,
            ).first()

            if existing:
                changed = False
                old_value = existing.value
                if existing.value != value:
                    existing.value = value
                    changed = True
                if existing.status != RecordStatusChoices.STATUS_ACTIVE:
                    existing.status = RecordStatusChoices.STATUS_ACTIVE
                    changed = True
                if ttl is not None and existing.ttl != ttl:
                    existing.ttl = ttl
                    changed = True
                if changed:
                    existing.save()
                    logger.debug("DDNS UPDATE %s %s %s -> %s zone=%s", name, rdtype, old_value, value, zone.name)
                return

        else:
            # Multi-value types: deduplicate on exact value match
            existing = Record.objects.filter(
                zone=zone, name=name, type=rdtype, value=value,
            ).first()

            if existing:
                changed = False
                if existing.status != RecordStatusChoices.STATUS_ACTIVE:
                    existing.status = RecordStatusChoices.STATUS_ACTIVE
                    changed = True
                if ttl is not None and existing.ttl != ttl:
                    existing.ttl = ttl
                    changed = True
                if changed:
                    existing.save()
                return

        record = Record(
            zone=zone,
            name=name,
            type=rdtype,
            value=value,
            ttl=ttl,
            status=RecordStatusChoices.STATUS_ACTIVE,
            disable_ptr=is_address,
        )
        record.save()

        # Tag after save (M2M requires saved PK)
        if ddns_tag is not None:
            record.tags.add(ddns_tag)

        logger.debug("DDNS ADD %s %s %s ttl=%s zone=%s", name, rdtype, value, ttl, zone.name)

    def _delete_records_by_name(self, zone, name):
        """Delete all records with the given name.

        Apex SOA/NS protection is handled by _process_updates (line 313),
        which skips SOA/NS at '@' before calling any delete method.  This
        method must not exclude NS at non-apex names — those are delegation
        records and are deletable per RFC 2136 §3.4.2.4.
        """
        records = Record.objects.filter(zone=zone, name=name)
        count = 0
        for record in records:
            record.delete()
            count += 1
        if count:
            logger.debug("DDNS DEL name=%s: %d records zone=%s", name, count, zone.name)

    def _delete_records_by_name_type(self, zone, name, rdtype):
        """Delete all records with the given name and type."""
        records = Record.objects.filter(zone=zone, name=name, type=rdtype)
        count = 0
        for record in records:
            record.delete()
            count += 1
        if count:
            logger.debug("DDNS DEL name=%s type=%s: %d records zone=%s", name, rdtype, count, zone.name)

    def _delete_record(self, zone, name, rdtype, value):
        """Delete a specific record matching name+type+value."""
        records = Record.objects.filter(zone=zone, name=name, type=rdtype, value=value)
        count = 0
        for record in records:
            record.delete()
            count += 1
        if count:
            logger.debug("DDNS DEL name=%s type=%s value=%s zone=%s", name, rdtype, value, zone.name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _relative_name(self, fqdn, zone_name):
        """Convert an FQDN to a name relative to the zone, or '@' for zone apex."""
        # Strip any trailing dot for comparison
        fqdn_clean = fqdn.rstrip(".")
        zone_clean = zone_name.rstrip(".")

        if fqdn_clean == zone_clean:
            return "@"

        suffix = "." + zone_clean
        if fqdn_clean.endswith(suffix):
            return fqdn_clean[: -len(suffix)]

        # Fallback: return as-is (should not happen for valid updates)
        return fqdn_clean

    def _send_rcode(self, query, rcode):
        """Build and send an UPDATE response with the given rcode."""
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        self._send_response(response.to_wire())

    def _deny_bad_tsig(self, wire, tsig_error):
        """Send REFUSED with TSIG error RR per RFC 2845 §4.3.

        Only attaches a TSIG error RR when we hold the key (BADSIG).
        For BADKEY/BADTIME the server cannot sign, so send REFUSED without TSIG.
        """
        try:
            query = dns.message.from_wire(
                wire, keyring={}, ignore_trailing=True, continue_on_error=True
            )
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.REFUSED)
            if query.had_tsig and query.keyname in self.server.keyring:
                response.use_tsig(
                    self.server.keyring,
                    keyname=query.keyname,
                    tsig_error=tsig_error,
                )
            self._send_response(response.to_wire(multi=False))
        except Exception:
            logger.debug("Failed to send TSIG error response")

# ------------------------------------------------------------------
# Transport subclasses
# ------------------------------------------------------------------


class DDNSUDPHandler(DDNSBaseHandler):
    def _send_response(self, data):
        sock = self.request[1]
        sock.sendto(data, self.client_address)

    def handle(self):
        data, _sock = self.request
        try:
            self._handle_update(data)
        except Exception:
            logger.exception("DDNS UDP error from %s", self.client_address[0])


class DDNSTCPHandler(DDNSBaseHandler):
    def _send_response(self, data):
        length = len(data).to_bytes(2, byteorder="big")
        self.request.sendall(length + data)

    def handle(self):
        sock = self.request
        sock.settimeout(10.0)
        try:
            while True:
                length_data = sock.recv(2)
                if not length_data:
                    return
                if len(length_data) < 2:
                    while len(length_data) < 2:
                        chunk = sock.recv(2 - len(length_data))
                        if not chunk:
                            return
                        length_data += chunk

                length = int.from_bytes(length_data, byteorder="big")
                wire = b""
                while len(wire) < length:
                    chunk = sock.recv(length - len(wire))
                    if not chunk:
                        return
                    wire += chunk
                self._handle_update(wire)
        except socket.timeout:
            pass
        except Exception:
            logger.exception("DDNS TCP error from %s", self.client_address[0])
