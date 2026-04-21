import logging
import threading
import time

import dns.name
import dns.tsig

from django.core.management.base import BaseCommand
from django.conf import settings
from django.db import close_old_connections
from netbox_dns.models import View
from netbox_bind_ddns.service.endpoint.request_handler import UDPRequestHandler, TCPRequestHandler
from netbox_bind_ddns.service.endpoint.dns_server import (
    UDPDNSServer, TCPDNSServer,
    ThreadingUDPDNSServer, ThreadingTCPDNSServer,
)
from netbox_bind_ddns.service.endpoint.ddns_handler import DDNSUDPHandler, DDNSTCPHandler
from netbox_bind_ddns.service.endpoint import catalog_zone_manager as catzm

logger = logging.getLogger("netbox_bind_ddns")


class Command(BaseCommand):
    help = "Run AXFR DNS transfer endpoint and optional DDNS receiver using NetBox DNS data"

    def load_settings(self):
        self.settings = settings.PLUGINS_CONFIG.get("netbox_bind_ddns", None)
        if not self.settings:
            raise RuntimeError(
                "netbox_bind_ddns: Plugin failed to initialize due to missing settings."
            )

        self.tsig_keys = self.settings.get("tsig_keys", None)
        if not self.tsig_keys:
            raise RuntimeError("netbox_bind_ddns: tsig_keys not set in plugin settings.")

    def load_tsig_key_settings(self):
        self.keyring = {}
        self.tsig_view_map = {}

        for view_name, data in self.tsig_keys.items():
            raw_key_name = data.get("keyname")
            secret = data.get("secret")
            algorithm_str = data.get("algorithm", "hmac-sha256")

            if not raw_key_name or not secret:
                logger.error(
                    "Skipping TSIG key for view %s: missing keyname or secret.", view_name
                )
                continue

            try:
                nb_view = View.objects.get(name=view_name)
            except View.DoesNotExist:
                logger.error(
                    "Skipping TSIG key %s: view '%s' not found.", raw_key_name, view_name
                )
                continue

            key_name_obj = dns.name.from_text(raw_key_name, origin=None).canonicalize()
            if not key_name_obj.is_absolute():
                key_name_obj = key_name_obj.concatenate(dns.name.root)
            key_name_str = key_name_obj.to_text()

            self.keyring[key_name_obj] = dns.tsig.Key(
                name=key_name_obj, secret=secret, algorithm=algorithm_str
            )
            self.tsig_view_map[key_name_str] = nb_view
            logger.debug("Loaded TSIG key: %s view: %s", key_name_str, nb_view.name)

        if not self.keyring:
            msg = "netbox_bind_ddns: No valid TSIG keys loaded."
            logger.critical(msg)
            raise RuntimeError(msg)

    def add_arguments(self, parser):
        parser.add_argument(
            "--port", type=int, default=5354, help="AXFR transfer endpoint port"
        )
        parser.add_argument(
            "--address", type=str, default="0.0.0.0", help="Listen address"
        )
        parser.add_argument(
            "--ddns-port", type=int, default=0,
            help="DDNS receiver port (0 = disabled)"
        )

    def _prune_changelog(self, retention):
        """Periodically prune ZoneChangelog entries beyond retention limit per zone."""
        from netbox_bind_ddns.models import ZoneChangelog

        while True:
            time.sleep(300)  # Run every 5 minutes
            # Drop any stale DB connection this daemon thread is holding.
            close_old_connections()
            try:
                zone_ids = (
                    ZoneChangelog.objects.values_list("zone_id", flat=True).distinct()
                )
                for zone_id in zone_ids:
                    count = ZoneChangelog.objects.filter(zone_id=zone_id).count()
                    if count > retention:
                        cutoff = (
                            ZoneChangelog.objects.filter(zone_id=zone_id)
                            .order_by("-serial", "-id")
                            .values_list("id", flat=True)[retention:]
                        )
                        deleted, _ = ZoneChangelog.objects.filter(
                            id__in=list(cutoff)
                        ).delete()
                        if deleted:
                            logger.info(
                                "Pruned %d changelog entries for zone_id=%s",
                                deleted, zone_id,
                            )
            except Exception:
                logger.exception("Error pruning ZoneChangelog")

    def handle(self, *args, **options):
        port = options["port"]
        address = options["address"]
        ddns_port = options["ddns_port"]

        # Initialize catalog zone manager
        catzm.init()

        # Load settings and TSIG keys
        self.load_settings()
        self.load_tsig_key_settings()

        # ---- Changelog pruning ----
        axfr_config = self.settings.get("axfr", {})
        retention = axfr_config.get("ixfr_changelog_retention", 1000)
        threading.Thread(
            target=self._prune_changelog, args=(retention,), daemon=True
        ).start()
        logger.info("IXFR changelog pruning active (retention=%d per zone)", retention)

        # ---- AXFR servers ----
        ixfr_as_axfr = axfr_config.get("ixfr_as_axfr", False)

        udp_server = UDPDNSServer(
            (address, port), UDPRequestHandler, self.keyring, self.tsig_view_map,
            ixfr_as_axfr=ixfr_as_axfr,
        )
        tcp_server = TCPDNSServer(
            (address, port), TCPRequestHandler, self.keyring, self.tsig_view_map,
            ixfr_as_axfr=ixfr_as_axfr,
        )

        udp_thread = threading.Thread(
            target=udp_server.serve_forever, daemon=True
        )
        udp_thread.start()
        logger.info("AXFR endpoint listening on %s udp/%d", address, port)

        # ---- DDNS servers (new) ----
        if ddns_port > 0:
            ddns_config = self.settings.get("ddns", {})
            allowed_zones = set(ddns_config.get("allowed_zones", []))

            # Ensure the ddns tag exists
            from extras.models import Tag
            ddns_tag, created = Tag.objects.get_or_create(
                name="ddns",
                defaults={
                    "color": "9e9e9e",
                    "description": "Created by DDNS update (RFC 2136)",
                },
            )
            if created:
                logger.info("Created 'ddns' tag in NetBox")

            ddns_udp = ThreadingUDPDNSServer(
                (address, ddns_port), DDNSUDPHandler,
                self.keyring, self.tsig_view_map,
                allowed_zones=allowed_zones,
                ddns_tag=ddns_tag,
            )
            ddns_tcp = ThreadingTCPDNSServer(
                (address, ddns_port), DDNSTCPHandler,
                self.keyring, self.tsig_view_map,
                allowed_zones=allowed_zones,
                ddns_tag=ddns_tag,
            )

            threading.Thread(target=ddns_udp.serve_forever, daemon=True).start()
            threading.Thread(target=ddns_tcp.serve_forever, daemon=True).start()
            logger.info("DDNS receiver listening on %s:%d (UDP+TCP)", address, ddns_port)

        # AXFR TCP server runs on main thread (blocking)
        logger.info("AXFR endpoint listening on %s tcp/%d", address, port)
        tcp_server.serve_forever()
