# netbox-provisioner-bind-ddns — Fork Overview

Fork of [Suraxius/netbox-plugin-dns-bridge](https://github.com/Suraxius/netbox-plugin-dns-bridge) that keeps the upstream AXFR/catalog-zone provisioning and adds a writable receiver path so external systems (BIND, DHCP servers, etc.) can push record changes back into NetBox.

## What the fork adds over upstream

1. **RFC 2136 Dynamic DNS receiver** — accepts TSIG-authenticated UPDATE messages on a separate port (`--ddns-port`) and translates them into `netbox_dns.Record` create/update/delete operations. Implemented in `netbox_dns_bridge/ddns_handler.py`.
2. **RFC 1996 NOTIFY sender** — after record changes (REST, DDNS, or direct ORM), a debounced NOTIFY is dispatched to every IP that has successfully transferred the zone. Implemented in `netbox_dns_bridge/notify.py` and `netbox_dns_bridge/notify_dispatcher.py`, driven by `netbox_dns_bridge/signals/notify.py`.
3. **RFC 1995 IXFR responses** — incremental zone transfers backed by a `ZoneChangelog` journal that records each ADD/DELETE at its SOA serial. Falls back to AXFR when the changelog doesn't span the client's serial. Handler lives in `netbox_dns_bridge/request_handler.py::_handle_ixfr_request`; journal writes in `netbox_dns_bridge/signals/changelog.py`.
4. **Transfer-client tracking** — `SeenTransferClient` records every peer that completes an AXFR/IXFR so NOTIFY has a concrete target list (no NS-record guesswork, no hidden-master surprises).
5. **DDNS record tagging** — records created via DDNS are tagged `ddns` for easy filtering.
6. **Per-zone DDNS gating** — respects a `ddns_enabled` NetBox custom field on zones.

## Configuration shape

```python
PLUGINS_CONFIG = {
    "netbox_dns_bridge": {
        "tsig_keys": {
            "<view_name>": {
                "keyname": "transfer-key.",
                "secret": "…",
                "algorithm": "hmac-sha512",
            }
        },
        "axfr": {
            "ixfr_enabled": True,
            "ixfr_changelog_retention": 1000,
        },
        "ddns": {
            "allowed_zones": ["zone1.example.com"],
        },
    }
}
```

Launch with `python manage.py dns-transfer-endpoint --port 5354 --ddns-port 5355` (both ports bind TCP and UDP).

## Repo layout

Matches upstream: source at `netbox_dns_bridge/` (no `src/` prefix). Upstream-shared and fork-only files live side-by-side in the same package:

- **Shared with upstream** — `__init__.py`, `catalog_zone_manager.py`, `dns_server.py`, `request_handler.py`, `utils.py`, `models.py` (upstream models only), `management/commands/dns-export-zone.py`, `management/commands/dns-export-zones.py`, `management/commands/dns-settings.py`, the core of `management/commands/dns-transfer-endpoint.py`.
- **Fork-only** — `ddns_handler.py`, `notify.py`, `notify_dispatcher.py`, `signals/changelog.py`, `signals/notify.py`, the IXFR path in `request_handler.py`, `SeenTransferClient` and `ZoneChangelog` models, migrations `0002`–`0005`, the `--ddns-port` block in the transfer-endpoint command.
- **Renamed from upstream** — `signals/catalog.py` (upstream's `signals/transfer_endpoint.py`, renamed to work around upstream's broken `from . import catalog_zone_manager` import).

See [docs/fork-vs-upstream.md](docs/fork-vs-upstream.md) for a detailed file-by-file comparison.
