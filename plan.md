# Plan: netbox-provisioner-bind-ddns Plugin

## What This Plugin Does

A NetBox plugin that provisions DNS zones to BIND via AXFR and catalog zones (inherited from upstream), extended with the ability to receive RFC 2136 dynamic DNS updates and write them into NetBox as DNS records.

### Capabilities

1. **Zone provisioning** (existing) — serves zones and catalog zones to BIND via AXFR on a configurable port
2. **DDNS receiver** (new) — accepts RFC 2136 UPDATE messages on a separate port, authenticated via TSIG
3. **Record management** (new) — creates, updates, and deletes `netbox_dns` Record objects based on incoming dynamic updates
4. **Record tagging** (new) — tags all dynamically-created records with a `ddns` tag to distinguish them from static records
5. **SOA serial management** (new) — increments the zone's SOA serial after processing updates
6. **BIND notification** (new) — sends DNS NOTIFY to BIND after updates so it re-transfers the affected zone promptly

## Steps

### Step 1: Populate repo and rename module

- Copy all source files from `netbox-plugin-bind-provisioner` into this repo
- Rename Python module from `netbox_plugin_bind_provisioner` to `netbox_bind_ddns`
- Update all internal imports, `pyproject.toml`, and `PluginConfig` metadata
- Commit as baseline

### Step 2: Create DDNS request handler

New file: `src/netbox_bind_ddns/service/endpoint/ddns_handler.py`

- Parse incoming DNS UPDATE messages (opcode UPDATE), validate TSIG
- Map TSIG key to NetBox DNS view
- Look up target zone in NetBox
- Process prerequisite section (RFC 2136 Section 3.2)
- Process update section (RFC 2136 Section 3.4) — create/delete `netbox_dns.models.Record` objects
- Tag created records with `ddns` (`extras.models.Tag`)
- Increment `zone.soa_serial` and save
- Return NOERROR response

### Step 3: Create NOTIFY sender

New file: `src/netbox_bind_ddns/service/endpoint/notify.py`

- Build and send a DNS NOTIFY message for a zone via UDP to a configurable target
- Run in a background thread so it doesn't block the UPDATE response

### Step 4: Add threaded DNS server classes

Modify `src/netbox_bind_ddns/service/endpoint/dns_server.py`:

- Add `ThreadingTCPDNSServer` and `ThreadingUDPDNSServer` using `socketserver.ThreadingMixIn`
- Used by the DDNS listener since update processing involves DB writes

### Step 5: Extend the management command

Modify `src/netbox_bind_ddns/management/commands/dns-transfer-endpoint.py`:

- Add `--ddns-port` argument (default: off)
- When provided, start additional threaded TCP/UDP servers using `DDNSRequestHandler`
- Read DDNS settings (allowed_zones, notify_target, notify_port) from `PLUGINS_CONFIG`

## Plugin Configuration

```python
PLUGINS_CONFIG = {
    "netbox_bind_ddns": {
        "tsig_keys": {
            "<view_name>": {
                "keyname": "...",
                "secret": "...",
                "algorithm": "hmac-sha512",
            }
        },
        "ddns": {
            "allowed_zones": ["zone1.example.com", "zone2.example.com"],
            "notify_target": "127.0.0.1",
            "notify_port": 53,
        }
    }
}
```

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `pyproject.toml` | Modify | New package name, module paths |
| `src/netbox_bind_ddns/` | Rename | From `netbox_plugin_bind_provisioner` |
| `src/netbox_bind_ddns/__init__.py` | Modify | PluginConfig name and metadata |
| `src/netbox_bind_ddns/service/endpoint/ddns_handler.py` | **New** | RFC 2136 UPDATE handler |
| `src/netbox_bind_ddns/service/endpoint/notify.py` | **New** | DNS NOTIFY sender |
| `src/netbox_bind_ddns/service/endpoint/dns_server.py` | Modify | Threaded server classes |
| `src/netbox_bind_ddns/management/commands/dns-transfer-endpoint.py` | Modify | `--ddns-port` argument |
