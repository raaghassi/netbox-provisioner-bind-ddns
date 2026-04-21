# Fork vs Upstream: Style & Structure Differences

## Context

Comparing `netbox-provisioner-bind-ddns` (fork on `main`) against `Suraxius/netbox-plugin-dns-bridge` (upstream `main`). Goal: document differences, evaluate tradeoffs, recommend which approach to adopt so the fork can submit clean PRs.

---

## 1. Logging

### Upstream
- Custom `logger.py` module with `get_logger(name)` factory
- All modules use `from .logger import get_logger` then `logger = get_logger(__name__)`
- `get_logger()` ignores the `name` argument and always returns `logging.getLogger("dns-bridge")` (single logger for entire plugin)
- Has a **bug**: `__init__.py` line 9 does `logger = logger.get_logger(__name__)` — `logger` isn't assigned yet, causing `NameError`

### Fork
- No `logger.py` — uses stdlib `logging.getLogger()` directly
- Each module gets its own namespaced logger: `"netbox_dns_bridge.transfer"`, `"netbox_dns_bridge.catz"`, `"netbox_dns_bridge.ddns"`, etc.

### Analysis
| Criterion | Upstream | Fork |
|-----------|----------|------|
| Works at all | No (NameError bug) | Yes |
| Per-module filtering | No (single logger) | Yes (namespaced loggers) |
| Standard Python practice | No (custom wrapper) | Yes (stdlib) |
| Less code to maintain | No (extra module) | Yes |

### Recommendation
**Fork approach is strictly better.** The upstream `logger.py` is both buggy and adds no value — the commented-out code shows the author intended per-module loggers but abandoned it. Upstream should adopt the fork's pattern. **Drop `logger.py` entirely.**

---

## 2. Import hygiene

### Upstream
- Many unused imports scattered across files:
  - `dns-export-zone.py`: `os`, `dns.zone`, `dns.rdatatype`, `dns.rdataclass`, `dns.exception`
  - `dns-export-zones.py`: `dns.zone`, `dns.rdatatype`, `dns.rdataclass`, `dns.exception`
  - `dns-transfer-endpoint.py`: `dns.query`, `dns.message`, `dns.tsigkeyring`, `dns.zone`, `dns.rdatatype`, `dns.rdataclass`, `dns.rdtypes`, `dns.exception`, `dns.renderer`
  - `catalog_zone_manager.py`: `dns.query`, `dns.message`, `dns.tsigkeyring`, `dns.rdtypes`, `dns.exception`, `dns.renderer`
  - `models.py`: `import netbox.models` (unused)
- Imports are loosely ordered (no consistent stdlib → third-party → local grouping)

### Fork
- Only imports what's used
- Consistent ordering: stdlib → third-party → django → netbox → local

### Analysis
Unused imports increase load time slightly and confuse readers about actual dependencies. No functional benefit to keeping them.

### Recommendation
**Fork approach.** Clean imports are standard practice and make dependency auditing easier.

---

## 3. Threading model (`dns_server.py`)

### Upstream
```python
class TCPDNSServer(DNSAddressMixin, socketserver.TCPServer):
    allow_reuse_address = True
```

### Fork
```python
class TCPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
```

### Analysis
Without `ThreadingMixIn`, the TCP server handles one connection at a time — a slow client blocks all others. The UDP server has the same issue. For a DNS transfer endpoint serving multiple secondaries, this is a correctness bug, not just a style choice.

### Recommendation
**Fork approach is required.** Single-threaded DNS servers are unusable in production with multiple secondaries. `daemon_threads = True` prevents zombie threads on shutdown.

---

## 4. IPv6 sockaddr normalization (`dns_server.py`)

### Upstream
```python
return sockaddr  # Returns raw getaddrinfo() result
```

### Fork
```python
return (sockaddr[0], sockaddr[1])  # Normalize to 2-tuple
```

### Analysis
`socket.getaddrinfo()` returns 4-tuple `(host, port, flowinfo, scope_id)` for IPv6 (AF_INET6). `socketserver.TCPServer.__init__()` passes `server_address` to `socket.bind()`, which for AF_INET6 accepts a 4-tuple — so the upstream code actually works for both IPv4 and IPv6.

However, `socketserver` also stores `server_address` as a public attribute used by `server_close()` and subclass introspection. The 4-tuple can cause surprises downstream. The fork's 2-tuple normalization is safer and more predictable.

### Recommendation
**Fork approach is marginally safer.** The upstream technically works but the normalization prevents subtle downstream issues and makes the address consistent across families.

---

## 5. Error handling style

### Upstream
```python
except Exception as e:
    logger.error(f"Error handling request from {peer}: {e}")
    import traceback
    traceback.print_exc()
```

### Fork
```python
except Exception:
    logger.exception(f"Error handling request from {peer}")
```

### Analysis
| Criterion | Upstream | Fork |
|-----------|----------|------|
| Stack trace captured | Yes (to stdout) | Yes (to logger) |
| Respects logging config | No (prints to stdout) | Yes |
| Import at use site | Yes (anti-pattern) | No |
| Usable in daemon mode | No (stdout may be lost) | Yes |

### Recommendation
**Fork approach.** `logger.exception()` is the standard Python pattern — it captures the traceback through the logging framework so it goes to the configured handler (file, syslog, etc.) rather than being lost to stdout in daemon/systemd deployments.

---

## 6. TSIG error responses (`request_handler.py`)

### Upstream
```python
def _deny_request_bad_tsig(self, wire, tsig_error: dns.rcode) -> None:
    query = dns.message.from_wire(wire, keyring={}, ...)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.REFUSED)
    if query.had_tsig:
        response.use_tsig(keyring={}, keyname=query.keyname, tsig_error=tsig_error)
    self._send_response(response.to_wire())
```
- Always attaches TSIG error RR with empty keyring, even for BADKEY
- No try/except — if parsing fails, exception propagates

### Fork
```python
def _deny_request_bad_tsig(self, wire, tsig_error: dns.rcode.Rcode) -> None:
    try:
        query = dns.message.from_wire(wire, keyring={}, ...)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        if query.had_tsig and query.keyname in self.server.keyring:
            response.use_tsig(self.server.keyring, keyname=query.keyname, tsig_error=tsig_error)
        self._send_response(response.to_wire(multi=False))
    except Exception:
        logger.debug("Failed to send TSIG error response")
```
- Only attaches TSIG error RR when server holds the key (BADSIG) — per RFC 2845 §4.3, BADKEY responses should not have TSIG
- Wrapped in try/except for robustness
- Uses actual keyring for signing

### Analysis
RFC 2845 §4.3 states that when the server doesn't recognize the key (BADKEY), it cannot sign the response. The upstream attempts to sign with an empty keyring, which is technically a protocol violation. The fork correctly signs only when it holds the key (BADSIG case).

### Recommendation
**Fork approach.** It's RFC-correct and more robust.

---

## 7. `_handle_soa_request` BADKEY path

### Upstream
```python
response.use_tsig({}, keyname=query.keyname, tsig_error=dns.rcode.BADKEY)
```

### Fork
```python
response.use_tsig({}, keyname=query.keyname, tsig_error=dns.rcode.BADKEY)
```

### Analysis
Both upstream and fork use the same pattern here — empty keyring with BADKEY. This is inconsistent with the fork's improved `_deny_request_bad_tsig` which only signs when it holds the key. The SOA handler's BADKEY path should probably not attempt to attach TSIG at all (since the server doesn't hold the key), but both codebases have the same behavior here.

### Recommendation
**Neither is ideal.** Both should skip the `use_tsig()` call entirely for BADKEY in SOA responses, matching the fork's logic in `_deny_request_bad_tsig`. Minor issue — the empty keyring means dnspython won't actually produce a MAC, so the response is effectively unsigned regardless.

---

## 8. DB connection management

### Upstream
No `close_old_connections()` anywhere — the daemon threads reuse connections that may have been closed by the DB server (default MySQL/PostgreSQL timeout).

### Fork
```python
def _handle_dns_query(self, wire) -> None:
    close_old_connections()
    ...
```

### Analysis
NetBox's management commands run outside Django's request/response cycle, so Django's automatic connection cleanup doesn't apply. Long-running daemon threads will eventually hit stale connections. This is a production reliability bug in upstream.

### Recommendation
**Fork approach is required** for any deployment that runs longer than the DB's connection timeout (typically 5-10 minutes).

---

## 9. TXT record handling

### Upstream
Inline in `request_handler.py._getZoneFromNB()` — 10 lines of TXT quoting/chunking logic embedded in the record loop. Not available to `utils.py`/`export_bind_zone_file()`, which has **no TXT handling at all** (records >255 chars will fail silently or produce corrupt zone files).

### Fork
Extracted to `utils.py:format_txt_value()` — shared by both `_getZoneFromNB()` and `export_bind_zone_file()`.

### Analysis
The upstream has a TXT quoting bug in `request_handler.py`: the inner quote replacement `replace('"', '"')` is a no-op (replaces `"` with `"`). The fork's `format_txt_value()` correctly handles this: `replace('"', '')`.

DRY principle also applies — having TXT logic in two places (transfer and export) is error-prone.

### Recommendation
**Fork approach.** The extracted helper is correct, reusable, and fixes the upstream's quoting bug.

---

## 10. Zone export: TTL fallback and relativize

### Upstream (`utils.py`)
```python
rdata = dns.rdata.from_text(rdclass, rdatatype, record.value)
rdataset.add(rdata, record.ttl)
```
- No `relativize=False, origin=` — relative names in CNAME/MX/NS values won't resolve correctly
- Uses `record.ttl` directly — records with `ttl=None` will fail (dnspython requires int TTL)

### Fork (`utils.py`)
```python
rdata = dns.rdata.from_text(rdclass, rdatatype, value, relativize=False, origin=dp_zone.origin)
ttl = record.ttl or nb_zone.default_ttl
rdataset.add(rdata, ttl)
```

### Recommendation
**Fork approach.** Both fixes are necessary for correct zone file export.

---

## 11. Null safety for viewless zones

### Upstream
- `dns-export-zones.py`: `zone.view.name` — crashes with `AttributeError` if zone has no view
- `catalog_zone_manager.py`: `latest_zone.view.name` — crashes if most-recently-updated zone has no view

### Fork
- `dns-export-zones.py`: Guards with `if zone.view is None: continue`
- `catalog_zone_manager.py`: `latest_zone.view.name if latest_zone.view else '(no view)'`

### Recommendation
**Fork approach.** NetBox DNS allows viewless zones; the code must handle them.

---

## 12. AXFR multi-message wire sending

### Upstream
```python
self.request.sendall(len(wire).to_bytes(2, "big") + wire)
```
Bypasses `_send_response()` and accesses `self.request` directly — only works for TCP. If the send abstraction changes, this breaks silently.

### Fork
```python
self._send_response(wire)
```
Uses the transport-agnostic method consistently.

### Recommendation
**Fork approach.** Using the abstraction consistently prevents transport-coupling bugs.

---

## 13. Signal module structure

### Upstream
Single file `signals/transfer_endpoint.py` with zone pre_save/post_save for catalog zone identifiers.

### Fork
Three files:
- `signals/catalog.py` — zone pre_save/post_save (same logic as upstream, minor efficiency improvement with `.only("name")`)
- `signals/changelog.py` — record pre_save/post_save/post_delete for IXFR journal
- `signals/notify.py` — record post_save/post_delete for NOTIFY dispatch

### Analysis
The fork's split is necessary for its additional features (IXFR, NOTIFY). The upstream file naming (`transfer_endpoint.py`) describes the consumer, not the signal's purpose — `catalog.py` is a clearer name.

### Recommendation
**Fork approach for the fork's needs.** For upstream PRs, only the rename from `transfer_endpoint.py` → `catalog.py` and the `.only("name")` optimization are relevant.

---

## 14. Upstream signal import bug

### Upstream (`signals/transfer_endpoint.py`)
```python
from . import catalog_zone_manager as catzm
```
This is a **relative import from `signals/`**, but `catalog_zone_manager` is in the parent package `netbox_dns_bridge/`. This would raise `ImportError` at runtime.

### Fork (`signals/catalog.py`)
```python
from .. import catalog_zone_manager as catzm
```
Correct parent-relative import.

### Recommendation
**Fork approach.** The upstream has a broken import.

---

## 15. Type hints

### Upstream
- `_generate_member_identifier() -> None` (returns `str`)
- `_deny_request_bad_tsig(self, wire, tsig_error: dns.rcode)` (should be `dns.rcode.Rcode`)
- `_getZoneFromNB(...) -> dns.zone.Zone` (can return `None`)
- `_SERIAL_OBJ = None` (no type annotation — type checkers can't verify usage)

### Fork
- `-> str` (correct)
- `tsig_error: dns.rcode.Rcode` (correct)
- `-> Optional[dns.zone.Zone]` (correct)
- `_SERIAL_OBJ: Optional[IntegerKeyValueSetting] = None` with assertions before use

### Recommendation
**Fork approach.** Correct type hints enable static analysis and catch bugs early.

---

## 16. Comments and dead code

### Upstream
- Stale comments: `# Following function loads the last serial from the DB. No return value...`
- Commented-out code blocks: dnssec status config, old zone export sys.exit, logger per-module code
- Redundant comments: `# Create SOA rdata object`, `# Add to zone`, `# Load parameters`

### Fork
- No stale comments or commented-out code
- Comments only where logic is non-obvious

### Recommendation
**Fork approach.** Dead code and redundant comments are maintenance debt.

---

## 17. `pyproject.toml`

| Field | Upstream | Fork |
|-------|----------|------|
| `requires-python` | `>=3.7` | `>=3.10` |
| `description` | `"A bridge between..."` (generic) | `"...with DDNS and IXFR support."` |
| `license` | `{ file = "LICENSE.md" }` | `{ text = "MIT" }` |
| `project.urls` | Points to old repo name (`bind-provisioner`) | Points to upstream repo |
| `package-dir` | `{ "" = "." }` (explicit) | Not specified (default) |

### Analysis
- Python 3.7 is EOL (June 2023). NetBox 4.x requires Python 3.10+, so `>=3.7` is misleading.
- Upstream's project URLs still point to the old repo name — a bug.
- Fork's `{ text = "MIT" }` vs upstream's `{ file = "LICENSE.md" }` — both valid, file reference is more canonical.

### Recommendation
**Mixed.** Fork is correct on Python version. Upstream's `{ file = "LICENSE.md" }` license format is better practice. Both need URL fixes.

---

## Summary of Recommendations

| # | Area | Adopt | Rationale |
|---|------|-------|-----------|
| 1 | Logging | Fork | Upstream is buggy; fork uses stdlib correctly |
| 2 | Import hygiene | Fork | Unused imports add noise |
| 3 | ThreadingMixIn | Fork | Required for concurrent transfers |
| 4 | IPv6 sockaddr | Fork | Safer normalization |
| 5 | Error handling | Fork | `logger.exception()` over `traceback.print_exc()` |
| 6 | TSIG error responses | Fork | RFC 2845 compliant |
| 7 | SOA BADKEY | Neither | Both should skip TSIG for BADKEY |
| 8 | DB connections | Fork | Required for daemon reliability |
| 9 | TXT handling | Fork | Extracted helper, fixes quoting bug |
| 10 | TTL/relativize | Fork | Required for correct zone export |
| 11 | Null safety | Fork | NetBox allows viewless zones |
| 12 | AXFR wire send | Fork | Uses transport abstraction correctly |
| 13 | Signal structure | Fork | Clearer naming, necessary for features |
| 14 | Signal import | Fork | Upstream has broken import |
| 15 | Type hints | Fork | Correct annotations enable static analysis |
| 16 | Comments/dead code | Fork | Clean code, no maintenance debt |
| 17 | pyproject.toml | Mixed | Fork Python version, upstream license format |

**Overall: The fork's style and structure is better in every category.** The upstream has multiple bugs (NameError, broken import, quoting no-op, missing threading) that the fork has fixed, plus the fork follows Python best practices more consistently. For upstream PRs, the fixes should be re-authored against upstream's codebase in small, focused commits.
