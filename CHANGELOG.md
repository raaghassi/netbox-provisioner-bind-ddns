## 1.0.7 - 2026-03-02
README Change - Moving private keys to global scope since Bind 9.20 view scoped keys have become unreliable and sometimes wouldnt match.

## 1.0.8 - 2026-03-12
- Change License to MIT to match the netbox-plugin-dns License. This project rests on the netbox-plugin-dns so a matching
  license makes more sense.
- Renaming Project from Netbox Plugin Bind Provisioner to Netbox DNS Bridge as new code will be contributed that allows
  data to flow in both directions (Dynamic Updates), not just out of Netbox DNS.

## 1.5.0 - 2026-04-08
- Change to versioning scheme - Now matches the major and minor version number to the one of netbox-plugin-dns. Only the minor sub version
  will be used to track incremental changes to this plugin.

## 1.5.4 - 2026-05-02

- Include the SOA RR in the Answer section of NOTIFY messages
  (RFC 1996 § 3.7) so secondaries learn the new serial without an
  extra round-trip. Bind previously logged "no serial" for our
  NOTIFYs and fell back to an SOA query.
- Drain pending debounced NOTIFYs synchronously at process exit
  via an atexit hook. Short-lived callers (one-shot management
  commands, ArgoCD PostSync workflow scripts running
  `manage.py shell -c …`) used to lose NOTIFYs because the 2s
  debounce timer is a daemon thread and dies with the process.
  schedule_notify now lazily registers atexit on first use so
  zero-NOTIFY processes pay no overhead.

## 1.5.5 - 2026-05-02

- IXFR responses now use `dns.renderer.Renderer` + `add_multi_tsig`
  (the same path AXFR uses) instead of the simpler `dns.message`
  API. The latter produced wire-format that bind rejected with
  "failed while receiving responses: extra input data" — bind's
  zone-transfer parser expects multi-message-aware TSIG signing
  on IXFR even when the response fits in a single message.
  Bind now accepts our IXFR responses cleanly; AXFR fallback is
  no longer needed for every record change.

## 1.5.6 - 2026-05-02

- Skip SOA records when writing IXFR changelog entries. netbox_dns
  bumps the auto-managed `@ SOA` Record's serial via `update_serial()`
  on every change, which fires post_save and used to record DELETE
  + ADD SOA entries in our changelog. Those entries replayed back in
  the IXFR difference sequence as record-level deltas instead of the
  RFC 1995 boundary delimiters that the IXFR builder generates from
  the zone's serial transitions, producing two SOAs per delimiter
  (one real, one stray) and corrupting the wire format. Symptom on
  bind: "failed while receiving responses: extra input data" → AXFR
  fallback for every change. Symptom on dnspython: "IXFR base serial
  mismatch".
- IXFR builder also excludes `rdtype="SOA"` rows defensively so legacy
  changelog data already in the database doesn't corrupt the next IXFR
  served from a fixed plugin.

## 1.6.8 - 2026-07-02

- Fix zone deletion failing with `IntegrityError: insert or update on table
  "netbox_dns_bridge_zonechangelog" violates foreign key constraint ... Key
  (zone_id)=(N) is not present in table "netbox_dns_zone"`, which rolled back
  the delete and made zones undeletable from the UI. The 1.6.x guard checked
  whether the zone row still exists, but Django's deletion collector deletes a
  zone's Records (firing their post_delete) BEFORE the zone row itself — so the
  check always passed and the handler journaled a changelog row for the doomed
  zone after its changelog rows had already been cascade-deleted. With Django's
  DEFERRABLE INITIALLY DEFERRED foreign keys the orphaned insert only fails at
  COMMIT, which is also why the handler's try/except never caught it. Zones are
  now marked in a thread-local set by a Zone pre_delete receiver (fired by the
  collector before any row is deleted, including cascades from parent objects),
  and the record changelog handlers skip journaling into marked zones.

## 1.6.9 - 2026-07-03

- Fix a database connection leak in every short-lived thread the plugin
  spawns: the ThreadingMixIn per-request threads of the transfer endpoint
  (SOA/AXFR/IXFR) and DDNS receiver, and the per-NOTIFY dispatch threads.
  Each thread's first ORM query opened a connection that nothing ever
  closed — NetBox runs with CONN_MAX_AGE=300 (netbox-docker default), so
  the existing close_old_connections() calls treated fresh connections as
  current, and dead threads never call again. The endpoint leaked ~1 idle
  connection per hour in dev until postgres hit max_connections (100),
  locking the NetBox web UI out entirely ("remaining connection slots are
  reserved for roles with the SUPERUSER attribute"). Request handlers now
  close the thread's connections in socketserver's finish() hook (always
  runs, even when handle() raises) and notify_zone() closes on the way out
  of its dedicated thread, via django.db.connections.close_all().

## 1.6.10 - 2026-07-03

- Cap concurrent request threads in the transfer endpoint and DDNS receiver.
  Stock ThreadingMixIn spawns an unbounded thread per request, so a burst of
  DNS traffic meant unbounded live threads — each holding up to one database
  connection while it works, which can exhaust postgres max_connections even
  with the 1.6.9 per-thread cleanup in place. A BoundedThreadingMixIn
  semaphore now caps each server (AXFR UDP/TCP, DDNS UDP/TCP) at
  `max_concurrent_requests` threads (new plugin setting, default 16). When
  saturated, the accept loop blocks and further requests wait in the kernel
  listen backlog / UDP receive buffer — standard DNS overload behavior;
  clients retry. A warning is logged when the cap is hit.

## 1.7.0 - 2026-08-09

- Register NOTIFY targets on authenticated SOA refresh checks, not only on
  transfers. A secondary that reloads a current disk copy never transfers, so
  it dropped off the dynamic NOTIFY list whenever its address changed and
  missed every zone change until its next real transfer (observed live: a
  cluster BIND replica restored from its PVC missed same-day record updates
  while its two siblings were notified). `last_transfer` now means "last
  transfer OR authenticated SOA check" — the liveness timestamp that
  TTL-based pruning actually wants.
- Seen Transfer Clients are now inspectable: read-only UI list under the DNS
  Bridge menu and a read-only REST endpoint
  (`/api/plugins/dns-bridge/seen-clients/`). Rows remain machine-managed
  (created by the transfer/SOA handlers, liveness-updated and pruned by the
  NOTIFY sender); the model deliberately stays a plain Django model so
  per-transfer row updates never journal changelog entries.
