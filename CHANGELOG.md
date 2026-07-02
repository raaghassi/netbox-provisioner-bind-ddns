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
