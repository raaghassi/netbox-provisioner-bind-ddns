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
