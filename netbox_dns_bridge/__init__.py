from netbox.plugins import PluginConfig
from django.conf import settings

__version__ = "1.6.2"


class DNSBridgeConfig(PluginConfig):
    name = "netbox_dns_bridge"
    verbose_name = "Netbox DNS Bridge"
    description = "A bridge between netbox-plugin-dns and your DNS infrastructure with DDNS and IXFR support."
    version = __version__
    author = "Sven Luethi"
    author_email = "dev@sven.luethi.co"
    base_url = "dns-bridge"

    # NOTIFY tuning, pruning options, and static targets are NOT plugin
    # settings — they are managed in NetBox itself (UI/REST) via the
    # NotifyConfig singleton and StaticNotifyTarget models, which are the sole
    # source of truth. PLUGINS_CONFIG still carries tsig_keys / axfr / ddns.

    def ready(self):
        self.settings = settings.PLUGINS_CONFIG.get(self.name, None)
        if not self.settings:
            raise RuntimeError(
                f"{self.name}: Plugin {self.verbose_name} failed to initialize due to missing settings. Terminating Netbox."
            )

        from . import signals  # noqa: F401  (register signal receivers)


config = DNSBridgeConfig
