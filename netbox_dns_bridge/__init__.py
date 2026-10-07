from netbox.plugins import PluginConfig
from django.conf import settings

__version__ = "1.7.0"


class DNSBridgeConfig(PluginConfig):
    name = "netbox_dns_bridge"
    verbose_name = "Netbox DNS Bridge"
    description = "A bridge between netbox-plugin-dns and your DNS infrastructure with DDNS and IXFR support."
    version = __version__
    # NetBox gates the plugin on these at load time and raises
    # IncompatiblePluginError on a mismatch. The range follows the pairing
    # rule in the README: this plugin's major.minor must match the
    # netbox-plugin-dns major.minor it runs against. This plugin is 1.7, so
    # it pairs with netbox-plugin-dns 1.7, which supports NetBox 4.7.
    min_version = "4.7.0"
    max_version = "4.7.99"
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

        # MUST call the base PluginConfig.ready(): it is what registers the
        # navigation menu (register_menu), model feature registry
        # (register_models), search indexes, template extensions and GraphQL.
        # Overriding ready() without super() silently drops ALL of that — the
        # plugin still loads/migrates/serves pages, but its menu never appears.
        super().ready()

        from . import signals  # noqa: F401  (register signal receivers)


config = DNSBridgeConfig
