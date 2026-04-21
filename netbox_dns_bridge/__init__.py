import logging
from netbox.plugins import PluginConfig
from django.conf import settings

__version__ = "1.5.3"

logger = logging.getLogger(__name__)


class DNSBridgeConfig(PluginConfig):
    name = "netbox_dns_bridge"
    verbose_name = "Netbox DNS Bridge"
    description = "A bridge between netbox-plugin-dns and your DNS infrastructure with DDNS and IXFR support."
    version = __version__
    author = "Sven Luethi"
    author_email = "dev@sven.luethi.co"
    base_url = "dns-bridge"

    def ready(self):
        self.settings = settings.PLUGINS_CONFIG.get(self.name, None)
        if not self.settings:
            raise RuntimeError(
                f"{self.name}: Plugin {self.verbose_name} failed to initialize due to missing settings. Terminating Netbox."
            )

        from . import signals  # noqa: F401  (register signal receivers)


config = DNSBridgeConfig
