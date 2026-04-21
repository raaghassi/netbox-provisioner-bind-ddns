import logging
from netbox.plugins import PluginConfig
from django.conf import settings

__version__ = "1.0.0"

logger = logging.getLogger(__name__)


class BindDDNSConfig(PluginConfig):
    name = "netbox_bind_ddns"
    verbose_name = "NetBox BIND DDNS"
    description = "BIND provisioner with RFC 2136 DDNS support for NetBox DNS"
    version = __version__
    author = "Ramin Aghassi"
    base_url = "bind_ddns"

    def ready(self):
        self.settings = settings.PLUGINS_CONFIG.get(self.name, None)
        if not self.settings:
            raise RuntimeError(
                f"{self.name}: Plugin {self.verbose_name} failed to initialize due to missing settings. Terminating Netbox."
            )

        from . import signals  # noqa: F401  (register signal receivers)

        # Clean up legacy webhook/event-rule objects from pre-signal versions
        try:
            from extras.models import EventRule, Webhook
            EventRule.objects.filter(name="netbox_bind_ddns record change").delete()
            Webhook.objects.filter(name="netbox_bind_ddns record NOTIFY").delete()
        except Exception:
            pass


config = BindDDNSConfig
