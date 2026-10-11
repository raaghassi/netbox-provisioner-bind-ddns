"""Assert this plugin is actually loaded, and that the netbox_dns surface it
builds on still exists.

These cover the failure class the fleet hit in 2026-10: NetBox catches
IncompatiblePluginError, warns and continues (settings.py), so a plugin whose
min_version/max_version gate fails is SKIPPED while NetBox reports healthy. A
pinned-but-absent plugin then surfaces much later as an app_label RuntimeError
for the models it was supposed to register. Nothing in a lint or a packaging
check can see that - it needs a booted NetBox.
"""

from django.db.models import Model
from django.test import TestCase

from netbox.registry import registry


class PluginIsInstalledTestCase(TestCase):
    def test_plugin_registered(self):
        """A failed version gate skips the plugin silently. Catch that here."""
        self.assertIn(
            "netbox_dns_bridge",
            registry["plugins"]["installed"],
            "netbox_dns_bridge is not in the installed registry: its version "
            "gate rejected this NetBox, and NetBox skipped it without failing",
        )

    def test_netbox_dns_registered(self):
        """This plugin imports netbox_dns at module scope, so it must load."""
        self.assertIn("netbox_dns", registry["plugins"]["installed"])

    def test_gate_brackets_this_netbox(self):
        """The declared window must actually contain the NetBox under test.

        Reads RELEASE.version, not the VERSION alias - settings.py marks that
        one "Retained for backward compatibility". Splits on "-" first, the way
        NetBox does when it derives REST_FRAMEWORK_VERSION.
        """
        from netbox.settings import RELEASE

        from netbox_dns_bridge import DNSBridgeConfig

        def parts(version):
            return tuple(int(p) for p in version.split("-")[0].split(".")[:3])

        running = parts(RELEASE.version)
        self.assertLessEqual(
            parts(DNSBridgeConfig.min_version),
            running,
            f"min_version {DNSBridgeConfig.min_version} excludes {RELEASE.version}",
        )
        if getattr(DNSBridgeConfig, "max_version", None):
            self.assertLessEqual(
                running,
                parts(DNSBridgeConfig.max_version),
                f"max_version {DNSBridgeConfig.max_version} excludes {RELEASE.version}",
            )


class NetBoxDNSSurfaceTestCase(TestCase):
    """The five names this plugin imports from netbox_dns, and the Record
    fields it writes. A rename upstream is a silent break otherwise: the
    import fails at NetBox boot, the plugin is skipped, and NetBox stays up.
    """

    def test_models_importable_and_are_models(self):
        from netbox_dns.models import Record, View, Zone

        for model in (Zone, Record, View):
            with self.subTest(model=model.__name__):
                self.assertTrue(issubclass(model, Model))

    def test_choices_importable(self):
        from netbox_dns.choices import RecordStatusChoices, ZoneStatusChoices

        for choices in (ZoneStatusChoices, RecordStatusChoices):
            with self.subTest(choices=choices.__name__):
                self.assertTrue(hasattr(choices, "CHOICES"))

    def test_record_fields_this_plugin_writes_exist(self):
        from netbox_dns.models import Record

        names = {f.name for f in Record._meta.get_fields()}
        for field in ("name", "zone", "type", "value", "status", "ttl", "disable_ptr"):
            with self.subTest(field=field):
                self.assertIn(field, names)

    def test_zone_fields_the_exporter_reads_exist(self):
        from netbox_dns.models import Zone

        names = {f.name for f in Zone._meta.get_fields()}
        for field in ("name", "status", "view", "default_ttl", "records"):
            with self.subTest(field=field):
                self.assertIn(field, names)
