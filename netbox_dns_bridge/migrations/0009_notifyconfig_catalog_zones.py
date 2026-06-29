from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_dns_bridge", "0008_staticnotifytarget_notifyconfig"),
    ]

    operations = [
        migrations.AddField(
            model_name="notifyconfig",
            name="catalog_zones",
            field=models.CharField(
                blank=True,
                default="",
                help_text=(
                    "Comma-separated catalog zone name(s), as configured in bind's "
                    "catalog-zones, to NOTIFY when zone MEMBERSHIP changes (zone add / "
                    "rename / delete) so bind re-AXFRs the catalog promptly instead of "
                    "waiting for its SOA refresh. The NOTIFY is sent to the no-view "
                    "static targets (unsigned — ensure bind's allow-notify covers them). "
                    "Empty = disabled."
                ),
                max_length=512,
            ),
        ),
    ]
