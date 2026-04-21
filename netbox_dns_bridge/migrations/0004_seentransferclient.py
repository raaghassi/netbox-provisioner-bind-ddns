from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_dns", "0030_dnsseckeytemplate_comments_dnsseckeytemplate_owner_and_more"),
        ("netbox_dns_bridge", "0003_zonechangelog"),
    ]

    operations = [
        migrations.CreateModel(
            name="SeenTransferClient",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("address", models.GenericIPAddressField()),
                ("last_transfer", models.DateTimeField(auto_now=True)),
                (
                    "zone",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="transfer_clients",
                        to="netbox_dns.zone",
                    ),
                ),
                (
                    "view",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="netbox_dns.view",
                    ),
                ),
            ],
            options={
                "ordering": ["zone", "address"],
                "unique_together": {("address", "zone", "view")},
            },
        ),
    ]
