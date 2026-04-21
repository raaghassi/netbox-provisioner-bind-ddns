"""
Squashed initial migration for netbox_dns_bridge.

Creates the final state of both models (IntegerKeyValueSetting and
CatalogZoneMemberIdentifier) as they exist after upstream's 5 migrations.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("netbox_dns", "0030_dnsseckeytemplate_comments_dnsseckeytemplate_owner_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="IntegerKeyValueSetting",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False
                    ),
                ),
                ("key", models.CharField(max_length=64)),
                ("value", models.IntegerField()),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="CatalogZoneMemberIdentifier",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False
                    ),
                ),
                ("name", models.CharField(max_length=26, unique=True)),
                (
                    "zone",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="catz_identifier",
                        to="netbox_dns.zone",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
            },
        ),
    ]
