import django.db.models.deletion
import taggit.managers
from django.db import migrations, models

import utilities.json


class Migration(migrations.Migration):

    dependencies = [
        ("extras", "0122_charfield_null_choices"),
        ("netbox_dns", "0030_dnsseckeytemplate_comments_dnsseckeytemplate_owner_and_more"),
        ("netbox_dns_bridge", "0007_seentransferclient_notify_tracking"),
    ]

    operations = [
        migrations.CreateModel(
            name="StaticNotifyTarget",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        encoder=utilities.json.CustomFieldJSONEncoder,
                    ),
                ),
                ("address", models.CharField(max_length=255)),
                ("port", models.PositiveIntegerField(default=53)),
                ("enabled", models.BooleanField(default=True)),
                ("description", models.CharField(blank=True, max_length=200)),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
                (
                    "view",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="netbox_dns.view",
                    ),
                ),
            ],
            options={
                "verbose_name": "static NOTIFY target",
                "verbose_name_plural": "static NOTIFY targets",
                "ordering": ("address", "port"),
            },
        ),
        migrations.CreateModel(
            name="NotifyConfig",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        encoder=utilities.json.CustomFieldJSONEncoder,
                    ),
                ),
                ("timeout", models.FloatField(default=2.0)),
                ("attempts", models.PositiveIntegerField(default=2)),
                ("retry_backoff", models.FloatField(default=0.5)),
                ("max_workers", models.PositiveIntegerField(default=16)),
                ("prune_strategy", models.CharField(default="ttl", max_length=20)),
                ("prune_max_failures", models.PositiveIntegerField(default=5)),
                ("prune_ttl", models.PositiveIntegerField(default=604800)),
                (
                    "tags",
                    taggit.managers.TaggableManager(
                        through="extras.TaggedItem", to="extras.Tag"
                    ),
                ),
            ],
            options={
                "verbose_name": "NOTIFY configuration",
                "verbose_name_plural": "NOTIFY configuration",
            },
        ),
        migrations.AddConstraint(
            model_name="staticnotifytarget",
            constraint=models.UniqueConstraint(
                fields=("address", "port", "view"),
                name="netbox_dns_bridge_staticnotifytarget_unique",
            ),
        ),
        migrations.AddConstraint(
            model_name="staticnotifytarget",
            constraint=models.UniqueConstraint(
                fields=("address", "port"),
                condition=models.Q(view__isnull=True),
                name="netbox_dns_bridge_staticnotifytarget_unique_noview",
            ),
        ),
    ]
