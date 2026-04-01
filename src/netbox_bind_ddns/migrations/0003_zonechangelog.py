from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_dns", "0001_initial"),
        ("netbox_bind_ddns", "0002_migrate_from_upstream"),
    ]

    operations = [
        migrations.CreateModel(
            name="ZoneChangelog",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("serial", models.BigIntegerField(db_index=True)),
                ("action", models.CharField(max_length=10)),
                ("name", models.CharField(max_length=255)),
                ("rdtype", models.CharField(max_length=10)),
                ("value", models.TextField()),
                ("ttl", models.PositiveIntegerField()),
                (
                    "zone",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="netbox_dns.zone",
                    ),
                ),
            ],
            options={
                "ordering": ["serial", "id"],
                "indexes": [
                    models.Index(
                        fields=["zone", "serial"],
                        name="netbox_bind_zone_serial_idx",
                    ),
                ],
            },
        ),
    ]
