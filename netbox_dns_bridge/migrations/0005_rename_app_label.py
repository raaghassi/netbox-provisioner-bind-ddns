"""Rename app label from netbox_bind_ddns to netbox_dns_bridge for upstream alignment."""
from django.db import migrations


def rename_app_forward(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    ContentType.objects.filter(app_label="netbox_bind_ddns").update(
        app_label="netbox_dns_bridge"
    )
    schema_editor.execute(
        "UPDATE django_migrations SET app = 'netbox_dns_bridge' WHERE app = 'netbox_bind_ddns'"
    )


def rename_app_reverse(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    ContentType.objects.filter(app_label="netbox_dns_bridge").update(
        app_label="netbox_bind_ddns"
    )
    schema_editor.execute(
        "UPDATE django_migrations SET app = 'netbox_bind_ddns' WHERE app = 'netbox_dns_bridge'"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("netbox_dns_bridge", "0004_seentransferclient"),
    ]

    operations = [
        migrations.RunPython(rename_app_forward, rename_app_reverse),
    ]
