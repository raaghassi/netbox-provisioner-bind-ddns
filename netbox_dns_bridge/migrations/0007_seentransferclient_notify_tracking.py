from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_dns_bridge", "0006_zonechangelog_action_constraint"),
    ]

    operations = [
        migrations.AddField(
            model_name="seentransferclient",
            name="last_notify_ok",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="seentransferclient",
            name="notify_failures",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
