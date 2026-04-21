from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_dns_bridge", "0005_rename_app_label"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="zonechangelog",
            constraint=models.CheckConstraint(
                condition=models.Q(action__in=["ADD", "DELETE"]),
                name="netbox_dns_bridge_zc_action_ck",
            ),
        ),
    ]
