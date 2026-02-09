"""
One-time data migration from the upstream netbox_plugin_bind_provisioner plugin.

Copies IntegerKeyValueSetting and CatalogZoneMemberIdentifier rows from the
old plugin's tables if they exist.  Safe to run on fresh installs (no-op if
old tables don't exist).
"""
from django.db import connection, migrations


def migrate_upstream_data(apps, schema_editor):
    """Copy data from upstream plugin tables if they exist."""
    with connection.cursor() as cursor:
        # Check which tables exist
        all_tables = connection.introspection.table_names(cursor)

        old_kvs = "netbox_plugin_bind_provisioner_integerkeyvaluesetting"
        new_kvs = "netbox_bind_ddns_integerkeyvaluesetting"
        if old_kvs in all_tables and new_kvs in all_tables:
            cursor.execute(
                f'INSERT INTO "{new_kvs}" ("key", "value") '
                f'SELECT "key", "value" FROM "{old_kvs}" '
                f'WHERE "key" NOT IN (SELECT "key" FROM "{new_kvs}")'
            )
            count = cursor.rowcount
            if count:
                print(f"  Migrated {count} IntegerKeyValueSetting rows from upstream")

        old_catz = "netbox_plugin_bind_provisioner_catalogzonememberidentifier"
        new_catz = "netbox_bind_ddns_catalogzonememberidentifier"
        if old_catz in all_tables and new_catz in all_tables:
            cursor.execute(
                f'INSERT INTO "{new_catz}" ("name", "zone_id") '
                f'SELECT "name", "zone_id" FROM "{old_catz}" '
                f'WHERE "zone_id" NOT IN (SELECT "zone_id" FROM "{new_catz}")'
            )
            count = cursor.rowcount
            if count:
                print(f"  Migrated {count} CatalogZoneMemberIdentifier rows from upstream")


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_bind_ddns", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(
            migrate_upstream_data,
            migrations.RunPython.noop,  # No reverse migration
        ),
    ]
