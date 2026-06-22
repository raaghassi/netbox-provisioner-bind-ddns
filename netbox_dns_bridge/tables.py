import django_tables2 as tables

from netbox.tables import NetBoxTable, columns

from .models import StaticNotifyTarget


class StaticNotifyTargetTable(NetBoxTable):
    address = tables.Column(linkify=True)
    view = tables.Column(linkify=True)
    enabled = columns.BooleanColumn()
    tags = columns.TagColumn(url_name="plugins:netbox_dns_bridge:staticnotifytarget_list")

    class Meta(NetBoxTable.Meta):
        model = StaticNotifyTarget
        fields = (
            "pk", "id", "address", "port", "view", "enabled",
            "description", "tags", "created", "last_updated",
        )
        default_columns = ("address", "port", "view", "enabled", "description")
