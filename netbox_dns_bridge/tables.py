import django_tables2 as tables

from netbox.tables import NetBoxTable, columns

from .models import SeenTransferClient, StaticNotifyTarget


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


class SeenTransferClientTable(NetBoxTable):
    """
    Read-only: rows are machine-managed (created by the transfer/SOA
    handlers, liveness-updated by the NOTIFY sender, pruned per
    NotifyConfig) — no row actions, the table exists for operator
    visibility into the dynamic NOTIFY-target population.
    """

    zone = tables.Column(linkify=True)
    view = tables.Column(linkify=True)
    actions = columns.ActionsColumn(actions=())

    class Meta(NetBoxTable.Meta):
        model = SeenTransferClient
        fields = (
            "id", "address", "zone", "view",
            "last_transfer", "last_notify_ok", "notify_failures",
        )
        default_columns = (
            "address", "zone", "view",
            "last_transfer", "last_notify_ok", "notify_failures",
        )
