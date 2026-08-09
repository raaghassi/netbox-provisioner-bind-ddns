from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from netbox_dns.models import View

from ..models import NotifyConfig, SeenTransferClient, StaticNotifyTarget


class SeenTransferClientSerializer(serializers.ModelSerializer):
    """
    Read-only (plain ModelSerializer: the model is deliberately not a
    NetBoxModel — machine-managed rows must not journal a changelog entry
    per transfer). zone/view are represented by name for at-a-glance
    reads; all fields are read-only, the registry is maintained by the
    transfer/SOA handlers and the NOTIFY sender.
    """

    zone = serializers.SlugRelatedField(slug_field="name", read_only=True)
    view = serializers.SlugRelatedField(slug_field="name", read_only=True)

    class Meta:
        model = SeenTransferClient
        fields = (
            "id", "address", "zone", "view",
            "last_transfer", "last_notify_ok", "notify_failures",
        )
        read_only_fields = fields


class StaticNotifyTargetSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_dns_bridge-api:staticnotifytarget-detail"
    )
    # Represented/written by PK to avoid coupling to netbox_dns's nested
    # serializer internals; empty = applies to all views.
    view = serializers.PrimaryKeyRelatedField(
        queryset=View.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = StaticNotifyTarget
        fields = (
            "id", "url", "display", "address", "port", "view", "enabled",
            "description", "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display", "address", "port")


class NotifyConfigSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_dns_bridge-api:notifyconfig-detail"
    )

    class Meta:
        model = NotifyConfig
        fields = (
            "id", "url", "display", "timeout", "attempts", "retry_backoff",
            "max_workers", "prune_strategy", "prune_max_failures", "prune_ttl",
            "catalog_zones",
            "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display")
