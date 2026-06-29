from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from netbox_dns.models import View

from ..models import NotifyConfig, StaticNotifyTarget


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
