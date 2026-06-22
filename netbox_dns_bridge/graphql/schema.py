import strawberry
import strawberry_django

from .types import NotifyConfigType, StaticNotifyTargetType


@strawberry.type(name="Query")
class NetBoxDNSBridgeStaticNotifyTargetQuery:
    netbox_dns_bridge_static_target: StaticNotifyTargetType = strawberry_django.field()
    netbox_dns_bridge_static_target_list: list[StaticNotifyTargetType] = (
        strawberry_django.field()
    )


@strawberry.type(name="Query")
class NetBoxDNSBridgeNotifyConfigQuery:
    netbox_dns_bridge_notify_config: NotifyConfigType = strawberry_django.field()
    netbox_dns_bridge_notify_config_list: list[NotifyConfigType] = (
        strawberry_django.field()
    )


schema = [
    NetBoxDNSBridgeStaticNotifyTargetQuery,
    NetBoxDNSBridgeNotifyConfigQuery,
]
