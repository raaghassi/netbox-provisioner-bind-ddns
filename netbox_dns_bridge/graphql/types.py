import strawberry_django

from netbox.graphql.types import NetBoxObjectType

from ..models import NotifyConfig, StaticNotifyTarget

# Scalar fields only (the `view` FK is intentionally excluded to avoid
# cross-plugin GraphQL type resolution against netbox_dns).


@strawberry_django.type(
    StaticNotifyTarget,
    fields=["id", "address", "port", "enabled", "description"],
    pagination=True,
)
class StaticNotifyTargetType(NetBoxObjectType):
    pass


@strawberry_django.type(
    NotifyConfig,
    fields=[
        "id", "timeout", "attempts", "retry_backoff", "max_workers",
        "prune_strategy", "prune_max_failures", "prune_ttl",
    ],
    pagination=True,
)
class NotifyConfigType(NetBoxObjectType):
    pass
