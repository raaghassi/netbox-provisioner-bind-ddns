from netbox.search import SearchIndex, register_search

from .models import StaticNotifyTarget


@register_search
class StaticNotifyTargetIndex(SearchIndex):
    model = StaticNotifyTarget
    fields = (
        ("address", 100),
        ("description", 500),
    )
    display_attrs = ("view", "port", "description")
