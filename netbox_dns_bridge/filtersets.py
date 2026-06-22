from django.db.models import Q

from netbox.filtersets import NetBoxModelFilterSet

from .models import StaticNotifyTarget


class StaticNotifyTargetFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = StaticNotifyTarget
        fields = ("id", "address", "port", "view", "enabled")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(address__icontains=value) | Q(description__icontains=value)
        )
