from rest_framework.response import Response

from netbox.api.viewsets import NetBoxModelViewSet

from .. import filtersets, models
from .serializers import NotifyConfigSerializer, StaticNotifyTargetSerializer


class StaticNotifyTargetViewSet(NetBoxModelViewSet):
    queryset = models.StaticNotifyTarget.objects.all()
    serializer_class = StaticNotifyTargetSerializer
    filterset_class = filtersets.StaticNotifyTargetFilterSet


class NotifyConfigViewSet(NetBoxModelViewSet):
    queryset = models.NotifyConfig.objects.all()
    serializer_class = NotifyConfigSerializer

    def create(self, request, *args, **kwargs):
        # NotifyConfig is a singleton (save() pins pk=1). A POST when the row
        # already exists would force a duplicate-pk INSERT -> IntegrityError ->
        # HTTP 500, so reconcile by UPDATING the existing row instead. The
        # first-ever create still goes through the normal path.
        existing = self.get_queryset().first()
        if existing is None:
            return super().create(request, *args, **kwargs)
        serializer = self.get_serializer(existing, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
