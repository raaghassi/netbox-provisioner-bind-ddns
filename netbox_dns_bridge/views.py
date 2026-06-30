from django.shortcuts import redirect
from django.views import View

from netbox.views import generic

from . import filtersets, forms, models, tables


# ---------------------------------------------------------------------------
# Static NOTIFY targets (collection)
# ---------------------------------------------------------------------------
class StaticNotifyTargetView(generic.ObjectView):
    queryset = models.StaticNotifyTarget.objects.all()


class StaticNotifyTargetListView(generic.ObjectListView):
    queryset = models.StaticNotifyTarget.objects.all()
    table = tables.StaticNotifyTargetTable
    filterset = filtersets.StaticNotifyTargetFilterSet
    filterset_form = forms.StaticNotifyTargetFilterForm


class StaticNotifyTargetEditView(generic.ObjectEditView):
    queryset = models.StaticNotifyTarget.objects.all()
    form = forms.StaticNotifyTargetForm


class StaticNotifyTargetDeleteView(generic.ObjectDeleteView):
    queryset = models.StaticNotifyTarget.objects.all()


class StaticNotifyTargetBulkDeleteView(generic.BulkDeleteView):
    queryset = models.StaticNotifyTarget.objects.all()
    table = tables.StaticNotifyTargetTable
    filterset = filtersets.StaticNotifyTargetFilterSet


# ---------------------------------------------------------------------------
# NOTIFY configuration (singleton — always pk=1)
# ---------------------------------------------------------------------------
class NotifyConfigLandingView(View):
    """Pk-less entry for the nav menu + breadcrumb 'list'. The NOTIFY config is a
    singleton, but NetBox's object chrome is pk-based, so ensure the row exists
    and redirect to its pk=1 detail."""

    def get(self, request, *args, **kwargs):
        obj, _ = models.NotifyConfig.objects.get_or_create(pk=1)
        return redirect("plugins:netbox_dns_bridge:notifyconfig", pk=obj.pk)


class NotifyConfigView(generic.ObjectView):
    queryset = models.NotifyConfig.objects.all()

    def get_object(self, **kwargs):
        obj, _ = models.NotifyConfig.objects.get_or_create(pk=1)
        return obj


class NotifyConfigEditView(generic.ObjectEditView):
    queryset = models.NotifyConfig.objects.all()
    form = forms.NotifyConfigForm

    def get_object(self, **kwargs):
        obj, _ = models.NotifyConfig.objects.get_or_create(pk=1)
        return obj
