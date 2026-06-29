from django import forms

from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import DynamicModelChoiceField

from netbox_dns.models import View

from .choices import NotifyPruneStrategyChoices
from .models import StaticNotifyTarget, NotifyConfig


class StaticNotifyTargetForm(NetBoxModelForm):
    view = DynamicModelChoiceField(
        queryset=View.objects.all(),
        required=False,
        help_text="Restrict to zones in this view. Empty = all views.",
    )

    class Meta:
        model = StaticNotifyTarget
        fields = ("address", "port", "view", "enabled", "description", "tags")


class StaticNotifyTargetFilterForm(NetBoxModelFilterSetForm):
    model = StaticNotifyTarget
    # Field name must match the auto-generated FilterSet filter (the FK field
    # listed in Meta.fields yields a filter named `view`, not `view_id`), or the
    # sidebar View dropdown silently no-ops.
    view = DynamicModelChoiceField(
        queryset=View.objects.all(), required=False, label="View"
    )
    enabled = forms.NullBooleanField(required=False)


class NotifyConfigForm(NetBoxModelForm):
    prune_strategy = forms.ChoiceField(
        choices=NotifyPruneStrategyChoices,
        required=True,
        help_text="How to shed dead dynamic NOTIFY targets. Static targets are never pruned.",
    )

    class Meta:
        model = NotifyConfig
        fields = (
            "timeout", "attempts", "retry_backoff", "max_workers",
            "prune_strategy", "prune_max_failures", "prune_ttl",
            "catalog_zones",
        )
