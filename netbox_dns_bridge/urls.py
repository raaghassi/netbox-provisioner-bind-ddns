from django.urls import path
from django.views.generic import RedirectView

from netbox.views.generic import ObjectChangeLogView

from . import models, views

urlpatterns = [
    # Static NOTIFY targets
    path(
        "static-targets/",
        views.StaticNotifyTargetListView.as_view(),
        name="staticnotifytarget_list",
    ),
    path(
        "static-targets/add/",
        views.StaticNotifyTargetEditView.as_view(),
        name="staticnotifytarget_add",
    ),
    path(
        "static-targets/delete/",
        views.StaticNotifyTargetBulkDeleteView.as_view(),
        name="staticnotifytarget_bulk_delete",
    ),
    path(
        "static-targets/<int:pk>/",
        views.StaticNotifyTargetView.as_view(),
        name="staticnotifytarget",
    ),
    path(
        "static-targets/<int:pk>/edit/",
        views.StaticNotifyTargetEditView.as_view(),
        name="staticnotifytarget_edit",
    ),
    path(
        "static-targets/<int:pk>/delete/",
        views.StaticNotifyTargetDeleteView.as_view(),
        name="staticnotifytarget_delete",
    ),
    path(
        "static-targets/<int:pk>/changelog/",
        ObjectChangeLogView.as_view(),
        name="staticnotifytarget_changelog",
        kwargs={"model": models.StaticNotifyTarget},
    ),
    # NOTIFY configuration (singleton)
    path("config/", views.NotifyConfigView.as_view(), name="notifyconfig"),
    path("config/edit/", views.NotifyConfigEditView.as_view(), name="notifyconfig_edit"),
    # The singleton has no real list view, but NetBox's generic object/edit
    # chrome HARD-reverses <model>_list for the breadcrumb (utilities.views
    # get_action_url, no fallback) — so the detail/edit pages 500 without it.
    # Alias it to the singleton page. (Tab reverses for changelog/journal are
    # soft, so those simply stay hidden — no route needed.)
    path(
        "config/list/",
        RedirectView.as_view(
            pattern_name="plugins:netbox_dns_bridge:notifyconfig", permanent=False
        ),
        name="notifyconfig_list",
    ),
]
