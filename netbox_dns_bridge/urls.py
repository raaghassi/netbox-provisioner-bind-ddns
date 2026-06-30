from django.urls import path

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
    # NOTIFY configuration — a singleton (always pk=1). NetBox's generic object
    # chrome builds the detail/edit/delete URLs (and get_absolute_url + the
    # post-edit redirect) WITH the object's pk, so these must be pk-based like any
    # model: a pk-less edit URL makes the detail page's Edit button reverse to the
    # string "None" (get_action_url(instance,'edit',kwargs={'pk':1}) fails). The
    # nav menu + breadcrumb 'list' need a STATIC (pk-less) entry, so 'config/'
    # redirects to the pk=1 detail (NotifyConfigLandingView).
    path("config/", views.NotifyConfigLandingView.as_view(), name="notifyconfig_list"),
    path("config/<int:pk>/", views.NotifyConfigView.as_view(), name="notifyconfig"),
    path(
        "config/<int:pk>/edit/",
        views.NotifyConfigEditView.as_view(),
        name="notifyconfig_edit",
    ),
]
