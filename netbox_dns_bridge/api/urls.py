from netbox.api.routers import NetBoxRouter

from . import views

app_name = "netbox_dns_bridge"

router = NetBoxRouter()
router.register("static-targets", views.StaticNotifyTargetViewSet)
router.register("seen-clients", views.SeenTransferClientViewSet)
router.register("config", views.NotifyConfigViewSet)

urlpatterns = router.urls
