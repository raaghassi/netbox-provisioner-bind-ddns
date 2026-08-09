from django.db import models
from django.urls import reverse

from netbox.models import NetBoxModel

import netbox_dns.models


class IntegerKeyValueSetting(models.Model):
    key = models.CharField(max_length=64)
    value = models.IntegerField()

    def __str__(self):
        return f"{self.key}: {str(self.value)}"

    class Meta:
        default_permissions = ()


class CatalogZoneMemberIdentifier(models.Model):
    name = models.CharField(
        max_length=26,
        unique=True,
    )

    zone = models.OneToOneField(
        to=netbox_dns.models.Zone,
        on_delete=models.CASCADE,
        related_name="catz_identifier",
    )

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return str(self.name)


class ZoneChangelog(models.Model):
    """
    Journal of record-level changes per zone, indexed by SOA serial.

    Used to build native IXFR (RFC 1995) responses.  Each row represents
    one ADD or DELETE that occurred at a specific serial transition.
    For updates (value changed), two rows are written: DELETE of old + ADD of new.
    """

    class Action(models.TextChoices):
        ADD = "ADD", "Add"
        DELETE = "DELETE", "Delete"

    zone = models.ForeignKey(
        "netbox_dns.Zone", on_delete=models.CASCADE, db_index=True
    )
    serial = models.BigIntegerField(db_index=True)
    action = models.CharField(max_length=10, choices=Action)
    name = models.CharField(max_length=255)
    rdtype = models.CharField(max_length=10)
    value = models.TextField()
    ttl = models.PositiveIntegerField()

    class Meta:
        ordering = ["serial", "id"]
        indexes = [
            models.Index(fields=["zone", "serial"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    action__in=["ADD", "DELETE"],
                ),
                name="netbox_dns_bridge_zc_action_ck",
            ),
        ]

    def __str__(self):
        return f"{self.action} {self.name} {self.rdtype} (serial {self.serial})"


class SeenTransferClient(models.Model):
    """
    Tracks IPs that have successfully performed zone transfers (AXFR/IXFR).

    Used as the NOTIFY target list — instead of resolving NS records (which
    miss hidden masters and don't handle anycast), we notify every client
    that has actually transferred the zone.
    """

    address = models.GenericIPAddressField()
    zone = models.ForeignKey(
        "netbox_dns.Zone", on_delete=models.CASCADE, related_name="transfer_clients"
    )
    view = models.ForeignKey(
        "netbox_dns.View", on_delete=models.SET_NULL, null=True, blank=True
    )
    # Liveness timestamp: bumped on a successful transfer AND on an
    # authenticated SOA refresh check (a disk-restored, serial-current
    # secondary never transfers — its SOA polling is the only signal it
    # still holds the zone).
    last_transfer = models.DateTimeField(auto_now=True)

    # NOTIFY liveness, maintained by notify.notify_zone() per send cycle. The
    # SeenTransferClient population is dynamic — a secondary registers by
    # transferring and may later disappear (it is restarted, replaced,
    # renumbered, or decommissioned), so a target being unreachable is an
    # EXPECTED, routine condition, not an error.
    # These two fields let the NOTIFY path shed departed members gracefully
    # (see the configurable prune strategies in notify.py) instead of retrying a
    # dead address forever. last_notify_ok is the last time this target ACKed a
    # NOTIFY; notify_failures is the count of consecutive failed NOTIFY cycles
    # (reset to 0 on any success). Updated via QuerySet.update()/F() so they do
    # NOT touch last_transfer (which is auto_now and means "last real transfer").
    last_notify_ok = models.DateTimeField(null=True, blank=True)
    notify_failures = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [("address", "zone", "view")]
        ordering = ["zone", "address"]

    def __str__(self):
        return f"{self.address} -> {self.zone.name} (view={self.view})"


class StaticNotifyTarget(NetBoxModel):
    """
    An operator-defined, fixed NOTIFY target managed in NetBox (UI/REST).

    This is ADDITIVE to the dynamic SeenTransferClient discovery — it is sent a
    NOTIFY on every cycle for matching zones and is NEVER pruned (the operator
    owns its lifecycle). The address may be an IP literal or a hostname (the
    sender resolves hostnames at send time). A target with a `view` only applies
    to zones in that view (selecting the correct per-view TSIG key); a target
    with no view applies to every zone, signed with each zone's own view key.
    Deployment-agnostic: it is just a fixed address, no different from any other.
    """

    address = models.CharField(
        max_length=255,
        help_text="IP address or resolvable hostname of the secondary to NOTIFY.",
    )
    port = models.PositiveIntegerField(
        default=53,
        help_text="DNS port of the secondary (usually 53).",
    )
    view = models.ForeignKey(
        "netbox_dns.View",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text="Restrict this target to zones in this view. Empty = all views.",
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Disable to stop notifying this target without deleting it.",
    )
    description = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ("address", "port")
        verbose_name = "static NOTIFY target"
        verbose_name_plural = "static NOTIFY targets"
        constraints = [
            models.UniqueConstraint(
                fields=("address", "port", "view"),
                name="netbox_dns_bridge_staticnotifytarget_unique",
            ),
            # Postgres treats NULLs as distinct in a UNIQUE index, so the
            # constraint above does NOT dedupe the common all-views case
            # (view IS NULL). This partial constraint enforces it there too.
            models.UniqueConstraint(
                fields=("address", "port"),
                condition=models.Q(view__isnull=True),
                name="netbox_dns_bridge_staticnotifytarget_unique_noview",
            ),
        ]

    def __str__(self):
        view = f" [{self.view.name}]" if self.view_id else ""
        return f"{self.address}:{self.port}{view}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_dns_bridge:staticnotifytarget", args=[self.pk])


class NotifyConfig(NetBoxModel):
    """
    Singleton holding the NOTIFY sender's tuning and pruning options.

    Surfaced in NetBox (UI/REST) so an operator can tune behavior without a
    redeploy. There is at most one row (pk pinned to 1 on save). When no row
    exists yet (fresh install), get_solo() returns a transient instance carrying
    the field defaults, so the sender behaves sanely until the row is seeded.
    """

    timeout = models.FloatField(
        default=2.0, help_text="Per-attempt UDP timeout, seconds."
    )
    attempts = models.PositiveIntegerField(
        default=2, help_text="Send attempts before a target is deemed unreachable."
    )
    retry_backoff = models.FloatField(
        default=0.5, help_text="Delay between attempts, seconds."
    )
    max_workers = models.PositiveIntegerField(
        default=16, help_text="Cap on concurrent sends per zone cycle."
    )
    prune_strategy = models.CharField(
        max_length=20,
        default="ttl",
        help_text="How to shed dead dynamic targets: ttl | failures | none.",
    )
    prune_max_failures = models.PositiveIntegerField(
        default=5,
        help_text="'failures' strategy: prune after this many consecutive failed cycles.",
    )
    prune_ttl = models.PositiveIntegerField(
        default=604800,
        help_text="'ttl' strategy: prune if no successful NOTIFY within this many seconds.",
    )
    catalog_zones = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text=(
            "Comma-separated catalog zone name(s), as configured in bind's "
            "catalog-zones, to NOTIFY when zone MEMBERSHIP changes (zone add / rename "
            "/ delete) so bind re-AXFRs the catalog promptly instead of waiting for "
            "its SOA refresh. The NOTIFY is sent to the no-view static targets "
            "(unsigned — ensure bind's allow-notify covers them). Empty = disabled."
        ),
    )

    class Meta:
        verbose_name = "NOTIFY configuration"
        verbose_name_plural = "NOTIFY configuration"

    def __str__(self):
        return "NOTIFY configuration"

    def save(self, *args, **kwargs):
        # Enforce singleton: there is only ever one configuration row.
        self.pk = 1
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        # pk-based to match the (now pk-based) detail route; the singleton is
        # always pk=1. Mirrors StaticNotifyTarget.get_absolute_url above.
        return reverse("plugins:netbox_dns_bridge:notifyconfig", args=[self.pk])

    @classmethod
    def get_solo(cls):
        """Return the single config row, or a transient defaults instance (no write)."""
        return cls.objects.first() or cls()
