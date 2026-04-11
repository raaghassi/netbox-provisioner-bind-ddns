from django.db import models

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

    zone = models.ForeignKey(
        "netbox_dns.Zone", on_delete=models.CASCADE, db_index=True
    )
    serial = models.BigIntegerField(db_index=True)
    action = models.CharField(max_length=10)  # "ADD" or "DELETE"
    name = models.CharField(max_length=255)
    rdtype = models.CharField(max_length=10)
    value = models.TextField()
    ttl = models.PositiveIntegerField()

    class Meta:
        ordering = ["serial", "id"]
        indexes = [
            models.Index(fields=["zone", "serial"]),
        ]

    def __str__(self):
        return f"{self.action} {self.name} {self.rdtype} (serial {self.serial})"
