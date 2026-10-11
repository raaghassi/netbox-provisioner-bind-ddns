"""NetBox configuration for this plugin's integration tests. Not for production.

Selected with NETBOX_CONFIGURATION=netbox_dns_bridge.tests.configuration, the
mechanism netbox-plugin-dns uses for the same purpose.

Hosts default to the workflow service KEYS, not localhost. Under a container
job the services share a per-job bridge network and each one carries its
declared key as a network alias, so "postgres" and "redis" resolve while
localhost does not. A runner that instead publishes service ports onto the host
can override with POSTGRES_HOST / REDIS_HOST.
"""

import os

ALLOWED_HOSTS = ["*"]

# DATABASES, not DATABASE. NetBox 4.7 still accepts the singular form but marks
# it "Legacy DB definition" (settings.py), and setting both raises
# ImproperlyConfigured with "The use of DATABASES is encouraged."
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "netbox"),
        "USER": os.environ.get("POSTGRES_USER", "netbox"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "netbox"),
        "HOST": os.environ.get("POSTGRES_HOST", "postgres"),
        "PORT": os.environ.get("POSTGRES_PORT", ""),
        "CONN_MAX_AGE": 300,
    }
}

_REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
_REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

REDIS = {
    "tasks": {
        "HOST": _REDIS_HOST,
        "PORT": _REDIS_PORT,
        "PASSWORD": "",
        "DATABASE": 2,
        "SSL": False,
    },
    "caching": {
        "HOST": _REDIS_HOST,
        "PORT": _REDIS_PORT,
        "PASSWORD": "",
        "DATABASE": 3,
        "SSL": False,
    },
}

# netbox_dns must load too: this plugin imports its models and choices, and
# NetBox skips a plugin whose gate fails rather than failing the boot.
PLUGINS = [
    "netbox_dns",
    "netbox_dns_bridge",
]

# This plugin HARD-FAILS without its own PLUGINS_CONFIG entry: ready() raises
# RuntimeError("failed to initialize due to missing settings. Terminating
# Netbox.") when the key is absent or falsy. That is deliberate and is the
# opposite of the version gate, which NetBox swallows silently - so the shape
# below is required, not decorative.
#
# Mirrors the fleet's live configuration (svcs-aghassi-net
# netbox/templates/configmap-extra.yaml), which is the authority for the shape.
# tsig_keys is keyed by netbox-plugin-dns VIEW name, and "_default_" is the
# view netbox-plugin-dns auto-creates. The secret is a throwaway.
PLUGINS_CONFIG = {
    "netbox_dns_bridge": {
        "tsig_keys": {
            "_default_": {
                "keyname": "integration-test-key",
                "secret": "bmV0Ym94LWRucy1icmlkZ2UtaW50ZWdyYXRpb24tdGVzdC10c2lnLWtleS1ub3QtYS1yZWFsLXNlY3JldCEhIQ==",
                "algorithm": "hmac-sha512",
            },
        },
        "axfr": {
            "ixfr_enabled": True,
        },
        "ddns": {
            "allowed_zones": [],
        },
    },
}

RQ = {"COMMIT_MODE": "auto"}

# Test-only values. NetBox requires SECRET_KEY to be at least 50 characters,
# and warns that v2 API tokens are unusable when API_TOKEN_PEPPERS is unset.
SECRET_KEY = "netbox-dns-bridge-integration-tests-secret-key-0123456789"
API_TOKEN_PEPPERS = {
    1: "netbox-dns-bridge-integration-tests-pepper-one-0123456789",
}
