"""Load framework-free modules without standing up NetBox.

netbox_dns_bridge/__init__.py imports netbox.plugins, and utils.py imports
netbox_dns.models, so neither can be imported normally outside a NetBox
install. These tests cover logic that does not actually need either, so the
module is loaded straight from its file with the NetBox-side imports stubbed.
That keeps this layer at about a second and runnable on any machine, which is
what makes it usable as a pre-push gate.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def utils():
    netbox_dns = types.ModuleType("netbox_dns")
    models = types.ModuleType("netbox_dns.models")
    models.Zone = object
    netbox_dns.models = models
    sys.modules.setdefault("netbox_dns", netbox_dns)
    sys.modules.setdefault("netbox_dns.models", models)
    return _load("_bridge_utils", "netbox_dns_bridge/utils.py")
