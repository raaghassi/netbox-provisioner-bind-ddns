#!/usr/bin/env python3
"""Check that this plugin's version declarations agree with each other.

NetBox does NOT fail loudly on a bad declaration. netbox/settings.py wraps
PluginConfig.validate() in try/except IncompatiblePluginError and responds with
warnings.warn(...) followed by continue, so a plugin whose min_version or
max_version excludes the running NetBox is skipped silently: NetBox boots,
serves, and reports healthy with the plugin simply absent. For this plugin that
means DNS registration stops with nothing obviously broken.

The declarations therefore cannot enforce themselves, and this gate exists to
enforce them from outside. It reads the committed source only - no imports, no
NetBox, no network - so it runs in about a second.
"""

import re
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "netbox_dns_bridge" / "__init__.py"
PYPROJECT = ROOT / "pyproject.toml"

PAIRED_PLUGIN = "netbox-plugin-dns"


def _literal(pattern: str, text: str):
    """Return the captured literal, or None when it is not declared at all."""
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    source = INIT.read_text(encoding="utf-8")
    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))

    failures = []

    raw_version = _literal(r'^__version__\s*=\s*"([^"]+)"', source)
    raw_min = _literal(r'^\s*min_version\s*=\s*"([^"]+)"', source)
    raw_max = _literal(r'^\s*max_version\s*=\s*"([^"]+)"', source)

    for name, raw in (("__version__", raw_version), ("min_version", raw_min), ("max_version", raw_max)):
        if raw is None:
            failures.append(
                f"{name} is not declared in {INIT.name}; NetBox skips a plugin "
                f"silently when its gate is wrong, so an undeclared gate is unenforceable"
            )

    version = Version(raw_version) if raw_version else None
    min_version = Version(raw_min) if raw_min else None
    max_version = Version(raw_max) if raw_max else None

    requirements = [Requirement(r) for r in pyproject["project"]["dependencies"]]
    paired = next((r for r in requirements if r.name == PAIRED_PLUGIN), None)
    if paired is None:
        failures.append(f"{PAIRED_PLUGIN} is not declared in pyproject dependencies")

    # 1. The README pairing rule, as code: this plugin's major.minor must match
    #    the netbox-plugin-dns line it is built against.
    lower = None
    if paired is not None:
        lower = next((s for s in paired.specifier if s.operator in (">=", "==", "~=")), None)
    if paired is not None and lower is None:
        failures.append(f"{PAIRED_PLUGIN} has no lower bound: {paired.specifier}")
    elif lower is not None and version is not None:
        paired_line = Version(lower.version).release[:2]
        if version.release[:2] != paired_line:
            failures.append(
                f"pairing rule violated: this plugin is "
                f"{'.'.join(map(str, version.release[:2]))} but {PAIRED_PLUGIN} is pinned to "
                f"{'.'.join(map(str, paired_line))} - the README requires major.minor to match"
            )

    # 2. No open floor. An unbounded floor is what allowed an incompatible
    #    netbox-plugin-dns to install in 2026-10 and take NetBox down.
    if paired is not None and not any(
        s.operator in ("<", "<=", "==", "~=") for s in paired.specifier
    ):
        failures.append(
            f"{PAIRED_PLUGIN} has no upper bound ({paired.specifier}); an open floor "
            f"lets a future major install silently"
        )

    # 3. The NetBox gate must be a real range.
    if min_version is not None and max_version is not None and min_version > max_version:
        failures.append(f"min_version {min_version} is greater than max_version {max_version}")

    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1

    print(
        f"OK: plugin {version} pairs with {PAIRED_PLUGIN}{paired.specifier}; "
        f"NetBox gate {min_version} - {max_version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
