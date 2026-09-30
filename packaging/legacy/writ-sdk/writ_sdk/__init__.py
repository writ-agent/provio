"""writ_sdk was renamed to provio_sdk (pip install provio-sdk).

Importing ``writ_sdk`` (or ``writ_sdk.<module>``) gives you the provio_sdk
module of the same name, with every ``Provio*`` / ``provio_*`` name also
reachable under its old ``Writ*`` / ``writ_*`` spelling.
"""

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

import provio_sdk as _provio_sdk

warnings.warn(
    "writ_sdk is now provio_sdk (pip install provio-sdk); update your imports: "
    "writ_sdk -> provio_sdk, Writ* -> Provio*, writ_* -> provio_*",
    DeprecationWarning,
    stacklevel=2,
)


def _alias_names(module):
    for name in list(vars(module)):
        old = name.replace("Provio", "Writ").replace("provio", "writ").replace("PROVIO", "WRIT")
        if old != name and not hasattr(module, old):
            setattr(module, old, getattr(module, name))


class _RenamedFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """`writ_sdk.x` resolves to `provio_sdk.x`."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("writ_sdk."):
            return importlib.util.spec_from_loader(fullname, self)
        return None

    def create_module(self, spec):
        new = "provio_sdk." + spec.name[len("writ_sdk."):]
        module = importlib.import_module(new)
        _alias_names(module)
        return module

    def exec_module(self, module):
        pass


sys.meta_path.insert(0, _RenamedFinder())
_alias_names(_provio_sdk)
for _name in dir(_provio_sdk):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_provio_sdk, _name)
__all__ = [n for n in dir(_provio_sdk) if not n.startswith("_")]
