"""
Patcher Registry and handler exports.
All patcher submodules are imported here so that their @register_patcher decorators run.
"""

PATCHER_REGISTRY = {}

def register_patcher(name: str):
    """
    Decorator to register a custom patch handler function.
    Enables plug-and-play extensibility for custom XML profiles.
    """
    def decorator(fn):
        PATCHER_REGISTRY[name] = fn
        return fn
    return decorator

# Auto-register all patch modules
from . import kernel_sse42
from . import kernel_nx
from . import winload
from . import winload_nx
from . import hal_nx
from . import provtool
