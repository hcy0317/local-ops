"""Operating-system adapters used by the shared console core."""

from .contracts import PlatformBackend
from .loader import load_platform

__all__ = ["PlatformBackend", "load_platform"]
