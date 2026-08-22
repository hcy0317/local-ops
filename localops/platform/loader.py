"""Select the native adapter without importing foreign-platform dependencies."""

from __future__ import annotations

import sys

from .contracts import PlatformBackend


def load_platform(base_dir: str, entrypoint: str) -> PlatformBackend:
    if sys.platform == "darwin":
        from .macos import MacOSPlatform

        return MacOSPlatform(base_dir=base_dir, entrypoint=entrypoint)

    if sys.platform == "win32":
        from .windows import WindowsPlatform

        return WindowsPlatform(base_dir=base_dir, entrypoint=entrypoint)

    from .unsupported import UnsupportedPlatform

    return UnsupportedPlatform(sys.platform)
