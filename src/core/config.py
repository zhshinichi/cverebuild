"""Centralized configuration helpers."""
from __future__ import annotations

import os


def get_shared_root() -> str:
    """
    Resolve the shared directory location.
    Preference order:
    1) env SHARED_DIR
    2) /workspaces/submission/src/shared (devcontainer)
    3) /shared (container)
    """
    env_dir = os.environ.get("SHARED_DIR")
    if env_dir:
        return env_dir

    devcontainer_shared = "/workspaces/submission/src/shared"
    if os.path.exists(os.path.dirname(devcontainer_shared)):
        return devcontainer_shared

    return "/shared"
