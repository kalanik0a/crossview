"""Filesystem path resolution.

Default location order (override any time with the ``CROSSVIEW_DATA_DIR`` env var):

  1. ``CROSSVIEW_DATA_DIR`` if set.
  2. ``<repo>/data`` when running from a writable source checkout — detected by a
     ``pyproject.toml`` next to the package. Keeps dev data in-tree as before.
  3. ``$XDG_DATA_HOME/crossview`` (falling back to ``~/.local/share/crossview``)
     for installed packages, where the package itself lives in a read-only
     location such as the nix store and cannot host a writable ``data/`` dir.
"""
import os
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _default_data_dir() -> Path:
    env = os.environ.get("CROSSVIEW_DATA_DIR")
    if env:
        return Path(env).expanduser()
    # Source checkout: repo root carries pyproject.toml and is writable.
    if (_PROJECT_ROOT / "pyproject.toml").is_file() and os.access(_PROJECT_ROOT, os.W_OK):
        return _PROJECT_ROOT / "data"
    # Installed package (read-only store / site-packages): XDG user data dir.
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "crossview"


DATA_DIR = _default_data_dir()
RAW_DIR = DATA_DIR / "raw"
DB_PATH = DATA_DIR / "crossview.db"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
