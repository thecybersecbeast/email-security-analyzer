"""What to actually do with a message once it's been scored."""

from __future__ import annotations

import shutil
from pathlib import Path

_VERDICT_SUBDIR = {
    "deliver": "cur",
    "quarantine": "quarantine",
    "reject": "rejected",
}


def apply_maildir_action(eml_path: Path, verdict: str, base_dir: Path) -> Path:
    """Move a processed message out of the watched 'new' directory into
    cur/, quarantine/, or rejected/ based on its verdict — mirroring how a
    real mail transfer agent milter would act before final delivery."""
    subdir = _VERDICT_SUBDIR[verdict]
    dest_dir = base_dir / subdir
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / eml_path.name
    shutil.move(str(eml_path), str(dest_path))
    return dest_path
