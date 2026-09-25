"""Activity logger module for Secure Document Verification System (SDVS).

Maintains an audit trail of operations in data/activity.log.
Strict security rule: NEVER log passwords, keys, or plaintext data.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

DEFAULT_LOG_PATH = Path("data") / "activity.log"


def get_log_path(custom_path: Optional[Path] = None) -> Path:
    """Returns the log path, creating the parent directory if needed."""
    path = custom_path if custom_path is not None else DEFAULT_LOG_PATH
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
    return path


def log_activity(
    operation: str,
    filename: str,
    result: str,
    log_path: Optional[Path] = None,
) -> None:
    """Appends an activity entry to the activity log.

    Format: YYYY-MM-DDTHH:MM:SS | operation | filename | result
    """
    path = get_log_path(log_path)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # Sanitize inputs to prevent log injection or delimiter collision
    clean_op = str(operation).strip().replace("|", "/")
    clean_fn = Path(str(filename)).name.strip().replace("|", "/")
    clean_res = str(result).strip().replace("\n", " ").replace("\r", "").replace("|", "/")

    entry = f"{timestamp} | {clean_op} | {clean_fn} | {clean_res}\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(entry)


def read_activity_logs(
    limit: Optional[int] = None,
    log_path: Optional[Path] = None,
) -> List[Dict[str, str]]:
    """Reads activity log entries from newest to oldest.

    Returns a list of dicts:
    [{"timestamp": ..., "operation": ..., "filename": ..., "result": ...}]
    """
    path = get_log_path(log_path)
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    entries = []
    for line in reversed(lines):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4:
            entries.append({
                "timestamp": parts[0],
                "operation": parts[1],
                "filename": parts[2],
                "result": " | ".join(parts[3:]),
            })
        elif len(parts) == 3:
            entries.append({
                "timestamp": parts[0],
                "operation": parts[1],
                "filename": parts[2],
                "result": "",
            })

    if limit is not None and limit > 0:
        return entries[:limit]
    return entries


def clear_activity_logs(log_path: Optional[Path] = None) -> None:
    """Clears all logged activity records."""
    path = get_log_path(log_path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("")

