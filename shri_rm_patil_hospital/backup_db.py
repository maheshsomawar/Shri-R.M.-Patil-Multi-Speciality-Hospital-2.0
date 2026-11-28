"""
Safe Online SQLite Backup & Integrity Verification Script
for Shri R.M. Patil Multi Speciality Hospital.

- Uses SQLite's native online backup API (safe while server.py is serving live WAL traffic)
- Timestamps backups in Asia/Kolkata (IST)
- Verifies every backup with PRAGMA integrity_check
- Restricts backup file permissions (0o600) and prunes old backups automatically
"""

import glob
import os
import sqlite3
from datetime import datetime

from migrations import IST

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_backup(
    db_path: str | None = None,
    backup_dir: str | None = None,
    keep_latest: int = 14,
) -> dict:
    src_path = db_path or os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "hospital.db"))
    if not os.path.isfile(src_path):
        raise FileNotFoundError(f"Database file not found: {src_path}")

    out_dir = backup_dir or os.path.join(BASE_DIR, "backups", "db")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(IST).strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(out_dir, f"hospital_{ts}.db")

    src_conn = sqlite3.connect(src_path, timeout=10.0)
    dest_conn = sqlite3.connect(dest_path)
    try:
        src_conn.backup(dest_conn)
        check_res = dest_conn.execute("PRAGMA integrity_check;").fetchone()[0]
    finally:
        dest_conn.close()
        src_conn.close()

    try:
        os.chmod(dest_path, 0o600)
    except OSError:
        pass

    if check_res != "ok":
        os.remove(dest_path)
        raise RuntimeError(f"Backup integrity check failed: {check_res}")

    # Prune backups beyond keep_latest
    existing = sorted(glob.glob(os.path.join(out_dir, "hospital_*.db")))
    pruned = 0
    while len(existing) > max(1, keep_latest):
        old_file = existing.pop(0)
        os.remove(old_file)
        pruned += 1

    return {
        "status": "ok",
        "source": src_path,
        "backup_file": dest_path,
        "integrity_check": check_res,
        "pruned_old_backups": pruned,
    }


if __name__ == "__main__":
    import json
    result = run_backup()
    print(json.dumps(result, indent=2))
