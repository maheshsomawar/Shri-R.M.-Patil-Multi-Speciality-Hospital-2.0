"""
SQLite Query Plan & Index Verification Tool (Part 12)
for Shri R.M. Patil Multi Speciality Hospital.

Runs EXPLAIN QUERY PLAN on critical hot hospital queries and verifies
that every query uses an index (zero accidental full table scans).
"""

import json
import os
import sqlite3
import tempfile
from typing import Any, Dict, List

from migrations import run_migrations

HOT_QUERIES = [
    (
        "Doctor daily appointment lookup",
        "SELECT id, appointment_number FROM appointments WHERE doctor_username = ? AND appointment_date = ?",
        ("dr_rohan", "2026-11-27"),
    ),
    (
        "Active slot conflict check",
        "SELECT id FROM appointments WHERE doctor_username = ? AND appointment_date = ? AND slot_time = ? AND status != 'cancelled'",
        ("dr_rohan", "2026-11-27", "10:00"),
    ),
    (
        "QR code check-in verification",
        "SELECT id, status FROM appointments WHERE qr_token = ?",
        ("QR-TESTTOKEN",),
    ),
    (
        "Patient own appointment lookup",
        "SELECT id, appointment_number FROM appointments WHERE patient_code = ?",
        ("PAT-20261127-001",),
    ),
    (
        "Appointment status filter",
        "SELECT id FROM appointments WHERE status = ?",
        ("confirmed",),
    ),
    (
        "Payment lookup by appointment",
        "SELECT id, payment_status FROM payments WHERE appointment_id = ?",
        (1,),
    ),
    (
        "Background job queue poll",
        "SELECT id, job_type FROM background_jobs WHERE status = 'pending' ORDER BY run_after ASC LIMIT 10",
        (),
    ),
]


def verify_query_plans(db_path: str | None = None) -> Dict[str, Any]:
    tmp = None
    if not db_path:
        tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(tmp.name, "plan_check.db")

    conn = sqlite3.connect(db_path)
    run_migrations(conn)
    conn.execute("ANALYZE;")

    results: List[Dict[str, Any]] = []
    all_indexed = True
    for name, sql, params in HOT_QUERIES:
        rows = conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()
        plan_text = " | ".join(str(r[3]) for r in rows)
        uses_index = "USING INDEX" in plan_text or "USING COVERING INDEX" in plan_text
        if not uses_index:
            all_indexed = False
        results.append({"query": name, "indexed": uses_index, "plan": plan_text})

    conn.close()
    if tmp:
        tmp.cleanup()

    return {"all_indexed": all_indexed, "checked_queries": len(results), "plans": results}


if __name__ == "__main__":
    report = verify_query_plans()
    print(json.dumps(report, indent=2))
    if not report["all_indexed"]:
        raise SystemExit(1)
