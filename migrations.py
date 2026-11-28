"""
Safe, idempotent SQLite schema migrations & Asia/Kolkata (IST) time helpers
for Shri R.M. Patil Multi Speciality Hospital.

- Never drops or deletes existing records during upgrades.
- Tracks applied versions in `schema_migrations`.
- Uses unambiguous Unix epoch timestamps plus Asia/Kolkata (UTC+05:30) display helpers.
"""

import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Tuple

IST = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")


def ist_today() -> str:
    """Return current date in Asia/Kolkata (YYYY-MM-DD)."""
    return datetime.now(IST).strftime("%Y-%m-%d")


def ist_now_iso() -> str:
    """Return current ISO-8601 timestamp in Asia/Kolkata (+05:30)."""
    return datetime.now(IST).isoformat(timespec="seconds")


def _m001_initial_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist', 'billing', 'patient', 'nurse', 'pharmacist', 'lab_tech')),
            department TEXT,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_number TEXT UNIQUE NOT NULL,
            reference_code TEXT UNIQUE NOT NULL,
            appointment_date TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile TEXT NOT NULL,
            department TEXT NOT NULL,
            doctor_username TEXT NOT NULL,
            message TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'confirmed', 'completed', 'cancelled')),
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_appointments_doctor ON appointments(doctor_username);
        CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date);
        CREATE INDEX IF NOT EXISTS idx_appointments_created ON appointments(created_at DESC);

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL,
            appointment_number TEXT NOT NULL,
            doctor_username TEXT NOT NULL,
            recipient_mobile TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'sms',
            notification_type TEXT NOT NULL,
            body TEXT NOT NULL,
            delivery_status TEXT NOT NULL,
            sent_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_notifications_doctor ON notifications(doctor_username, created_at DESC);

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )


def _m002_departments_and_doctors(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT UNIQUE NOT NULL,
            tag TEXT NOT NULL,
            description TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            department_code TEXT NOT NULL,
            specialization TEXT NOT NULL,
            qualification TEXT NOT NULL,
            reg_no TEXT UNIQUE NOT NULL,
            consultation_fee_inr INTEGER NOT NULL DEFAULT 500,
            slot_duration_min INTEGER NOT NULL DEFAULT 15,
            active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (department_code) REFERENCES departments(code)
        );
        """
    )

    depts = [
        ("ORTHO", "Orthopaedics", "Bone Surgery", "Bone, joint, fracture management, and trauma surgery."),
        ("OBGY", "Obstetrics & Gynaecology", "24x7 Delivery", "Normal deliveries, C-sections, and women's health care."),
        ("DENTAL", "Dental Surgery", "Dental Surgery", "Extractions, root canals, implants, and oral surgery."),
        ("MED", "General Medicine", "General Physician", "Acute & chronic illnesses, preventive care, and wellness."),
    ]
    for code, name, tag, desc in depts:
        conn.execute(
            """
            INSERT OR IGNORE INTO departments (code, name, tag, description)
            VALUES (?, ?, ?, ?)
            """,
            (code, name, tag, desc),
        )

    docs = [
        ("dr_rohan", "Dr. Rohan Patil", "ORTHO", "Consultant Orthopaedician", "MBBS, MD, D.Ortho, DNB (Ortho)", "2008/10/3539", 500, 15),
        ("dr_rahul", "Dr. Rahul Patil", "OBGY", "Consultant Obgy Specialist", "MBBS, DGO, DNB (Obs & Gyn)", "2022/12/9582", 500, 15),
        ("dr_manjusha", "Dr. Manjusha Patil", "DENTAL", "Dental Surgeon", "BDS", "A-29811", 400, 20),
        ("dr_snehal", "Dr. Snehal Patil", "MED", "General Physician", "MBBS", "A-2018/03/0645", 300, 15),
    ]
    for row in docs:
        conn.execute(
            """
            INSERT OR IGNORE INTO doctors
            (username, full_name, department_code, specialization, qualification, reg_no, consultation_fee_inr, slot_duration_min)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )



def _m003_patients_and_patient_links(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            gender TEXT NOT NULL DEFAULT '',
            blood_group TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            emergency_contact_name TEXT NOT NULL DEFAULT '',
            emergency_contact_phone TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_patients_mobile ON patients(mobile);
        """
    )
    cols = {row[1] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()}
    if "patient_code" not in cols:
        conn.execute("ALTER TABLE appointments ADD COLUMN patient_code TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_appointments_patient ON appointments(patient_code)")



def _m004_doctor_schedules_and_slots(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS doctor_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_username TEXT NOT NULL,
            day_of_week INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            break_start TEXT NOT NULL DEFAULT '',
            break_end TEXT NOT NULL DEFAULT '',
            slot_duration_min INTEGER NOT NULL DEFAULT 15,
            is_working INTEGER NOT NULL DEFAULT 1,
            UNIQUE(doctor_username, day_of_week)
        );

        CREATE TABLE IF NOT EXISTS doctor_holidays (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_username TEXT NOT NULL,
            holiday_date TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT 'Doctor on leave',
            created_at INTEGER NOT NULL,
            UNIQUE(doctor_username, holiday_date)
        );
        """
    )
    cols = {row[1] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()}
    if "slot_time" not in cols:
        conn.execute("ALTER TABLE appointments ADD COLUMN slot_time TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_appointments_active_slot
        ON appointments(doctor_username, appointment_date, slot_time)
        WHERE slot_time != '' AND status != 'cancelled'
        """
    )

    # Seed Mon-Sat schedules (0=Mon..5=Sat working, 6=Sun off) for all 4 doctors
    doctor_durations = [
        ("dr_rohan", 15),
        ("dr_rahul", 15),
        ("dr_manjusha", 20),
        ("dr_snehal", 15),
    ]
    for doc, dur in doctor_durations:
        for dow in range(7):
            is_working = 1 if dow < 6 else 0
            conn.execute(
                """
                INSERT OR IGNORE INTO doctor_schedules
                (doctor_username, day_of_week, start_time, end_time, break_start, break_end, slot_duration_min, is_working)
                VALUES (?, ?, '09:30', '18:00', '13:30', '15:00', ?, ?)
                """,
                (doc, dow, dur, is_working),
            )



def _m005_payments_qr_and_checkin(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            receipt_number TEXT UNIQUE,
            appointment_id INTEGER UNIQUE NOT NULL,
            appointment_number TEXT NOT NULL,
            amount_inr INTEGER NOT NULL,
            method TEXT NOT NULL CHECK(method IN ('pay_at_hospital', 'online_razorpay')),
            payment_status TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(payment_status IN ('PENDING', 'PAID', 'FAILED', 'REFUNDED')),
            provider_order_id TEXT UNIQUE,
            provider_payment_id TEXT UNIQUE,
            collected_by TEXT NOT NULL DEFAULT '',
            paid_at INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(payment_status);

        CREATE TABLE IF NOT EXISTS payment_webhooks (
            event_id TEXT PRIMARY KEY,
            provider_order_id TEXT NOT NULL DEFAULT '',
            received_at INTEGER NOT NULL
        );
        """
    )
    cols = {row[1] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()}
    if "qr_token" not in cols:
        conn.execute("ALTER TABLE appointments ADD COLUMN qr_token TEXT NOT NULL DEFAULT ''")
    if "checked_in_at" not in cols:
        conn.execute("ALTER TABLE appointments ADD COLUMN checked_in_at INTEGER")
    if "queue_token" not in cols:
        conn.execute("ALTER TABLE appointments ADD COLUMN queue_token TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_appointments_qr ON appointments(qr_token)")



def _m006_clinical_pharmacy_lab_billing(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL,
            patient_code TEXT NOT NULL DEFAULT '',
            doctor_username TEXT NOT NULL,
            diagnosis TEXT NOT NULL,
            medicines_text TEXT NOT NULL,
            advice TEXT NOT NULL DEFAULT '',
            follow_up_date TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_prescriptions_patient ON prescriptions(patient_code);

        CREATE TABLE IF NOT EXISTS pharmacy_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            medicine_code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            unit_price_inr INTEGER NOT NULL,
            stock_qty INTEGER NOT NULL DEFAULT 0 CHECK(stock_qty >= 0),
            reorder_level INTEGER NOT NULL DEFAULT 20,
            expiry_date TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_code TEXT UNIQUE NOT NULL,
            appointment_id INTEGER NOT NULL,
            patient_code TEXT NOT NULL DEFAULT '',
            doctor_username TEXT NOT NULL,
            test_name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Pathology',
            price_inr INTEGER NOT NULL DEFAULT 350,
            sample_status TEXT NOT NULL DEFAULT 'ordered'
                CHECK(sample_status IN ('ordered', 'collected', 'completed')),
            result_summary TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE NOT NULL,
            appointment_id INTEGER NOT NULL,
            patient_code TEXT NOT NULL DEFAULT '',
            consultation_inr INTEGER NOT NULL DEFAULT 0,
            lab_inr INTEGER NOT NULL DEFAULT 0,
            pharmacy_inr INTEGER NOT NULL DEFAULT 0,
            total_inr INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'UNPAID'
                CHECK(status IN ('UNPAID', 'PAID', 'REFUNDED')),
            created_at INTEGER NOT NULL,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );
        """
    )
    now = int(time.time())
    meds = [
        ("MED-PCM500", "Paracetamol 500mg Strip (10 tabs)", 25, 150, 30, "2028-06-30", now),
        ("MED-ORS", "Oral Rehydration Salts (ORS) Sachet", 22, 120, 25, "2027-12-31", now),
        ("MED-PAN40", "Pantoprazole 40mg Strip (10 tabs)", 65, 90, 20, "2028-03-31", now),
        ("MED-AMX500", "Amoxicillin 500mg Strip (10 caps)", 85, 18, 20, "2027-09-30", now),
    ]
    for m in meds:
        conn.execute(
            """
            INSERT OR IGNORE INTO pharmacy_inventory
            (medicine_code, name, unit_price_inr, stock_qty, reorder_level, expiry_date, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            m,
        )



def _m007_privacy_consent_refunds_billing(conn: sqlite3.Connection) -> None:
    # Ensure existing databases upgraded from older schemas allow the 'billing' role cleanly
    tbl_sql_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if tbl_sql_row and "'billing'" not in (tbl_sql_row[0] or ""):
        conn.execute("PRAGMA foreign_keys=OFF;")
        conn.executescript(
            """
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist', 'billing', 'patient', 'nurse', 'pharmacist', 'lab_tech')),
                department TEXT,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            INSERT INTO users_new SELECT id, username, full_name, role, department, password_hash, created_at FROM users;
            DROP TABLE users;
            ALTER TABLE users_new RENAME TO users;
            """
        )
        conn.execute("PRAGMA foreign_keys=ON;")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS patient_consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_code TEXT NOT NULL,
            purpose TEXT NOT NULL,
            consent_version TEXT NOT NULL DEFAULT 'v1.0',
            granted INTEGER NOT NULL CHECK(granted IN (0, 1)),
            granted_at INTEGER NOT NULL,
            withdrawn_at INTEGER,
            UNIQUE(patient_code, purpose)
        );

        CREATE TABLE IF NOT EXISTS privacy_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_code TEXT UNIQUE NOT NULL,
            patient_code TEXT NOT NULL,
            request_type TEXT NOT NULL CHECK(request_type IN ('access', 'correction', 'erasure', 'consent_withdrawal')),
            details TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'submitted'
                CHECK(status IN ('submitted', 'in_review', 'completed', 'retained_legal')),
            created_at INTEGER NOT NULL,
            resolved_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_privacy_requests_patient ON privacy_requests(patient_code);

        CREATE TABLE IF NOT EXISTS refunds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            refund_code TEXT UNIQUE NOT NULL,
            payment_id INTEGER UNIQUE NOT NULL,
            appointment_id INTEGER NOT NULL,
            amount_inr INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PROCESSED' CHECK(status IN ('INITIATED', 'PROCESSED')),
            processed_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE,
            FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
        );
        """
    )



def _m008_indexes_and_background_jobs(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_appointments_doc_date
            ON appointments(doctor_username, appointment_date);
        CREATE INDEX IF NOT EXISTS idx_appointments_status
            ON appointments(status);
        CREATE INDEX IF NOT EXISTS idx_invoices_appointment
            ON invoices(appointment_id);
        CREATE INDEX IF NOT EXISTS idx_lab_tests_appointment
            ON lab_tests(appointment_id);

        CREATE TABLE IF NOT EXISTS background_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_type TEXT NOT NULL,
            idempotency_key TEXT UNIQUE NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'completed', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            last_error TEXT NOT NULL DEFAULT '',
            run_after INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_status_run
            ON background_jobs(status, run_after);
        """
    )



def _m009_recovery_nurse_pharmacy_lab_catalog(conn: sqlite3.Connection) -> None:
    u_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in u_cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    if "phone" not in u_cols:
        conn.execute("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_pwd_reset_user ON password_reset_tokens(username, used);

        CREATE TABLE IF NOT EXISTS nurse_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_number TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('normal', 'urgent')),
            created_by TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pharmacy_bills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bill_number TEXT UNIQUE NOT NULL,
            store_name TEXT NOT NULL DEFAULT 'Shiv Medical Stores',
            patient_name TEXT NOT NULL,
            patient_mobile TEXT NOT NULL DEFAULT '',
            items_json TEXT NOT NULL,
            total_inr INTEGER NOT NULL,
            payment_method TEXT NOT NULL DEFAULT 'cash' CHECK(payment_method IN ('cash', 'upi', 'card')),
            payment_status TEXT NOT NULL DEFAULT 'PAID' CHECK(payment_status IN ('PAID', 'PENDING')),
            billed_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_pharmacy_bills_created ON pharmacy_bills(created_at DESC);

        CREATE TABLE IF NOT EXISTS pharmacy_purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_code TEXT UNIQUE NOT NULL,
            medicine_code TEXT NOT NULL,
            supplier_name TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            unit_cost_inr INTEGER NOT NULL CHECK(unit_cost_inr >= 0),
            total_cost_inr INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_test_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            catalog_code TEXT UNIQUE NOT NULL,
            test_name TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL DEFAULT 'Pathology',
            default_price_inr INTEGER NOT NULL CHECK(default_price_inr >= 0),
            added_by TEXT NOT NULL DEFAULT 'system',
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        """
    )
    now = int(time.time())
    defaults = [
        ("CAT-CBC", "Complete Blood Count (CBC)", "Pathology", 350, "system", now),
        ("CAT-BSL", "Blood Sugar (FBS / PPBS)", "Biochemistry", 150, "system", now),
        ("CAT-ELEC", "Serum Electrolytes", "Biochemistry", 450, "system", now),
        ("CAT-XRAY", "Digital X-Ray", "Radiology", 400, "system", now),
    ]
    for row in defaults:
        conn.execute(
            """
            INSERT OR IGNORE INTO lab_test_catalog
            (catalog_code, test_name, category, default_price_inr, added_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            row,
        )


MIGRATIONS: List[Tuple[str, Callable[[sqlite3.Connection], None]]] = [
    ("001_initial_schema", _m001_initial_schema),
    ("002_departments_and_doctors", _m002_departments_and_doctors),
    ("003_patients_and_patient_links", _m003_patients_and_patient_links),
    ("004_doctor_schedules_and_slots", _m004_doctor_schedules_and_slots),
    ("005_payments_qr_and_checkin", _m005_payments_qr_and_checkin),
    ("006_clinical_pharmacy_lab_billing", _m006_clinical_pharmacy_lab_billing),
    ("007_privacy_consent_refunds_billing", _m007_privacy_consent_refunds_billing),
    ("008_indexes_and_background_jobs", _m008_indexes_and_background_jobs),
    ("009_recovery_nurse_pharmacy_lab_catalog", _m009_recovery_nurse_pharmacy_lab_catalog),
]


def run_migrations(conn: sqlite3.Connection) -> List[str]:
    """Apply all pending migrations inside transactions without touching existing data."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            applied_at_ist TEXT NOT NULL
        );
        """
    )
    applied = {
        row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
    }
    newly_applied: List[str] = []
    for version, fn in MIGRATIONS:
        if version in applied:
            continue
        with conn:
            fn(conn)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at, applied_at_ist) VALUES (?, ?, ?)",
                (version, int(time.time()), ist_now_iso()),
            )
            newly_applied.append(version)
    return newly_applied


if __name__ == "__main__":
    import os
    db_file = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "hospital.db"))
    os.makedirs(os.path.dirname(os.path.abspath(db_file)), exist_ok=True)
    connection = sqlite3.connect(db_file)
    connection.execute("PRAGMA foreign_keys=ON;")
    applied_now = run_migrations(connection)
    all_versions = [r[0] for r in connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
    connection.close()
    print(f"Asia/Kolkata time: {ist_now_iso()}")
    print(f"Newly applied: {applied_now}")
    print(f"Current schema versions: {all_versions}")
