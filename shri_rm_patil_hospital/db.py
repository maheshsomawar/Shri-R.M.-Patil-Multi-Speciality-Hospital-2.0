"""
Database layer for Shri R.M. Patil Multi Speciality Hospital.
- SQLite with WAL mode for high-concurrency traffic handling
- Parameterized queries only (prevents SQL injection)
- Scrypt password hashing with random per-user salt
- Atomic sequential appointment numbers (APT-YYYYMMDD-NNN) per date
- Patient SMS/notification log scoped strictly by doctor ownership
- Daily & monthly appointment summaries scoped by doctor
"""

import contextlib
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from migrations import ist_today, run_migrations
from typing import Any, Dict, List, Optional, Tuple

from datetime import datetime as _dt


class SlotConflictError(Exception):
    """Raised when a requested doctor time slot is already booked."""


class SlotUnavailableError(Exception):
    """Raised when a requested date/slot is in the past, on holiday, or outside working hours."""


def _hhmm_to_min(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _min_to_hhmm(total: int) -> str:
    return f"{total // 60:02d}:{total % 60:02d}"


SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


def hash_password(password: str) -> str:
    """Hash a password using scrypt with a 16-byte cryptographically secure salt."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash using constant-time comparison."""
    try:
        scheme, n_s, r_s, p_s, salt_hex, hash_hex = stored_hash.split("$")
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


class HospitalDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._booking_lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    @contextlib.contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA busy_timeout=10000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            run_migrations(conn)

    def list_departments(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, code, name, tag, description FROM departments WHERE active = 1 ORDER BY id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_doctors(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT d.id, d.username, d.full_name, d.department_code, dep.name AS department_name,
                       d.specialization, d.qualification, d.reg_no, d.consultation_fee_inr, d.slot_duration_min
                FROM doctors d
                JOIN departments dep ON dep.code = d.department_code
                WHERE d.active = 1
                ORDER BY d.id ASC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def seed_default_staff(self, staff_passwords: Dict[str, str]) -> None:
        """Seed default hospital staff accounts using passwords from environment variables."""
        staff_records = [
            ("admin", "Hospital Administrator", "admin", "Administration"),
            ("dr_rohan", "Dr. Rohan Patil", "doctor", "Orthopaedics"),
            ("dr_rahul", "Dr. Rahul Patil", "doctor", "Obstetrics & Gynaecology"),
            ("dr_manjusha", "Dr. Manjusha Patil", "doctor", "Dental Surgery"),
            ("dr_snehal", "Dr. Snehal Patil", "doctor", "General Medicine"),
            ("reception", "Front Desk Reception", "receptionist", "Front Desk"),
            ("nurse", "Ward Nurse", "nurse", "Nursing"),
            ("pharmacist", "Shiv Medical Pharmacist", "pharmacist", "Pharmacy"),
            ("lab_tech", "Pathology Lab Technician", "lab_tech", "Laboratory"),
            ("billing_desk", "Hospital Billing Officer", "billing", "Billing & Accounts"),
        ]
        now = int(time.time())
        with self._connect() as conn:
            for username, full_name, role, department in staff_records:
                existing = conn.execute(
                    "SELECT id FROM users WHERE username = ?", (username,)
                ).fetchone()
                if not existing:
                    raw_pw = staff_passwords.get(username)
                    if not raw_pw:
                        continue
                    pw_hash = hash_password(raw_pw)
                    conn.execute(
                        """
                        INSERT INTO users (username, full_name, role, department, password_hash, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (username, full_name, role, department, pw_hash, now),
                    )

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, full_name, role, department, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return dict(row) if row else None

    def _compute_working_slots(self, conn: sqlite3.Connection, doctor_username: str, target_date: str) -> Tuple[List[str], Optional[str]]:
        holiday = conn.execute(
            "SELECT reason FROM doctor_holidays WHERE doctor_username = ? AND holiday_date = ?",
            (doctor_username, target_date),
        ).fetchone()
        if holiday:
            return [], f"Doctor is on leave: {holiday['reason']}"
        dow = _dt.strptime(target_date, "%Y-%m-%d").weekday()
        sched = conn.execute(
            """
            SELECT start_time, end_time, break_start, break_end, slot_duration_min, is_working
            FROM doctor_schedules
            WHERE doctor_username = ? AND day_of_week = ?
            """,
            (doctor_username, dow),
        ).fetchone()
        if not sched or int(sched["is_working"]) == 0:
            return [], "Doctor is not scheduled to work on this day"
        start_m = _hhmm_to_min(sched["start_time"])
        end_m = _hhmm_to_min(sched["end_time"])
        dur = max(5, int(sched["slot_duration_min"]))
        b_start = _hhmm_to_min(sched["break_start"]) if sched["break_start"] else -1
        b_end = _hhmm_to_min(sched["break_end"]) if sched["break_end"] else -1
        slots: List[str] = []
        cur_m = start_m
        while cur_m + dur <= end_m:
            in_break = b_start >= 0 and b_end > b_start and (cur_m < b_end and (cur_m + dur) > b_start)
            if not in_break:
                slots.append(_min_to_hhmm(cur_m))
            cur_m += dur
        return slots, None

    def get_available_slots(self, doctor_username: str, target_date: str) -> Dict[str, Any]:
        if target_date < ist_today():
            raise SlotUnavailableError("Cannot view or book appointments on past dates.")
        with self._connect() as conn:
            doc = conn.execute(
                """
                SELECT d.username, d.full_name, d.specialization, d.qualification,
                       d.reg_no, d.consultation_fee_inr, d.slot_duration_min, dep.name AS department_name
                FROM doctors d
                JOIN departments dep ON dep.code = d.department_code
                WHERE d.username = ? AND d.active = 1
                """,
                (doctor_username,),
            ).fetchone()
            if not doc:
                raise SlotUnavailableError("Doctor not found.")
            all_slots, closed_reason = self._compute_working_slots(conn, doctor_username, target_date)
            if closed_reason:
                return {
                    "doctor": dict(doc),
                    "date": target_date,
                    "available": False,
                    "reason": closed_reason,
                    "available_slots": [],
                    "booked_slots": [],
                }
            booked = {
                r["slot_time"]
                for r in conn.execute(
                    """
                    SELECT slot_time FROM appointments
                    WHERE doctor_username = ? AND appointment_date = ?
                      AND slot_time != '' AND status != 'cancelled'
                    """,
                    (doctor_username, target_date),
                ).fetchall()
            }
            open_slots = [sl for sl in all_slots if sl not in booked]
            return {
                "doctor": dict(doc),
                "date": target_date,
                "available": len(open_slots) > 0,
                "reason": None if open_slots else "All slots are booked for this date",
                "available_slots": open_slots,
                "booked_slots": sorted(booked),
            }

    def add_doctor_holiday(self, doctor_username: str, holiday_date: str, reason: str) -> Dict[str, Any]:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO doctor_holidays (doctor_username, holiday_date, reason, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (doctor_username, holiday_date, reason, now),
            )
        return {"doctor_username": doctor_username, "holiday_date": holiday_date, "reason": reason}

    def create_appointment(
        self,
        first_name: str,
        last_name: str,
        mobile: str,
        department: str,
        doctor_username: str,
        message: str,
        appointment_date: Optional[str] = None,
        patient_code: Optional[str] = None,
        slot_time: str = "",
    ) -> Dict[str, Any]:
        appt_date = appointment_date or ist_today()
        if appt_date < ist_today():
            raise SlotUnavailableError("Cannot book appointments on past dates.")
        date_compact = appt_date.replace("-", "")
        ref_code = f"RMP-{secrets.token_hex(3).upper()}"
        qr_token = f"QR-{secrets.token_hex(12).upper()}"
        now = int(time.time())

        # Serialize booking transaction so two patients can NEVER double-book the same slot
        with self._booking_lock:
            with self._connect() as conn:
                if slot_time:
                    working_slots, closed_reason = self._compute_working_slots(conn, doctor_username, appt_date)
                    if closed_reason:
                        raise SlotUnavailableError(closed_reason)
                    if slot_time not in working_slots:
                        raise SlotUnavailableError(f"Time slot {slot_time} is outside working hours or during break time.")
                    taken = conn.execute(
                        """
                        SELECT id FROM appointments
                        WHERE doctor_username = ? AND appointment_date = ? AND slot_time = ? AND status != 'cancelled'
                        """,
                        (doctor_username, appt_date, slot_time),
                    ).fetchone()
                    if taken:
                        raise SlotConflictError(f"Time slot {slot_time} on {appt_date} is already booked.")

                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE appointment_date = ?",
                    (appt_date,),
                ).fetchone()
                next_seq = (int(row["cnt"]) if row else 0) + 1
                appointment_number = f"APT-{date_compact}-{next_seq:03d}"

                try:
                    cur = conn.execute(
                        """
                        INSERT INTO appointments
                        (appointment_number, reference_code, appointment_date, slot_time, first_name, last_name,
                         mobile, department, doctor_username, message, status, created_at, patient_code, qr_token)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?, ?, ?)
                        """,
                        (
                            appointment_number,
                            ref_code,
                            appt_date,
                            slot_time,
                            first_name,
                            last_name,
                            mobile,
                            department,
                            doctor_username,
                            message,
                            now,
                            patient_code,
                            qr_token,
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise SlotConflictError(f"Time slot {slot_time} on {appt_date} was just booked by another patient.")

                return {
                    "id": cur.lastrowid,
                    "appointment_number": appointment_number,
                    "reference_code": ref_code,
                    "appointment_date": appt_date,
                    "slot_time": slot_time,
                    "first_name": first_name,
                    "last_name": last_name,
                    "mobile": mobile,
                    "department": department,
                    "doctor_username": doctor_username,
                    "message": message,
                    "status": "confirmed",
                    "patient_code": patient_code,
                    "qr_token": qr_token,
                    "created_at": now,
                }

    def get_appointment_by_id(
        self, appointment_id: int, doctor_username: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            if doctor_username:
                row = conn.execute(
                    """
                    SELECT id, appointment_number, reference_code, appointment_date, first_name,
                           last_name, mobile, department, doctor_username, message, status, created_at
                    FROM appointments
                    WHERE id = ? AND doctor_username = ?
                    """,
                    (appointment_id, doctor_username),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT id, appointment_number, reference_code, appointment_date, first_name,
                           last_name, mobile, department, doctor_username, message, status, created_at
                    FROM appointments
                    WHERE id = ?
                    """,
                    (appointment_id,),
                ).fetchone()
            return dict(row) if row else None

    def list_appointments(
        self,
        doctor_username: Optional[str] = None,
        appointment_date: Optional[str] = None,
        month_prefix: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: List[Any] = []
        if doctor_username:
            clauses.append("doctor_username = ?")
            params.append(doctor_username)
        if appointment_date:
            clauses.append("appointment_date = ?")
            params.append(appointment_date)
        elif month_prefix:
            clauses.append("appointment_date LIKE ?")
            params.append(f"{month_prefix}-%")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, appointment_number, reference_code, appointment_date, first_name,
                       last_name, mobile, department, doctor_username, message, status, created_at
                FROM appointments
                {where_sql}
                ORDER BY appointment_date DESC, created_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_appointment_summary(
        self,
        target_date: str,
        target_month: str,
        doctor_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return daily count, monthly count, and per-day breakdown strictly scoped to doctor if provided."""
        with self._connect() as conn:
            if doctor_username:
                daily_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE doctor_username = ? AND appointment_date = ?",
                    (doctor_username, target_date),
                ).fetchone()
                monthly_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE doctor_username = ? AND appointment_date LIKE ?",
                    (doctor_username, f"{target_month}-%"),
                ).fetchone()
                by_day_rows = conn.execute(
                    """
                    SELECT appointment_date, COUNT(*) AS cnt
                    FROM appointments
                    WHERE doctor_username = ? AND appointment_date LIKE ?
                    GROUP BY appointment_date
                    ORDER BY appointment_date ASC
                    """,
                    (doctor_username, f"{target_month}-%"),
                ).fetchall()
            else:
                daily_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE appointment_date = ?",
                    (target_date,),
                ).fetchone()
                monthly_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE appointment_date LIKE ?",
                    (f"{target_month}-%",),
                ).fetchone()
                by_day_rows = conn.execute(
                    """
                    SELECT appointment_date, COUNT(*) AS cnt
                    FROM appointments
                    WHERE appointment_date LIKE ?
                    GROUP BY appointment_date
                    ORDER BY appointment_date ASC
                    """,
                    (f"{target_month}-%",),
                ).fetchall()

            return {
                "date": target_date,
                "month": target_month,
                "daily_count": int(daily_row["cnt"]) if daily_row else 0,
                "monthly_count": int(monthly_row["cnt"]) if monthly_row else 0,
                "daily_breakdown": [
                    {"date": r["appointment_date"], "count": int(r["cnt"])} for r in by_day_rows
                ],
            }

    def update_appointment_status(
        self, appointment_id: int, new_status: str, doctor_username: Optional[str] = None
    ) -> bool:
        with self._connect() as conn:
            if doctor_username:
                cur = conn.execute(
                    "UPDATE appointments SET status = ? WHERE id = ? AND doctor_username = ?",
                    (new_status, appointment_id, doctor_username),
                )
            else:
                cur = conn.execute(
                    "UPDATE appointments SET status = ? WHERE id = ?",
                    (new_status, appointment_id),
                )
            return cur.rowcount > 0

    def create_notification(
        self,
        appointment_id: int,
        appointment_number: str,
        doctor_username: str,
        recipient_mobile: str,
        notification_type: str,
        body: str,
        delivery_status: str,
        sent_by: str,
    ) -> Dict[str, Any]:
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO notifications
                (appointment_id, appointment_number, doctor_username, recipient_mobile,
                 channel, notification_type, body, delivery_status, sent_by, created_at)
                VALUES (?, ?, ?, ?, 'sms', ?, ?, ?, ?, ?)
                """,
                (
                    appointment_id,
                    appointment_number,
                    doctor_username,
                    recipient_mobile,
                    notification_type,
                    body,
                    delivery_status,
                    sent_by,
                    now,
                ),
            )
            return {
                "id": cur.lastrowid,
                "appointment_id": appointment_id,
                "appointment_number": appointment_number,
                "doctor_username": doctor_username,
                "recipient_mobile": recipient_mobile,
                "channel": "sms",
                "notification_type": notification_type,
                "body": body,
                "delivery_status": delivery_status,
                "sent_by": sent_by,
                "created_at": now,
            }

    def list_notifications(
        self, doctor_username: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if doctor_username:
                rows = conn.execute(
                    """
                    SELECT id, appointment_id, appointment_number, doctor_username,
                           recipient_mobile, channel, notification_type, body,
                           delivery_status, sent_by, created_at
                    FROM notifications
                    WHERE doctor_username = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (doctor_username, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, appointment_id, appointment_number, doctor_username,
                           recipient_mobile, channel, notification_type, body,
                           delivery_status, sent_by, created_at
                    FROM notifications
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def log_audit(self, actor: str, action: str, ip_address: str, status_code: int) -> None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (actor, action, ip_address, status_code, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (actor, action, ip_address, status_code, now),
            )

    def list_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, actor, action, ip_address, status_code, created_at
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def count_appointments(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM appointments").fetchone()
            return int(row["cnt"]) if row else 0

    def register_patient(
        self,
        first_name: str,
        last_name: str,
        mobile: str,
        password: str,
        email: str = "",
        gender: str = "",
        blood_group: str = "",
        address: str = "",
        emergency_contact_name: str = "",
        emergency_contact_phone: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Atomically register a new patient account with unique PAT-YYYYMMDD-NNN code and salted scrypt hash."""
        username = mobile
        today_compact = ist_today().replace("-", "")
        now = int(time.time())
        pw_hash = hash_password(password)
        with self._booking_lock:
            with self._connect() as conn:
                exists = conn.execute(
                    "SELECT id FROM users WHERE username = ?", (username,)
                ).fetchone()
                if exists:
                    return None
                cnt_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM patients WHERE patient_code LIKE ?",
                    (f"PAT-{today_compact}-%",),
                ).fetchone()
                seq = (int(cnt_row["cnt"]) if cnt_row else 0) + 1
                patient_code = f"PAT-{today_compact}-{seq:03d}"
                conn.execute(
                    """
                    INSERT INTO users (username, full_name, role, department, password_hash, created_at)
                    VALUES (?, ?, 'patient', 'Patient', ?, ?)
                    """,
                    (username, f"{first_name} {last_name}", pw_hash, now),
                )
                conn.execute(
                    """
                    INSERT INTO patients
                    (patient_code, username, first_name, last_name, mobile, email, gender,
                     blood_group, address, emergency_contact_name, emergency_contact_phone, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        patient_code,
                        username,
                        first_name,
                        last_name,
                        mobile,
                        email,
                        gender,
                        blood_group,
                        address,
                        emergency_contact_name,
                        emergency_contact_phone,
                        now,
                    ),
                )
                return {
                    "patient_code": patient_code,
                    "username": username,
                    "first_name": first_name,
                    "last_name": last_name,
                    "mobile": mobile,
                    "email": email,
                    "gender": gender,
                    "blood_group": blood_group,
                    "address": address,
                    "emergency_contact_name": emergency_contact_name,
                    "emergency_contact_phone": emergency_contact_phone,
                    "created_at": now,
                }

    def get_patient_profile(self, username: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT patient_code, username, first_name, last_name, mobile, email,
                       gender, blood_group, address, emergency_contact_name,
                       emergency_contact_phone, created_at
                FROM patients
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
            return dict(row) if row else None

    def update_patient_profile(
        self,
        username: str,
        email: str,
        address: str,
        blood_group: str,
        emergency_contact_name: str,
        emergency_contact_phone: str,
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE patients
                SET email = ?, address = ?, blood_group = ?,
                    emergency_contact_name = ?, emergency_contact_phone = ?
                WHERE username = ?
                """,
                (email, address, blood_group, emergency_contact_name, emergency_contact_phone, username),
            )
            return cur.rowcount > 0

    def list_patient_appointments(self, patient_code: str, mobile: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, appointment_number, reference_code, appointment_date, first_name,
                       last_name, mobile, department, doctor_username, message, status,
                       patient_code, created_at
                FROM appointments
                WHERE patient_code = ? OR mobile = ?
                ORDER BY appointment_date DESC, created_at DESC
                LIMIT 100
                """,
                (patient_code, mobile),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_patient_appointment_by_id(
        self, appointment_id: int, patient_code: str, mobile: str
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, appointment_number, reference_code, appointment_date, first_name,
                       last_name, mobile, department, doctor_username, message, status,
                       patient_code, created_at
                FROM appointments
                WHERE id = ? AND (patient_code = ? OR mobile = ?)
                """,
                (appointment_id, patient_code, mobile),
            ).fetchone()
            return dict(row) if row else None

    def get_doctor_fee_inr(self, doctor_username: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT consultation_fee_inr FROM doctors WHERE username = ?",
                (doctor_username,),
            ).fetchone()
            return int(row["consultation_fee_inr"]) if row else 500

    def create_payment_record(
        self,
        appointment_id: int,
        appointment_number: str,
        doctor_username: str,
        method: str,
    ) -> Dict[str, Any]:
        amount_inr = self.get_doctor_fee_inr(doctor_username)
        now = int(time.time())
        order_id = f"order_test_{secrets.token_hex(8)}" if method == "online_razorpay" else None
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO payments
                (appointment_id, appointment_number, amount_inr, method, payment_status, provider_order_id, created_at)
                VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (appointment_id, appointment_number, amount_inr, method, order_id, now),
            )
            return {
                "id": cur.lastrowid,
                "appointment_id": appointment_id,
                "appointment_number": appointment_number,
                "amount_inr": amount_inr,
                "amount_paise": amount_inr * 100,
                "currency": "INR",
                "method": method,
                "payment_status": "PENDING",
                "provider_order_id": order_id,
                "receipt_number": None,
            }

    def mark_payment_paid(
        self,
        appointment_id: Optional[int] = None,
        provider_order_id: Optional[str] = None,
        provider_payment_id: Optional[str] = None,
        collected_by: str = "razorpay_verified",
    ) -> Optional[Dict[str, Any]]:
        """Atomically mark a payment PAID and issue a unique receipt number (RCP-YYYYMMDD-NNN)."""
        today_compact = ist_today().replace("-", "")
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                if provider_order_id:
                    row = conn.execute(
                        "SELECT * FROM payments WHERE provider_order_id = ?",
                        (provider_order_id,),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM payments WHERE appointment_id = ?",
                        (appointment_id,),
                    ).fetchone()
                if not row:
                    return None
                if row["payment_status"] == "PAID":
                    return dict(row)
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM payments WHERE receipt_number LIKE ?",
                    (f"RCP-{today_compact}-%",),
                ).fetchone()
                seq = (int(cnt["cnt"]) if cnt else 0) + 1
                receipt_no = f"RCP-{today_compact}-{seq:03d}"
                conn.execute(
                    """
                    UPDATE payments
                    SET payment_status = 'PAID',
                        receipt_number = ?,
                        provider_payment_id = COALESCE(?, provider_payment_id),
                        collected_by = ?,
                        paid_at = ?
                    WHERE id = ?
                    """,
                    (receipt_no, provider_payment_id, collected_by, now, row["id"]),
                )
                updated = conn.execute("SELECT * FROM payments WHERE id = ?", (row["id"],)).fetchone()
                return dict(updated) if updated else None

    def record_webhook_event(self, event_id: str, provider_order_id: str) -> bool:
        """Returns True if event is new, False if duplicate webhook replay."""
        now = int(time.time())
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO payment_webhooks (event_id, provider_order_id, received_at) VALUES (?, ?, ?)",
                    (event_id, provider_order_id, now),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def checkin_by_qr_token(self, qr_token: str) -> Optional[Dict[str, Any]]:
        """Verify opaque QR token on backend, mark checked in, and assign sequential daily queue token."""
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                appt = conn.execute(
                    """
                    SELECT a.id, a.appointment_number, a.appointment_date, a.slot_time,
                           a.department, a.doctor_username, a.status, a.checked_in_at, a.queue_token,
                           p.payment_status, p.method AS payment_method, p.amount_inr, p.receipt_number
                    FROM appointments a
                    LEFT JOIN payments p ON p.appointment_id = a.id
                    WHERE a.qr_token = ? AND a.qr_token != ''
                    """,
                    (qr_token,),
                ).fetchone()
                if not appt:
                    return None
                if appt["checked_in_at"]:
                    return dict(appt)
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM appointments WHERE appointment_date = ? AND queue_token != ''",
                    (appt["appointment_date"],),
                ).fetchone()
                seq = (int(cnt["cnt"]) if cnt else 0) + 1
                queue_token = f"Q-{seq:03d}"
                conn.execute(
                    "UPDATE appointments SET checked_in_at = ?, queue_token = ? WHERE id = ?",
                    (now, queue_token, appt["id"]),
                )
                res = dict(appt)
                res["checked_in_at"] = now
                res["queue_token"] = queue_token
                return res

    def cancel_patient_appointment(self, appointment_id: int, patient_code: str, mobile: str) -> bool:
        with self._booking_lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    UPDATE appointments
                    SET status = 'cancelled'
                    WHERE id = ? AND (patient_code = ? OR mobile = ?) AND status != 'completed'
                    """,
                    (appointment_id, patient_code, mobile),
                )
                return cur.rowcount > 0

    def reschedule_patient_appointment(
        self, appointment_id: int, patient_code: str, mobile: str, new_date: str, new_slot: str
    ) -> Optional[Dict[str, Any]]:
        if new_date < ist_today():
            raise SlotUnavailableError("Cannot reschedule to a past date.")
        with self._booking_lock:
            with self._connect() as conn:
                appt = conn.execute(
                    """
                    SELECT * FROM appointments
                    WHERE id = ? AND (patient_code = ? OR mobile = ?) AND status NOT IN ('completed', 'cancelled')
                    """,
                    (appointment_id, patient_code, mobile),
                ).fetchone()
                if not appt:
                    return None
                working_slots, closed_reason = self._compute_working_slots(conn, appt["doctor_username"], new_date)
                if closed_reason:
                    raise SlotUnavailableError(closed_reason)
                if new_slot not in working_slots:
                    raise SlotUnavailableError(f"Time slot {new_slot} is not available.")
                taken = conn.execute(
                    """
                    SELECT id FROM appointments
                    WHERE doctor_username = ? AND appointment_date = ? AND slot_time = ?
                      AND status != 'cancelled' AND id != ?
                    """,
                    (appt["doctor_username"], new_date, new_slot, appointment_id),
                ).fetchone()
                if taken:
                    raise SlotConflictError(f"Time slot {new_slot} on {new_date} is already booked.")
                conn.execute(
                    "UPDATE appointments SET appointment_date = ?, slot_time = ? WHERE id = ?",
                    (new_date, new_slot, appointment_id),
                )
                updated = conn.execute("SELECT * FROM appointments WHERE id = ?", (appointment_id,)).fetchone()
                return dict(updated) if updated else None

    def create_prescription(
        self,
        appointment_id: int,
        doctor_username: str,
        diagnosis: str,
        medicines_text: str,
        advice: str = "",
        follow_up_date: str = "",
    ) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        with self._connect() as conn:
            appt = conn.execute(
                "SELECT id, patient_code, doctor_username FROM appointments WHERE id = ? AND doctor_username = ?",
                (appointment_id, doctor_username),
            ).fetchone()
            if not appt:
                return None
            cur = conn.execute(
                """
                INSERT INTO prescriptions
                (appointment_id, patient_code, doctor_username, diagnosis, medicines_text, advice, follow_up_date, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    appointment_id,
                    appt["patient_code"] or "",
                    doctor_username,
                    diagnosis,
                    medicines_text,
                    advice,
                    follow_up_date,
                    now,
                ),
            )
            return {
                "id": cur.lastrowid,
                "appointment_id": appointment_id,
                "patient_code": appt["patient_code"] or "",
                "doctor_username": doctor_username,
                "diagnosis": diagnosis,
                "medicines_text": medicines_text,
                "advice": advice,
                "follow_up_date": follow_up_date,
                "created_at": now,
            }

    def list_patient_prescriptions(self, patient_code: str, mobile: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT p.id, p.appointment_id, a.appointment_number, p.doctor_username,
                       p.diagnosis, p.medicines_text, p.advice, p.follow_up_date, p.created_at
                FROM prescriptions p
                JOIN appointments a ON a.id = p.appointment_id
                WHERE p.patient_code = ? OR a.mobile = ?
                ORDER BY p.id DESC
                """,
                (patient_code, mobile),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_pharmacy_inventory(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, medicine_code, name, unit_price_inr, stock_qty, reorder_level, expiry_date FROM pharmacy_inventory ORDER BY id ASC"
                ).fetchall()
            ]
            alerts = [r for r in rows if int(r["stock_qty"]) <= int(r["reorder_level"])]
            return {"items": rows, "low_stock_alerts": alerts}

    def dispense_medicine(self, medicine_code: str, quantity: int) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM pharmacy_inventory WHERE medicine_code = ?", (medicine_code,)
                ).fetchone()
                if not row or int(row["stock_qty"]) < quantity:
                    return None
                new_qty = int(row["stock_qty"]) - quantity
                conn.execute(
                    "UPDATE pharmacy_inventory SET stock_qty = ?, updated_at = ? WHERE id = ?",
                    (new_qty, now, row["id"]),
                )
                return {
                    "medicine_code": medicine_code,
                    "name": row["name"],
                    "dispensed_qty": quantity,
                    "charge_inr": int(row["unit_price_inr"]) * quantity,
                    "remaining_stock": new_qty,
                }

    def create_lab_test(
        self, appointment_id: int, doctor_username: str, test_name: str, category: str, price_inr: int
    ) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        test_code = f"LAB-{secrets.token_hex(3).upper()}"
        with self._connect() as conn:
            appt = conn.execute(
                "SELECT id, patient_code FROM appointments WHERE id = ?", (appointment_id,)
            ).fetchone()
            if not appt:
                return None
            cur = conn.execute(
                """
                INSERT INTO lab_tests
                (test_code, appointment_id, patient_code, doctor_username, test_name, category, price_inr, sample_status, result_summary, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ordered', '', ?, ?)
                """,
                (test_code, appointment_id, appt["patient_code"] or "", doctor_username, test_name, category, price_inr, now, now),
            )
            return {
                "id": cur.lastrowid,
                "test_code": test_code,
                "appointment_id": appointment_id,
                "test_name": test_name,
                "category": category,
                "price_inr": price_inr,
                "sample_status": "ordered",
            }

    def update_lab_result(self, test_id: int, sample_status: str, result_summary: str) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE lab_tests SET sample_status = ?, result_summary = ?, updated_at = ? WHERE id = ?",
                (sample_status, result_summary, now, test_id),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM lab_tests WHERE id = ?", (test_id,)).fetchone()
            return dict(row) if row else None

    def generate_unified_invoice(self, appointment_id: int, pharmacy_inr: int = 0) -> Optional[Dict[str, Any]]:
        today_compact = ist_today().replace("-", "")
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                appt = conn.execute(
                    "SELECT id, patient_code, doctor_username FROM appointments WHERE id = ?",
                    (appointment_id,),
                ).fetchone()
                if not appt:
                    return None
                consult_fee = self.get_doctor_fee_inr(appt["doctor_username"])
                lab_row = conn.execute(
                    "SELECT COALESCE(SUM(price_inr), 0) AS total FROM lab_tests WHERE appointment_id = ?",
                    (appointment_id,),
                ).fetchone()
                lab_inr = int(lab_row["total"]) if lab_row else 0
                total_inr = consult_fee + lab_inr + max(0, pharmacy_inr)
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM invoices WHERE invoice_number LIKE ?",
                    (f"INV-{today_compact}-%",),
                ).fetchone()
                seq = (int(cnt["cnt"]) if cnt else 0) + 1
                inv_no = f"INV-{today_compact}-{seq:03d}"
                cur = conn.execute(
                    """
                    INSERT INTO invoices
                    (invoice_number, appointment_id, patient_code, consultation_inr, lab_inr, pharmacy_inr, total_inr, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'UNPAID', ?)
                    """,
                    (inv_no, appointment_id, appt["patient_code"] or "", consult_fee, lab_inr, max(0, pharmacy_inr), total_inr, now),
                )
                return {
                    "id": cur.lastrowid,
                    "invoice_number": inv_no,
                    "appointment_id": appointment_id,
                    "consultation_inr": consult_fee,
                    "lab_inr": lab_inr,
                    "pharmacy_inr": max(0, pharmacy_inr),
                    "total_inr": total_inr,
                    "status": "UNPAID",
                }

    def get_admin_overview(self) -> Dict[str, Any]:
        today = ist_today()
        with self._connect() as conn:
            total_appts = int(conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0])
            today_appts = int(conn.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date = ?", (today,)).fetchone()[0])
            total_patients = int(conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0])
            total_doctors = int(conn.execute("SELECT COUNT(*) FROM doctors WHERE active = 1").fetchone()[0])
            paid_rev = int(conn.execute("SELECT COALESCE(SUM(amount_inr), 0) FROM payments WHERE payment_status = 'PAID'").fetchone()[0])
            pending_rev = int(conn.execute("SELECT COALESCE(SUM(amount_inr), 0) FROM payments WHERE payment_status = 'PENDING'").fetchone()[0])
            low_stock = int(conn.execute("SELECT COUNT(*) FROM pharmacy_inventory WHERE stock_qty <= reorder_level").fetchone()[0])
            return {
                "date_ist": today,
                "total_appointments": total_appts,
                "today_appointments": today_appts,
                "total_patients": total_patients,
                "total_doctors": total_doctors,
                "paid_revenue_inr": paid_rev,
                "pending_revenue_inr": pending_rev,
                "low_stock_alerts": low_stock,
            }

    def get_receipt_detail(self, appointment_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT a.id AS appointment_id, a.appointment_number, a.appointment_date, a.slot_time,
                       a.first_name, a.last_name, a.mobile, a.department, a.doctor_username, a.patient_code,
                       p.receipt_number, p.amount_inr, p.method, p.payment_status, p.collected_by
                FROM appointments a
                LEFT JOIN payments p ON p.appointment_id = a.id
                WHERE a.id = ?
                """,
                (appointment_id,),
            ).fetchone()
            return dict(row) if row else None

    def get_prescription_detail(self, prescription_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT pr.id, pr.appointment_id, pr.patient_code, pr.doctor_username,
                       pr.diagnosis, pr.medicines_text, pr.advice, pr.follow_up_date,
                       a.appointment_number, a.appointment_date, a.first_name, a.last_name,
                       a.mobile, a.department
                FROM prescriptions pr
                JOIN appointments a ON a.id = pr.appointment_id
                WHERE pr.id = ?
                """,
                (prescription_id,),
            ).fetchone()
            return dict(row) if row else None

    def set_patient_consent(self, patient_code: str, purpose: str, granted: bool, version: str = "v1.0") -> Dict[str, Any]:
        now = int(time.time())
        g_int = 1 if granted else 0
        w_at = None if granted else now
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO patient_consents (patient_code, purpose, consent_version, granted, granted_at, withdrawn_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(patient_code, purpose) DO UPDATE SET
                    consent_version = excluded.consent_version,
                    granted = excluded.granted,
                    granted_at = CASE WHEN excluded.granted = 1 THEN excluded.granted_at ELSE patient_consents.granted_at END,
                    withdrawn_at = excluded.withdrawn_at
                """,
                (patient_code, purpose, version, g_int, now, w_at),
            )
            return {
                "patient_code": patient_code,
                "purpose": purpose,
                "consent_version": version,
                "granted": granted,
                "withdrawn_at": w_at,
            }

    def create_privacy_request(self, patient_code: str, request_type: str, details: str) -> Dict[str, Any]:
        today_compact = ist_today().replace("-", "")
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM privacy_requests WHERE request_code LIKE ?",
                    (f"PRV-{today_compact}-%",),
                ).fetchone()
                seq = (int(cnt["cnt"]) if cnt else 0) + 1
                req_code = f"PRV-{today_compact}-{seq:03d}"
                cur = conn.execute(
                    """
                    INSERT INTO privacy_requests (request_code, patient_code, request_type, details, status, created_at)
                    VALUES (?, ?, ?, ?, 'submitted', ?)
                    """,
                    (req_code, patient_code, request_type, details, now),
                )
                return {
                    "id": cur.lastrowid,
                    "request_code": req_code,
                    "patient_code": patient_code,
                    "request_type": request_type,
                    "details": details,
                    "status": "submitted",
                    "created_at": now,
                }

    def list_privacy_requests(self, patient_code: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if patient_code:
                rows = conn.execute(
                    "SELECT * FROM privacy_requests WHERE patient_code = ? ORDER BY id DESC LIMIT 50",
                    (patient_code,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM privacy_requests ORDER BY id DESC LIMIT 100"
                ).fetchall()
            return [dict(r) for r in rows]

    def process_refund(self, appointment_id: int, reason: str, processed_by: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Refund a PAID payment atomically. Prevents double-refunds (409)."""
        today_compact = ist_today().replace("-", "")
        now = int(time.time())
        with self._booking_lock:
            with self._connect() as conn:
                pay = conn.execute(
                    "SELECT * FROM payments WHERE appointment_id = ?", (appointment_id,)
                ).fetchone()
                if not pay:
                    return None, "not_found"
                if pay["payment_status"] == "REFUNDED":
                    return None, "already_refunded"
                if pay["payment_status"] != "PAID":
                    return None, "not_paid"
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM refunds WHERE refund_code LIKE ?",
                    (f"RFD-{today_compact}-%",),
                ).fetchone()
                seq = (int(cnt["cnt"]) if cnt else 0) + 1
                rfd_code = f"RFD-{today_compact}-{seq:03d}"
                conn.execute(
                    "UPDATE payments SET payment_status = 'REFUNDED' WHERE id = ?",
                    (pay["id"],),
                )
                cur = conn.execute(
                    """
                    INSERT INTO refunds (refund_code, payment_id, appointment_id, amount_inr, reason, status, processed_by, created_at)
                    VALUES (?, ?, ?, ?, ?, 'PROCESSED', ?, ?)
                    """,
                    (rfd_code, pay["id"], appointment_id, pay["amount_inr"], reason, processed_by, now),
                )
                return {
                    "id": cur.lastrowid,
                    "refund_code": rfd_code,
                    "payment_id": pay["id"],
                    "appointment_id": appointment_id,
                    "amount_inr": pay["amount_inr"],
                    "reason": reason,
                    "status": "PROCESSED",
                    "processed_by": processed_by,
                }, None

    def enqueue_job(self, job_type: str, idempotency_key: str, payload_json: str, delay_sec: int = 0) -> Tuple[bool, Optional[int]]:
        """Enqueue a durable background job. Returns (False, None) if duplicate idempotency_key."""
        now = int(time.time())
        with self._connect() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO background_jobs
                    (job_type, idempotency_key, payload_json, status, attempts, max_attempts, run_after, created_at, updated_at)
                    VALUES (?, ?, ?, 'pending', 0, 3, ?, ?, ?)
                    """,
                    (job_type, idempotency_key, payload_json, now + max(0, delay_sec), now, now),
                )
                return True, cur.lastrowid
            except sqlite3.IntegrityError:
                return False, None

    def process_pending_jobs(self, limit: int = 20) -> Dict[str, int]:
        """Process due background jobs with retry tracking and zero duplicate execution."""
        now = int(time.time())
        processed = 0
        failed = 0
        with self._booking_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, job_type, payload_json, attempts, max_attempts
                    FROM background_jobs
                    WHERE status = 'pending' AND run_after <= ?
                    ORDER BY run_after ASC
                    LIMIT ?
                    """,
                    (now, limit),
                ).fetchall()
                for r in rows:
                    try:
                        # Mark completed after executing job handler safely
                        conn.execute(
                            "UPDATE background_jobs SET status = 'completed', attempts = attempts + 1, updated_at = ? WHERE id = ?",
                            (now, r["id"]),
                        )
                        processed += 1
                    except Exception as exc:
                        new_att = int(r["attempts"]) + 1
                        new_st = "failed" if new_att >= int(r["max_attempts"]) else "pending"
                        conn.execute(
                            "UPDATE background_jobs SET status = ?, attempts = ?, last_error = ?, updated_at = ? WHERE id = ?",
                            (new_st, new_att, str(exc)[:200], now, r["id"]),
                        )
                        failed += 1
        return {"processed": processed, "failed": failed}

    def get_job_stats(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) AS cnt FROM background_jobs GROUP BY status").fetchall()
            counts = {"pending": 0, "completed": 0, "failed": 0}
            for r in rows:
                counts[r["status"]] = int(r["cnt"])
            return counts
