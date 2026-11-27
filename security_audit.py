"""
Automated Full Security Audit & Penetration Test Suite for Shri R.M. Patil Hospital.
Verifies 13 critical security & reliability invariants:
1. Git history & workspace secret scan (no leaked keys, .env not tracked)
2. Hidden API keys & debug mode disabled
3. Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, Server masking)
4. Exposed files & path traversal protection
5. Salted scrypt password hashing in SQLite (0 plaintext)
6. Unauthenticated admin & staff route blocking (401)
7. Form validation, XSS sanitization & SQLi resistance + sequential appointment number + auto confirmation SMS
8. Proper Authentication, RBAC isolation & CSRF enforcement
9. Doctor-scoped patient notification security (own patient 201, cross-doctor patient 403, missing CSRF 403)
10. Doctor-scoped daily & monthly appointment summary isolation (no cross-doctor count leaks)
11. Strict CORS allowlist enforcement
12. Safe error handling (zero stack traces)
13. Rate limiting enforcement (429 + Retry-After)
"""

import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Tuple

from datetime import datetime, timedelta
from backup_db import run_backup
from db_optimize import verify_query_plans
from migrations import IST, ist_today
from server import AppConfig, _safe_server_secret, create_server

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"sk-[A-Za-z0-9]{20,}", "Secret API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
]


def http_req(
    port: int,
    method: str,
    path: str,
    body: Any = None,
    headers: Dict[str, str] | None = None,
) -> Tuple[int, Dict[str, str], str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    hdrs = dict(headers or {})
    raw_body = None
    if body is not None:
        if isinstance(body, (dict, list)):
            raw_body = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        else:
            raw_body = str(body).encode("utf-8")
    conn.request(method, path, body=raw_body, headers=hdrs)
    resp = conn.getresponse()
    resp_body = resp.read().decode("utf-8", errors="replace")
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, resp_headers, resp_body


def scan_git_history() -> Tuple[bool, str]:
    if not os.path.isdir(os.path.join(BASE_DIR, ".git")):
        return True, "No .git directory yet (clean workspace scan passed)"
    tracked = subprocess.check_output(["git", "ls-files"], cwd=BASE_DIR, text=True).splitlines()
    if ".env" in tracked or any(f.endswith(".db") for f in tracked):
        return False, "Sensitive file (.env or .db) is tracked by Git!"
    log_out = subprocess.check_output(["git", "log", "-p", "--all"], cwd=BASE_DIR, text=True, errors="replace")
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, log_out):
            return False, f"Potential {label} found in Git history!"
    return True, f"Scanned {len(tracked)} tracked files and full Git history: 0 leaked secrets"


def _next_workdays() -> Tuple[str, str, str]:
    now = datetime.now(IST)
    today_s = now.strftime("%Y-%m-%d")
    d = now + timedelta(days=1)
    while d.weekday() == 6:  # skip Sunday
        d += timedelta(days=1)
    work1 = d.strftime("%Y-%m-%d")
    d2 = d + timedelta(days=1)
    while d2.weekday() == 6:
        d2 += timedelta(days=1)
    work2 = d2.strftime("%Y-%m-%d")
    return today_s, work1, work2


def run_audit() -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    today_s, work1, work2 = _next_workdays()
    today_compact = today_s.replace("-", "")
    month_s = today_s[:7]

    def record(name: str, passed: bool, detail: str) -> None:
        results.append({"check": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    # 1. Git history & secret scan
    git_ok, git_detail = scan_git_history()
    record("Git History & Secret Scan", git_ok, git_detail)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        cfg = AppConfig()
        cfg.host = "127.0.0.1"
        cfg.port = 0
        cfg.debug = False
        cfg.db_path = os.path.join(tmpdir, "audit_hospital.db")
        cfg.sms_api_key = "SUPER_SECRET_SMS_KEY_DO_NOT_LEAK_998877"
        cfg.allowed_origins = {"https://shrirmppatilhospital.in"}
        cfg.rate_limit_public = 200
        cfg.rate_limit_booking = 6
        cfg.rate_limit_login = 20
        cfg.rate_limit_notify = 20

        srv = create_server(cfg)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            # 2. Hidden API keys, non-secret config & debug mode off
            st, hdrs, body = http_req(port, "GET", "/api/health")
            st_pc, _, b_pc = http_req(port, "GET", "/api/payments/config")
            ph_sess = _safe_server_secret("replace_with_64_char_hex_secret_from_secrets_token_hex", min_len=32)
            ph_rzp = _safe_server_secret("replace_with_razorpay_test_secret", min_len=16)
            idx_html = open(os.path.join(BASE_DIR, "public", "index.html"), encoding="utf-8").read()
            adm_html = open(os.path.join(BASE_DIR, "public", "admin.html"), encoding="utf-8").read()
            client_clean = (
                "demoPass" not in idx_html
                and "Admin#RMP2026!" not in idx_html
                and "Admin#RMP2026!" not in adm_html
                and "RAZORPAY_KEY_SECRET" not in idx_html
                and "SMS_GATEWAY_API_KEY" not in idx_html
                and "SESSION_SECRET" not in idx_html
            )
            secrets_rejected = "replace_with" not in ph_sess and len(ph_sess) == 64 and "replace_with" not in ph_rzp
            key_hidden = (
                cfg.sms_api_key not in body
                and '"debug": false' in body.lower()
                and st_pc == 200
                and cfg.razorpay_key_secret not in b_pc
                and cfg.razorpay_webhook_secret not in b_pc
                and client_clean
                and secrets_rejected
            )
            record(
                "API Keys Hidden & Debug Mode Off",
                st == 200 and key_hidden,
                "Server secrets hidden; placeholder keys rejected; zero client passwords; DEBUG=false",
            )

            # 3. Security headers
            required_headers = [
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
                "strict-transport-security",
                "content-security-policy",
                "cache-control",
            ]
            missing = [h for h in required_headers if h not in hdrs]
            server_safe = hdrs.get("server") == "HospitalWeb"
            record(
                "Security Headers & Server Masking",
                len(missing) == 0 and server_safe,
                f"All {len(required_headers)} security headers present; Server='{hdrs.get('server')}'",
            )

            # 4. Exposed files & path traversal protection
            probes = ["/.env", "/.git/config", "/data/hospital.db", "/server.py", "/../etc/passwd"]
            probe_statuses = [http_req(port, "GET", p)[0] for p in probes]
            record(
                "Exposed Files & Path Traversal Blocked",
                all(code in (403, 404) for code in probe_statuses),
                f"All {len(probes)} sensitive file probes returned 404/403 ({probe_statuses})",
            )

            # 5. Scrypt password hashing in SQLite & password sync
            from db import verify_password as _verify_pw
            conn = sqlite3.connect(cfg.db_path)
            hashes = [r[0] for r in conn.execute("SELECT password_hash FROM users").fetchall()]
            conn.close()
            all_scrypt = len(hashes) >= 6 and all(h.startswith("scrypt$16384$8$1$") for h in hashes)
            no_plaintext = all(pw not in " ".join(hashes) for pw in cfg.staff_passwords.values())
            srv_py = open(os.path.join(BASE_DIR, "server.py"), encoding="utf-8").read()
            sync_ok = srv.db.sync_staff_passwords({"nurse": "TempRotated#2026!"}, skip_placeholders=True) == 1
            nurse_row = srv.db.get_user_by_username("nurse")
            sync_verified = bool(nurse_row and _verify_pw("TempRotated#2026!", nurse_row["password_hash"]))
            srv.db.sync_staff_passwords({"nurse": cfg.staff_passwords["nurse"]}, skip_placeholders=True)
            record(
                "Scrypt Password Hashing & DB Security",
                all_scrypt and no_plaintext and sync_ok and sync_verified and "Admin#RMP2026!" not in srv_py,
                f"Verified {len(hashes)} staff accounts hashed with salted scrypt (0 plaintext) + password sync",
            )

            # 6. Unauthenticated admin & staff routes blocked
            s_admin, _, _ = http_req(port, "GET", "/api/admin/audit")
            s_staff, _, _ = http_req(port, "GET", "/api/staff/appointments")
            s_sum, _, _ = http_req(port, "GET", "/api/staff/appointments/summary")
            record(
                "Admin & Staff Routes Protected",
                s_admin == 401 and s_staff == 401 and s_sum == 401,
                f"Unauthenticated admin={s_admin}, staff={s_staff}, summary={s_sum}",
            )

            # 7. XSS/SQLi defense + Sequential Appointment Number + Auto Confirmation SMS
            xss_payload = {
                "first_name": "Aarav",
                "last_name": "Deshmukh",
                "mobile": "9876543210",
                "department": "General Medicine — Dr. Snehal Patil",
                "appointment_date": today_s,
                "message": "<script>alert('xss')</script><img src=x onerror=alert(1)>'; DROP TABLE appointments;--",
            }
            s_book1, _, b_book1 = http_req(port, "POST", "/api/appointments", body=xss_payload)
            j1 = json.loads(b_book1)
            appt1 = j1.get("appointment", {})
            sms1 = j1.get("confirmation_sms", {})
            sanitized_msg = appt1.get("message", "")
            xss_clean = "<script" not in sanitized_msg.lower() and "onerror=" not in sanitized_msg.lower()
            sms_has_num = appt1.get("appointment_number") == f"APT-{today_compact}-001" and f"APT-{today_compact}-001" in sms1.get("text", "")

            s_book2, _, b_book2 = http_req(
                port,
                "POST",
                "/api/appointments",
                body={
                    "first_name": "Meera",
                    "last_name": "Kulkarni",
                    "mobile": "9822334455",
                    "department": "Orthopaedics — Dr. Rohan Patil",
                    "appointment_date": today_s,
                    "message": "Knee pain consultation",
                },
            )
            j2 = json.loads(b_book2)
            appt2 = j2.get("appointment", {})
            seq_ok = appt2.get("appointment_number") == f"APT-{today_compact}-002"
            record(
                "Form XSS/SQLi Defense & Auto Confirmation SMS",
                s_book1 == 201 and s_book2 == 201 and xss_clean and sms_has_num and seq_ok,
                f"Sequential numbers {appt1.get('appointment_number')}, {appt2.get('appointment_number')}; confirmation SMS sent; XSS neutralized",
            )

            # 8. Proper Authentication, RBAC Isolation & CSRF Enforcement
            def login(username: str, password: str) -> Tuple[str, str]:
                st_l, h_l, b_l = http_req(port, "POST", "/api/auth/login", {"username": username, "password": password})
                assert st_l == 200, f"Login failed for {username}: {st_l}"
                cookie_val = h_l["set-cookie"].split(";", 1)[0]
                csrf_val = json.loads(b_l)["csrf_token"]
                return cookie_val, csrf_val

            rohan_cookie, rohan_csrf = login("dr_rohan", cfg.staff_passwords["dr_rohan"])
            admin_cookie, _ = login("admin", cfg.staff_passwords["admin"])

            st_r_appts, _, b_r_appts = http_req(port, "GET", "/api/staff/appointments", headers={"Cookie": rohan_cookie})
            r_appts = json.loads(b_r_appts)["appointments"]
            only_rohan = st_r_appts == 200 and len(r_appts) == 1 and r_appts[0]["doctor_username"] == "dr_rohan"
            st_r_admin, _, _ = http_req(port, "GET", "/api/admin/audit", headers={"Cookie": rohan_cookie})
            st_no_csrf, _, _ = http_req(
                port,
                "PATCH",
                f"/api/staff/appointments/{appt2['id']}",
                body={"status": "confirmed"},
                headers={"Cookie": rohan_cookie},
            )
            st_ok_csrf, _, _ = http_req(
                port,
                "PATCH",
                f"/api/staff/appointments/{appt2['id']}",
                body={"status": "confirmed"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_a_admin, _, _ = http_req(port, "GET", "/api/admin/audit", headers={"Cookie": admin_cookie})
            record(
                "Authentication, RBAC Isolation & CSRF",
                only_rohan and st_r_admin == 403 and st_no_csrf == 403 and st_ok_csrf == 200 and st_a_admin == 200,
                "Doctor isolated to own patients & blocked from admin (403); CSRF verified; Admin authorized (200)",
            )

            # 9. Doctor-Scoped Patient Notification Security (cross-doctor blocked!)
            st_n_nocsrf, _, _ = http_req(
                port,
                "POST",
                f"/api/staff/appointments/{appt2['id']}/notify",
                body={"message": "Please arrive 15 mins early"},
                headers={"Cookie": rohan_cookie},
            )
            st_n_own, _, b_n_own = http_req(
                port,
                "POST",
                f"/api/staff/appointments/{appt2['id']}/notify",
                body={"message": "Please bring your X-ray report <script>bad()</script>"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_n_other, _, _ = http_req(
                port,
                "POST",
                f"/api/staff/appointments/{appt1['id']}/notify",
                body={"message": "Unauthorized cross-doctor message"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            n_clean = "<script" not in b_n_own.lower()
            record(
                "Doctor Patient Notification Isolation",
                st_n_nocsrf == 403 and st_n_own == 201 and st_n_other == 403 and n_clean,
                f"Own patient notify={st_n_own}, cross-doctor notify={st_n_other} (blocked), missing CSRF={st_n_nocsrf}",
            )

            # 10. Doctor-Scoped Daily & Monthly Appointment Summary Isolation
            st_s_doc, _, b_s_doc = http_req(
                port,
                "GET",
                f"/api/staff/appointments/summary?date={today_s}&month={month_s}",
                headers={"Cookie": rohan_cookie},
            )
            st_s_adm, _, b_s_adm = http_req(
                port,
                "GET",
                f"/api/staff/appointments/summary?date={today_s}&month={month_s}",
                headers={"Cookie": admin_cookie},
            )
            s_doc = json.loads(b_s_doc)
            s_adm = json.loads(b_s_adm)
            summary_ok = (
                st_s_doc == 200
                and s_doc["daily_count"] == 1
                and s_doc["monthly_count"] == 1
                and st_s_adm == 200
                and s_adm["daily_count"] == 2
                and s_adm["monthly_count"] == 2
            )
            record(
                "Daily & Monthly Summary RBAC Isolation",
                summary_ok,
                f"Doctor sees daily={s_doc['daily_count']}/monthly={s_doc['monthly_count']}; Admin sees daily={s_adm['daily_count']}/monthly={s_adm['monthly_count']}",
            )

            # 11. Strict CORS allowlist
            st_cors_ok, h_cors_ok, _ = http_req(
                port, "OPTIONS", "/api/appointments", headers={"Origin": "https://shrirmppatilhospital.in"}
            )
            st_cors_bad, h_cors_bad, _ = http_req(
                port, "OPTIONS", "/api/appointments", headers={"Origin": "https://evil-attacker.example"}
            )
            cors_pass = (
                st_cors_ok == 204
                and h_cors_ok.get("access-control-allow-origin") == "https://shrirmppatilhospital.in"
                and st_cors_bad == 403
                and "access-control-allow-origin" not in h_cors_bad
            )
            record(
                "Strict CORS Allowlist",
                cors_pass,
                f"Trusted origin={st_cors_ok}, untrusted origin={st_cors_bad} (no ACAO header)",
            )

            # 12. Malformed input handling (no stack trace leakage)
            st_bad_json, _, b_bad_json = http_req(
                port, "POST", "/api/appointments", body="{not-valid-json", headers={"Content-Type": "application/json"}
            )
            no_trace = "Traceback" not in b_bad_json and st_bad_json == 400
            record(
                "Safe Error Handling (Zero Stack Traces)",
                no_trace,
                f"Malformed JSON returned HTTP {st_bad_json} with clean JSON error",
            )

            # 14. Patient Registration, Weak Password Rejection & Unique Patient ID
            st_weak, _, _ = http_req(
                port,
                "POST",
                "/api/patients/register",
                body={"first_name": "Kiran", "last_name": "Patil", "mobile": "9812345678", "password": "123"},
            )
            st_p1, _, b_p1 = http_req(
                port,
                "POST",
                "/api/patients/register",
                body={
                    "first_name": "Kiran",
                    "last_name": "Patil",
                    "mobile": "9812345678",
                    "password": "Patient#2026",
                    "blood_group": "O+",
                },
            )
            st_dup, _, _ = http_req(
                port,
                "POST",
                "/api/patients/register",
                body={"first_name": "Kiran", "last_name": "Patil", "mobile": "9812345678", "password": "Patient#2026"},
            )
            st_p2, _, b_p2 = http_req(
                port,
                "POST",
                "/api/patients/register",
                body={"first_name": "Neha", "last_name": "Desai", "mobile": "9823456789", "password": "Patient#2026"},
            )
            p1_code = json.loads(b_p1).get("patient", {}).get("patient_code", "")
            p2_code = json.loads(b_p2).get("patient", {}).get("patient_code", "")
            record(
                "Patient Registration & Unique Patient IDs",
                st_weak == 400 and st_p1 == 201 and st_dup == 409 and st_p2 == 201 and p1_code.startswith("PAT-") and p1_code != p2_code,
                f"Registered {p1_code} & {p2_code}; weak password={st_weak}, duplicate mobile={st_dup}",
            )

            # 15. Patient Data Isolation & Role Boundary Enforcement
            p1_cookie, p1_csrf = login("9812345678", "Patient#2026")
            st_p1_me, _, _ = http_req(port, "GET", "/api/patient/me", headers={"Cookie": p1_cookie})
            st_p1_staff, _, _ = http_req(port, "GET", "/api/staff/appointments", headers={"Cookie": p1_cookie})
            st_p1_admin, _, _ = http_req(port, "GET", "/api/admin/audit", headers={"Cookie": p1_cookie})
            # Try reading another patient's appointment (appt1 belongs to mobile 9876543210, NOT 9812345678)
            st_p1_other, _, _ = http_req(port, "GET", f"/api/patient/appointments/{appt1['id']}", headers={"Cookie": p1_cookie})
            # PATCH /api/patient/me without CSRF -> 403, with CSRF -> 200
            st_p1_nocsrf, _, _ = http_req(
                port, "PATCH", "/api/patient/me", body={"address": "Chakur"}, headers={"Cookie": p1_cookie}
            )
            st_p1_okcsrf, _, _ = http_req(
                port,
                "PATCH",
                "/api/patient/me",
                body={"address": "Chakur, Latur", "blood_group": "O+", "emergency_contact_name": "Self", "emergency_contact_phone": "9812345678"},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            record(
                "Patient Data Isolation & Role Boundaries",
                st_p1_me == 200 and st_p1_staff == 403 and st_p1_admin == 403 and st_p1_other == 403 and st_p1_nocsrf == 403 and st_p1_okcsrf == 200,
                f"Own profile={st_p1_me}, staff={st_p1_staff}, admin={st_p1_admin}, other-patient-appt={st_p1_other}, CSRF verified",
            )

            # 16. Doctor Schedule Engine: Past-Date Block, Break Exclusion & Holiday Enforcement
            st_past, _, _ = http_req(port, "GET", "/api/doctors/dr_rohan/slots?date=2020-01-01")
            st_slots, _, b_slots = http_req(port, "GET", f"/api/doctors/dr_rohan/slots?date={work1}")
            slots_data = json.loads(b_slots)
            open_list = slots_data.get("available_slots", [])
            break_excluded = "13:30" not in open_list and "14:00" not in open_list and "10:00" in open_list
            # Mark 2026-11-28 as holiday for dr_rohan
            st_hol, _, _ = http_req(
                port,
                "POST",
                "/api/staff/holidays",
                body={"holiday_date": work2, "reason": "Medical conference"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_hol_slots, _, b_hol_slots = http_req(port, "GET", f"/api/doctors/dr_rohan/slots?date={work2}")
            hol_empty = len(json.loads(b_hol_slots).get("available_slots", [])) == 0
            st_hol_book, _, _ = http_req(
                port,
                "POST",
                "/api/appointments",
                body={
                    "first_name": "Holiday",
                    "last_name": "Test",
                    "mobile": "9811112222",
                    "department": "Orthopaedics — Dr. Rohan Patil",
                    "appointment_date": work2,
                    "slot_time": "10:00",
                },
            )
            st_hol_unauth, _, _ = http_req(port, "GET", "/api/staff/holidays")
            st_hol_rohan, _, _ = http_req(port, "GET", "/api/staff/holidays", headers={"Cookie": rohan_cookie})
            st_hol_adm, _, _ = http_req(port, "GET", "/api/staff/holidays", headers={"Cookie": admin_cookie})
            record(
                "Doctor Schedule, Break & Holiday Engine",
                st_past == 400 and st_slots == 200 and break_excluded and st_hol == 201 and st_hol_slots == 200 and hol_empty and st_hol_book == 400 and st_hol_unauth == 401 and st_hol_rohan == 200 and st_hol_adm == 200,
                f"Past date={st_past}, open slots={len(open_list)} (breaks excluded), holiday booking={st_hol_book}, holiday GET RBAC={st_hol_unauth}/{st_hol_rohan}",
            )

            # 17. Simultaneous Double-Booking Race Condition Protection (10 threads -> 1 wins, 9 get 409)
            # Raise booking limit temporarily for concurrency race test
            srv.config.rate_limit_booking = 50
            def _race_book(idx: int) -> int:
                code, _, _ = http_req(
                    port,
                    "POST",
                    "/api/appointments",
                    body={
                        "first_name": f"RaceUser{chr(65 + idx)}",
                        "last_name": "Test",
                        "mobile": f"98700000{idx:02d}",
                        "department": "Orthopaedics — Dr. Rohan Patil",
                        "appointment_date": work1,
                        "slot_time": "10:00",
                    },
                )
                return code

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                race_codes = list(pool.map(_race_book, range(10)))
            srv.config.rate_limit_booking = 6
            record(
                "Simultaneous Double-Booking Race Protection",
                race_codes.count(201) == 1 and race_codes.count(409) == 9 and all(c in (201, 409) for c in race_codes),
                f"10 simultaneous bookings on 2026-11-27 10:00 -> {race_codes.count(201)} created (201), {race_codes.count(409)} blocked (409), 0 errors",
            )

            # 18. Pay-at-Hospital Separation & Receptionist Collection RBAC
            reception_cookie, reception_csrf = login("reception", cfg.staff_passwords["reception"])
            # appt2 was booked with default pay_at_hospital -> appointment confirmed, payment PENDING
            st_doc_col, _, _ = http_req(
                port,
                "POST",
                f"/api/staff/payments/{appt2['id']}/collect",
                body={},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_rec_col, _, b_rec_col = http_req(
                port,
                "POST",
                f"/api/staff/payments/{appt2['id']}/collect",
                body={},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            pay2 = json.loads(b_rec_col).get("payment", {})
            record(
                "Pay-at-Hospital Separation & Collection RBAC",
                st_doc_col == 403 and st_rec_col == 200 and pay2.get("payment_status") == "PAID" and str(pay2.get("receipt_number", "")).startswith("RCP-"),
                f"Doctor collect blocked={st_doc_col}, Receptionist collect={st_rec_col} -> PAID ({pay2.get('receipt_number')})",
            )

            # 19. Online Payment (Razorpay Test Mode) HMAC Verification & Duplicate Webhook Protection
            srv.config.rate_limit_booking = 50
            st_onl, _, b_onl = http_req(
                port,
                "POST",
                "/api/appointments",
                body={
                    "first_name": "Vikram",
                    "last_name": "Kadam",
                    "mobile": "9845001122",
                    "department": "General Medicine — Dr. Snehal Patil",
                    "appointment_date": work1,
                    "slot_time": "11:00",
                    "payment_method": "online_razorpay",
                },
            )
            j_onl = json.loads(b_onl)
            onl_order = j_onl["payment"]["provider_order_id"]
            onl_qr = j_onl["appointment"]["qr_token"]
            # Forged signature must fail (400)
            st_forged, _, _ = http_req(
                port,
                "POST",
                "/api/payments/online/verify",
                body={"order_id": onl_order, "payment_id": "pay_test_001", "signature": "forged_bad_sig"},
            )
            # Valid HMAC signature must pass (200)
            valid_sig = hmac.new(
                srv.config.razorpay_key_secret.encode("utf-8"),
                f"{onl_order}|pay_test_001".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            st_valid_pay, _, b_valid_pay = http_req(
                port,
                "POST",
                "/api/payments/online/verify",
                body={"order_id": onl_order, "payment_id": "pay_test_001", "signature": valid_sig},
            )
            # Duplicate webhook replay test
            wh_payload = json.dumps({"event_id": "evt_test_9001", "order_id": onl_order, "payment_id": "pay_test_001"})
            wh_sig = hmac.new(
                srv.config.razorpay_webhook_secret.encode("utf-8"),
                wh_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            st_wh1, _, b_wh1 = http_req(
                port, "POST", "/api/payments/webhook", body=wh_payload, headers={"Content-Type": "application/json", "X-Razorpay-Signature": wh_sig}
            )
            st_wh2, _, b_wh2 = http_req(
                port, "POST", "/api/payments/webhook", body=wh_payload, headers={"Content-Type": "application/json", "X-Razorpay-Signature": wh_sig}
            )
            srv.config.rate_limit_booking = 6
            record(
                "Online Payment HMAC & Duplicate Webhook Defense",
                st_onl == 201 and st_forged == 400 and st_valid_pay == 200 and st_wh1 == 200 and st_wh2 == 200 and json.loads(b_wh2).get("duplicate") is True,
                f"Forged sig={st_forged}, valid HMAC={st_valid_pay}, duplicate webhook ignored=True",
            )

            # 20. Non-Sensitive QR Code & Reception Check-In Queue Token
            qr_no_pii = "Vikram" not in onl_qr and "9845001122" not in onl_qr and onl_qr.startswith("QR-")
            st_qr_pat, _, _ = http_req(
                port,
                "POST",
                "/api/staff/checkin/scan",
                body={"qr_token": onl_qr},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            st_qr_ok, _, b_qr_ok = http_req(
                port,
                "POST",
                "/api/staff/checkin/scan",
                body={"qr_token": onl_qr},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            st_qr_bad, _, _ = http_req(
                port,
                "POST",
                "/api/staff/checkin/scan",
                body={"qr_token": "QR-INVALID000000"},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            q_tok = json.loads(b_qr_ok).get("checkin", {}).get("queue_token", "")
            record(
                "Non-Sensitive QR Code & Reception Check-In",
                qr_no_pii and st_qr_pat == 403 and st_qr_ok == 200 and q_tok == "Q-001" and st_qr_bad == 404,
                f"QR contains 0 PII; patient blocked={st_qr_pat}, reception check-in={st_qr_ok} (queue={q_tok}), bad QR={st_qr_bad}",
            )

            # 21. Patient Cancellation Releases Slot & Rescheduling Enforces Availability
            srv.config.rate_limit_booking = 50
            st_pb, _, b_pb = http_req(
                port,
                "POST",
                "/api/appointments",
                body={
                    "first_name": "Kiran",
                    "last_name": "Patil",
                    "mobile": "9812345678",
                    "department": "Orthopaedics — Dr. Rohan Patil",
                    "appointment_date": work1,
                    "slot_time": "11:30",
                },
                headers={"Cookie": p1_cookie},
            )
            p1_appt_id = json.loads(b_pb)["appointment"]["id"]
            st_resch, _, _ = http_req(
                port,
                "POST",
                f"/api/patient/appointments/{p1_appt_id}/reschedule",
                body={"appointment_date": work1, "slot_time": "12:00"},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            st_can, _, _ = http_req(
                port,
                "POST",
                f"/api/patient/appointments/{p1_appt_id}/cancel",
                body={},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            # Slot 12:00 must now be free for another booking!
            st_rebook, _, b_rebook = http_req(
                port,
                "POST",
                "/api/appointments",
                body={
                    "first_name": "Kiran",
                    "last_name": "Patil",
                    "mobile": "9812345678",
                    "department": "Orthopaedics — Dr. Rohan Patil",
                    "appointment_date": work1,
                    "slot_time": "12:00",
                },
                headers={"Cookie": p1_cookie},
            )
            rebook_id = json.loads(b_rebook)["appointment"]["id"]
            srv.config.rate_limit_booking = 6
            record(
                "Patient Reschedule & Slot-Release Cancellation",
                st_pb == 201 and st_resch == 200 and st_can == 200 and st_rebook == 201,
                f"Book={st_pb}, Reschedule 11:30->12:00={st_resch}, Cancel={st_can}, Re-book freed 12:00={st_rebook}",
            )

            # 22. Doctor-Only Diagnosis/Prescription Boundary (Receptionist blocked 403!)
            st_rec_rx, _, _ = http_req(
                port,
                "POST",
                "/api/doctor/prescriptions",
                body={"appointment_id": rebook_id, "diagnosis": "Unauthorized edit", "medicines_text": "None"},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            st_doc_rx, _, _ = http_req(
                port,
                "POST",
                "/api/doctor/prescriptions",
                body={"appointment_id": rebook_id, "diagnosis": "Mild ankle sprain", "medicines_text": "Paracetamol 500mg SOS", "advice": "Rest 2 days"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_pat_rx, _, b_pat_rx = http_req(
                port, "GET", "/api/patient/prescriptions", headers={"Cookie": p1_cookie}
            )
            record(
                "Doctor-Only Diagnosis & Patient Prescription Access",
                st_rec_rx == 403 and st_doc_rx == 201 and st_pat_rx == 200 and json.loads(b_pat_rx).get("count", 0) >= 1,
                f"Receptionist blocked={st_rec_rx}, Doctor write={st_doc_rx}, Patient own read={st_pat_rx}",
            )

            # 23. Pharmacy, Laboratory & Unified Billing Role Isolation
            pharm_cookie, pharm_csrf = login("pharmacist", cfg.staff_passwords["pharmacist"])
            lab_cookie, lab_csrf = login("lab_tech", cfg.staff_passwords["lab_tech"])
            st_ph_inv, _, _ = http_req(port, "GET", "/api/pharmacy/inventory", headers={"Cookie": pharm_cookie})
            st_ph_disp, _, b_disp = http_req(
                port,
                "POST",
                "/api/pharmacy/dispense",
                body={"medicine_code": "MED-PCM500", "quantity": 2},
                headers={"Cookie": pharm_cookie, "X-CSRF-Token": pharm_csrf},
            )
            disp_charge = json.loads(b_disp)["dispense"]["charge_inr"]
            st_lab_ord, _, b_lab_ord = http_req(
                port,
                "POST",
                "/api/lab/tests",
                body={"appointment_id": rebook_id, "test_name": "X-Ray Ankle", "category": "Radiology", "price_inr": 450},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            lab_id = json.loads(b_lab_ord)["lab_test"]["id"]
            st_lab_res, _, _ = http_req(
                port,
                "PATCH",
                f"/api/lab/tests/{lab_id}",
                body={"sample_status": "completed", "result_summary": "No fracture seen"},
                headers={"Cookie": lab_cookie, "X-CSRF-Token": lab_csrf},
            )
            st_bill, _, b_bill = http_req(
                port,
                "POST",
                "/api/billing/invoices",
                body={"appointment_id": rebook_id, "pharmacy_inr": disp_charge},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            inv_data = json.loads(b_bill).get("invoice", {})
            st_lt_unauth, _, _ = http_req(port, "GET", "/api/lab/tests")
            st_lt_rec, _, _ = http_req(port, "GET", "/api/lab/tests", headers={"Cookie": reception_cookie})
            st_lt_doc, _, b_lt_doc = http_req(port, "GET", "/api/lab/tests", headers={"Cookie": rohan_cookie})
            st_lt_lab, _, _ = http_req(port, "GET", "/api/lab/tests", headers={"Cookie": lab_cookie})
            st_bi_unauth, _, _ = http_req(port, "GET", "/api/billing/invoices")
            st_bi_doc, _, _ = http_req(port, "GET", "/api/billing/invoices", headers={"Cookie": rohan_cookie})
            st_bi_rec, _, b_bi_rec = http_req(port, "GET", "/api/billing/invoices", headers={"Cookie": reception_cookie})
            # Doctor fee 500 + Lab 450 + Pharmacy 50 = 1000
            record(
                "Pharmacy, Lab & Unified Billing RBAC",
                st_ph_inv == 200
                and st_ph_disp == 200
                and st_lab_ord == 201
                and st_lab_res == 200
                and st_bill == 201
                and inv_data.get("total_inr") == 1000
                and st_lt_unauth == 401
                and st_lt_rec == 403
                and st_lt_doc == 200
                and st_lt_lab == 200
                and len(json.loads(b_lt_doc).get("lab_tests", [])) >= 1
                and st_bi_unauth == 401
                and st_bi_doc == 403
                and st_bi_rec == 200
                and len(json.loads(b_bi_rec).get("invoices", [])) >= 1,
                f"Pharmacy={st_ph_disp}, Lab={st_lab_res}, Invoice={inv_data.get('invoice_number')} (Total=INR {inv_data.get('total_inr')})",
            )

            # 24. Dedicated /admin Page & /api/admin/overview Strict Admin-Only Access Control
            st_adm_unauth, _, _ = http_req(port, "GET", "/admin")
            st_adm_doc, _, _ = http_req(port, "GET", "/admin", headers={"Cookie": rohan_cookie})
            st_adm_rec, _, _ = http_req(port, "GET", "/admin", headers={"Cookie": reception_cookie})
            st_adm_pat, _, _ = http_req(port, "GET", "/admin", headers={"Cookie": p1_cookie})
            st_adm_ok, h_adm_ok, b_adm_ok = http_req(port, "GET", "/admin", headers={"Cookie": admin_cookie})
            st_ov_doc, _, _ = http_req(port, "GET", "/api/admin/overview", headers={"Cookie": rohan_cookie})
            st_ov_ok, _, _ = http_req(port, "GET", "/api/admin/overview", headers={"Cookie": admin_cookie})
            no_store_ok = "no-store" in h_adm_ok.get("cache-control", "").lower()
            record(
                "Dedicated /admin Page Strictly Admin-Only",
                (
                    st_adm_unauth == 401
                    and st_adm_doc == 403
                    and st_adm_rec == 403
                    and st_adm_pat == 403
                    and st_adm_ok == 200
                    and "Admin Command Center" in b_adm_ok
                    and no_store_ok
                    and st_ov_doc == 403
                    and st_ov_ok == 200
                ),
                f"/admin unauth={st_adm_unauth}, doc={st_adm_doc}, rec={st_adm_rec}, pat={st_adm_pat}, admin={st_adm_ok} (no-store={no_store_ok})",
            )

            # 25. Printable Official Letterhead Receipt & Prescription Access Isolation
            st_rcp_ok, _, b_rcp = http_req(port, "GET", f"/api/receipts/{rebook_id}/print", headers={"Cookie": p1_cookie})
            st_rcp_other, _, _ = http_req(port, "GET", f"/api/receipts/{appt1['id']}/print", headers={"Cookie": p1_cookie})
            st_rx_rec_blk, _, _ = http_req(port, "GET", "/api/prescriptions/1/print", headers={"Cookie": reception_cookie})
            st_rx_ok, _, b_rx = http_req(port, "GET", "/api/prescriptions/1/print", headers={"Cookie": p1_cookie})
            record(
                "Printable Letterhead Receipts & Prescriptions RBAC",
                st_rcp_ok == 200 and "Shri R.M. Patil" in b_rcp and st_rcp_other == 403 and st_rx_rec_blk == 403 and st_rx_ok == 200 and "Digital Prescription" in b_rx,
                f"Own receipt={st_rcp_ok}, other receipt={st_rcp_other}, receptionist Rx={st_rx_rec_blk}, own Rx={st_rx_ok}",
            )

            # 26. Automated Online SQLite Backup & PRAGMA integrity_check
            bk = run_backup(db_path=cfg.db_path, backup_dir=os.path.join(tmpdir, "bk_test"), keep_latest=5)
            record(
                "Online SQLite Backup & Integrity Check",
                bk.get("status") == "ok" and bk.get("integrity_check") == "ok" and os.path.isfile(bk["backup_file"]),
                f"Verified live WAL backup integrity_check='{bk.get('integrity_check')}'",
            )

            # 27. DPDP Patient Consent Grant & Withdrawal Workflow
            st_cg, _, b_cg = http_req(
                port,
                "POST",
                "/api/patient/consent",
                body={"purpose": "appointment_sms_reminders", "granted": True},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            st_cw, _, b_cw = http_req(
                port,
                "POST",
                "/api/patient/consent",
                body={"purpose": "appointment_sms_reminders", "granted": False},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            cw_data = json.loads(b_cw).get("consent", {})
            record(
                "DPDP Patient Consent Grant & Withdrawal",
                st_cg == 200 and st_cw == 200 and cw_data.get("granted") is False and cw_data.get("withdrawn_at") is not None,
                f"Consent granted={st_cg}, withdrawn={st_cw} (timestamp recorded)",
            )

            # 28. DPDP Patient Data Correction & Erasure Request Workflow
            st_prq, _, b_prq = http_req(
                port,
                "POST",
                "/api/patient/privacy-requests",
                body={"request_type": "erasure", "details": "Remove optional marketing contact data"},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            st_prq_list, _, b_prq_list = http_req(
                port, "GET", "/api/patient/privacy-requests", headers={"Cookie": p1_cookie}
            )
            prq_code = json.loads(b_prq).get("privacy_request", {}).get("request_code", "")
            record(
                "DPDP Patient Correction & Erasure Requests",
                st_prq == 201 and prq_code.startswith("PRV-") and st_prq_list == 200 and json.loads(b_prq_list).get("count", 0) >= 1,
                f"Created {prq_code}; patient isolated request history={st_prq_list}",
            )

            # 29. Dedicated Billing Role Boundaries & Refund Workflow (Blocks Double-Refund 409)
            billing_cookie, billing_csrf = login("billing_desk", cfg.staff_passwords["billing_desk"])
            # Billing cannot write doctor prescriptions or open /admin
            st_bill_adm, _, _ = http_req(port, "GET", "/admin", headers={"Cookie": billing_cookie})
            st_bill_rx, _, _ = http_req(
                port,
                "POST",
                "/api/doctor/prescriptions",
                body={"appointment_id": rebook_id, "diagnosis": "Blocked", "medicines_text": "None"},
                headers={"Cookie": billing_cookie, "X-CSRF-Token": billing_csrf},
            )
            # Doctor cannot issue refunds (403); Billing officer succeeds (201) on appt2 (PAID); second refund -> 409
            st_doc_rfd, _, _ = http_req(
                port,
                "POST",
                "/api/billing/refunds",
                body={"appointment_id": appt2["id"], "reason": "Unauthorized"},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            st_rfd_ok, _, b_rfd_ok = http_req(
                port,
                "POST",
                "/api/billing/refunds",
                body={"appointment_id": appt2["id"], "reason": "Patient cancelled before consultation"},
                headers={"Cookie": billing_cookie, "X-CSRF-Token": billing_csrf},
            )
            st_rfd_dup, _, _ = http_req(
                port,
                "POST",
                "/api/billing/refunds",
                body={"appointment_id": appt2["id"], "reason": "Duplicate refund attempt"},
                headers={"Cookie": billing_cookie, "X-CSRF-Token": billing_csrf},
            )
            rfd_code = json.loads(b_rfd_ok).get("refund", {}).get("refund_code", "")
            record(
                "Dedicated Billing Role & Refund Protection",
                st_bill_adm == 403 and st_bill_rx == 403 and st_doc_rfd == 403 and st_rfd_ok == 201 and st_rfd_dup == 409 and rfd_code.startswith("RFD-"),
                f"Billing /admin={st_bill_adm}, Rx={st_bill_rx}; Doctor refund={st_doc_rfd}; Refund {rfd_code}={st_rfd_ok}, duplicate={st_rfd_dup}",
            )

            # 30. Zero Patient PII in Public Endpoints & Audit Logs
            _, _, b_pub_info = http_req(port, "GET", "/api/public/info")
            _, _, b_audit_logs = http_req(port, "GET", "/api/admin/audit", headers={"Cookie": admin_cookie})
            no_pii_leak = "9876543210" not in b_pub_info and "Aarav" not in b_pub_info and "Aarav" not in b_audit_logs and "9876543210" not in b_audit_logs
            record(
                "Zero Patient PII in Public APIs & Audit Logs",
                no_pii_leak,
                "Verified patient names and mobile numbers never leak into /api/public/info or audit_logs",
            )

            # 31. SQLite EXPLAIN QUERY PLAN Index Verification (Zero Full Table Scans)
            qp = verify_query_plans()
            record(
                "SQLite EXPLAIN QUERY PLAN Index Optimization",
                qp.get("all_indexed") is True and qp.get("checked_queries", 0) >= 7,
                f"All {qp.get('checked_queries')} hot hospital queries verified using SQLite indexes",
            )

            # 32. Durable Background Job Queue & Duplicate Reminder Prevention
            enq1, jid1 = srv.db.enqueue_job("appointment_reminder", f"rem:{rebook_id}", '{"type":"sms"}')
            enq2, _ = srv.db.enqueue_job("appointment_reminder", f"rem:{rebook_id}", '{"type":"sms"}')
            proc = srv.db.process_pending_jobs(limit=10)
            record(
                "Background Job Queue & Duplicate Prevention",
                enq1 is True and jid1 is not None and enq2 is False and proc["processed"] == 1 and proc["failed"] == 0,
                f"First enqueue=True, duplicate blocked=True, processed={proc['processed']}, failed={proc['failed']}",
            )

            # 33. Safe Public-Only TTL Cache (Slots Never Cached)
            _, h_c1, _ = http_req(port, "GET", "/api/public/info")
            _, h_c2, _ = http_req(port, "GET", "/api/public/info")
            _, h_sl, _ = http_req(port, "GET", f"/api/doctors/dr_rohan/slots?date={work1}")
            record(
                "Safe Public-Only Caching (Slots Uncached)",
                h_c2.get("x-cache") == "HIT" and "x-cache" not in h_sl and "no-store" in h_sl.get("cache-control", ""),
                f"/api/public/info X-Cache={h_c2.get('x-cache')}; /slots Cache-Control=no-store",
            )

            # 34. Admin-Only Observability Metrics Endpoint
            st_m_doc, _, _ = http_req(port, "GET", "/api/admin/metrics", headers={"Cookie": rohan_cookie})
            st_m_adm, _, b_m_adm = http_req(port, "GET", "/api/admin/metrics", headers={"Cookie": admin_cookie})
            m_data = json.loads(b_m_adm).get("metrics", {})
            record(
                "Admin-Only Observability Metrics",
                st_m_doc == 403 and st_m_adm == 200 and m_data.get("total_requests", 0) > 0 and m_data.get("status_5xx", 0) == 0,
                f"Doctor blocked={st_m_doc}, Admin={st_m_adm} (total_reqs={m_data.get('total_requests')}, 5xx={m_data.get('status_5xx')})",
            )

            # 35. Real Nested Razorpay Webhook Payload + SEO Routes (/robots.txt, /sitemap.xml)
            nested_wh = json.dumps({
                "event": "payment.captured",
                "payload": {"payment": {"entity": {"id": "pay_real_nested_001", "order_id": onl_order}}},
            })
            nested_sig = hmac.new(
                srv.config.razorpay_webhook_secret.encode("utf-8"),
                nested_wh.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            st_nwh, _, b_nwh = http_req(
                port,
                "POST",
                "/api/payments/webhook",
                body=nested_wh,
                headers={
                    "Content-Type": "application/json",
                    "X-Razorpay-Signature": nested_sig,
                    "X-Razorpay-Event-Id": "evt_nested_real_001",
                },
            )
            st_rob, _, b_rob = http_req(port, "GET", "/robots.txt")
            st_map, _, _ = http_req(port, "GET", "/sitemap.xml")
            record(
                "Real Nested Razorpay Webhook & SEO Routes",
                st_nwh == 200 and json.loads(b_nwh).get("duplicate") is False and st_rob == 200 and "Disallow: /admin" in b_rob and st_map == 200,
                f"Nested Razorpay webhook={st_nwh}, /robots.txt={st_rob} (blocks /admin), /sitemap.xml={st_map}",
            )

            # 36. Server-Side Session Token Revocation on Logout (Prevents Replay of Logged-Out Cookie)
            temp_cookie, _ = login("dr_snehal", cfg.staff_passwords["dr_snehal"])
            st_before_lo, _, _ = http_req(port, "GET", "/api/auth/me", headers={"Cookie": temp_cookie})
            st_lo, _, _ = http_req(port, "POST", "/api/auth/logout", body={}, headers={"Cookie": temp_cookie})
            st_after_lo, _, _ = http_req(port, "GET", "/api/auth/me", headers={"Cookie": temp_cookie})
            record(
                "Server-Side Logout Token Revocation",
                st_before_lo == 200 and st_lo == 200 and st_after_lo == 401,
                f"Before logout={st_before_lo}, logout={st_lo}, replayed token after logout={st_after_lo}",
            )

            # 37. Per-Account Brute-Force Lockout (5 Failed Logins -> 429 Account Lockout)
            bf_codes = []
            for _ in range(6):
                st_bf, _, _ = http_req(
                    port, "POST", "/api/auth/login", body={"username": "nurse", "password": "WrongPassword!"}
                )
                bf_codes.append(st_bf)
            record(
                "Per-Account Brute-Force Lockout (429)",
                bf_codes[:5] == [401, 401, 401, 401, 401] and bf_codes[5] == 429,
                f"6 bad logins on 'nurse' -> {bf_codes} (locked at 6th attempt with HTTP 429)",
            )

            # 38. Hospital Privilege Escalation Guard (Patient/Pharmacist/Billing Blocked from Staff PATCH & Notify)
            st_pat_patch, _, _ = http_req(
                port,
                "PATCH",
                f"/api/staff/appointments/{rebook_id}",
                body={"status": "completed"},
                headers={"Cookie": p1_cookie, "X-CSRF-Token": p1_csrf},
            )
            st_ph_notify, _, _ = http_req(
                port,
                "POST",
                f"/api/staff/appointments/{rebook_id}/notify",
                body={"message": "Unauthorized pharmacist SMS"},
                headers={"Cookie": pharm_cookie, "X-CSRF-Token": pharm_csrf},
            )
            st_bill_patch, _, _ = http_req(
                port,
                "PATCH",
                f"/api/staff/appointments/{rebook_id}",
                body={"status": "cancelled"},
                headers={"Cookie": billing_cookie, "X-CSRF-Token": billing_csrf},
            )
            record(
                "Hospital Staff Privilege Escalation Blocked",
                st_pat_patch == 403 and st_ph_notify == 403 and st_bill_patch == 403,
                f"Patient PATCH={st_pat_patch}, Pharmacist notify={st_ph_notify}, Billing PATCH={st_bill_patch}",
            )

            # 39. Cross-Doctor Lab Order Ownership Enforcement
            st_cross_lab, _, _ = http_req(
                port,
                "POST",
                "/api/lab/tests",
                body={"appointment_id": appt1["id"], "test_name": "Unauthorized CBC", "price_inr": 350},
                headers={"Cookie": rohan_cookie, "X-CSRF-Token": rohan_csrf},
            )
            record(
                "Cross-Doctor Lab Order Blocked",
                st_cross_lab == 403,
                f"Dr. Rohan ordering lab test on Dr. Snehal's patient -> HTTP {st_cross_lab}",
            )

            # 40. Cancelled Appointment Cannot Be Checked In via QR Token
            p1_cancelled_qr = json.loads(b_pb)["appointment"]["qr_token"]
            st_can_qr, _, _ = http_req(
                port,
                "POST",
                "/api/staff/checkin/scan",
                body={"qr_token": p1_cancelled_qr},
                headers={"Cookie": reception_cookie, "X-CSRF-Token": reception_csrf},
            )
            record(
                "Cancelled Appointment QR Check-In Blocked",
                st_can_qr == 404,
                f"Scanning cancelled appointment QR token -> HTTP {st_can_qr}",
            )

            # 41. Unsupported HTTP Methods (PUT/DELETE/TRACE) Return Safe 405 JSON
            st_del, _, _ = http_req(port, "DELETE", "/api/appointments")
            st_trc, _, _ = http_req(port, "TRACE", "/")
            record(
                "Safe HTTP Method Enforcement (405 JSON)",
                st_del == 405 and st_trc == 405,
                f"DELETE={st_del}, TRACE={st_trc} (no default HTML error leak)",
            )

            # 13. Rate limiting enforcement
            codes = []
            retry_seen = False
            for i in range(10):
                st_rl, h_rl, _ = http_req(
                    port,
                    "POST",
                    "/api/appointments",
                    body={
                        "first_name": "TestUser",
                        "last_name": "Burst",
                        "mobile": "9811223344",
                        "department": "Dental Surgery — Dr. Manjusha Patil",
                        "appointment_date": today_s,
                        "message": f"Checkup {i}",
                    },
                )
                codes.append(st_rl)
                if st_rl == 429 and "retry-after" in h_rl:
                    retry_seen = True
            record(
                "Rate Limiting (429 + Retry-After)",
                429 in codes and retry_seen,
                f"Burst responses: {codes.count(201)} allowed, {codes.count(429)} rate-limited with Retry-After",
            )
        finally:
            srv.shutdown()
            srv.server_close()

    passed_count = sum(1 for r in results if r["status"] == "PASS")
    return {
        "total_checks": len(results),
        "passed": passed_count,
        "failed": len(results) - passed_count,
        "results": results,
    }


if __name__ == "__main__":
    report = run_audit()
    print(json.dumps(report, indent=2))
    if report["failed"] > 0:
        raise SystemExit(1)
