# SECURITY_AUDIT_REPORT.md — Shri R.M. Patil Multi Speciality Hospital 2.0

**Audit Date:** 2026-11-27 (`Asia/Kolkata`)  
**Scope:** Authorized local source-code & automated API regression audit of `server.py`, `db.py`, `migrations.py`, `backup_db.py`, `db_optimize.py`, `public/index.html`, `public/admin.html`, `Dockerfile`, `docker-compose.yml`, and `.github/workflows/ci.yml`.  
**References:** OWASP Top 10 (2021) & OWASP ASVS Level 2 (Authentication, Access Control, Input Validation, Cryptography, Error Handling).  
**Final Automated Regression Suite (`python security_audit.py`):** **41 / 41 PASS, 0 FAIL**.

## Confirmed Vulnerabilities Found & Remediated

| # | Vulnerability | Severity | Affected File | Root Cause & Impact | Fix Implemented & Regression Check | Retest Result |
| :-: | :--- | :---: | :--- | :--- | :--- | :---: |
| 1 | Staff Appointment PATCH / Notify Privilege Escalation | **HIGH** | `server.py` (`do_PATCH`, `do_POST`) | `PATCH /api/staff/appointments/<id>` and `POST /api/staff/appointments/<id>/notify` checked `role == 'doctor'` for scoping but did not reject non-staff roles (`patient`, `pharmacist`, `billing`), allowing authenticated non-staff users with a valid CSRF token to update or notify appointments. | Added strict role allowlist `("admin", "doctor", "receptionist")` returning `403 Forbidden` + audit log (`UNAUTHORIZED_STAFF_APPT_PATCH` / `UNAUTHORIZED_STAFF_NOTIFY`). Added Check 38. | **PASS** (`403` for patient, pharmacist, billing) |
| 2 | Cross-Doctor Lab Order Ownership Bypass | **HIGH** | `server.py`, `db.py` (`create_lab_test`) | `POST /api/lab/tests` allowed any doctor to attach lab orders to another doctor's `appointment_id` and had no upper bound on `price_inr`. | Added `enforce_owner=True` check (`doctor_username = ?`) for doctors and validated `0 <= price_inr <= 100000`. Added Check 39. | **PASS** (`403` on cross-doctor lab order) |
| 3 | Logged-Out Session Token Replay | **HIGH** | `server.py` (`TokenSigner`, `/api/auth/logout`) | Clearing the browser cookie on logout did not invalidate a copied HMAC token server-side before its 1-hour expiry. | Added thread-safe server-side token revocation registry in `TokenSigner.revoke()` checked in `verify()`. Added Check 36. | **PASS** (`401` on replayed cookie after logout) |
| 4 | Distributed Account Brute-Force Exposure | **HIGH** | `server.py` (`/api/auth/login`) | Rate limiting tracked client IP only, leaving accounts exposed to distributed multi-IP password guessing. | Added per-username sliding-window lockout (`5` failures / 300s → `429` + `Retry-After: 300` + `ACCOUNT_LOCKED_BRUTEFORCE` log). Added Check 37. | **PASS** (6th bad login returns `429`) |
| 5 | Cancelled Appointment QR Check-In | **MEDIUM** | `db.py` (`checkin_by_qr_token`) | Scanning a cancelled appointment's QR token could still issue a queue token. | Filtered `AND a.status != 'cancelled'` in `checkin_by_qr_token()`. Added Check 40. | **PASS** (`404` on cancelled QR scan) |
| 6 | Unthrottled `PATCH` Endpoints | **MEDIUM** | `server.py` (`do_PATCH`) | `do_PATCH` lacked a top-level rate-limiting guard. | Added `_check_rate_limit("public", ...)` at the top of `do_PATCH`. | **PASS** |
| 7 | Defense-in-Depth DOM Escaping | **MEDIUM** | `public/index.html` | Live API responses (`rx.diagnosis`, `sms.text`) relied solely on backend sanitization before `innerHTML`. | Wrapped dynamic fields through `sanitizeText(...)` on the client as well. | **PASS** |
| 8 | Session Fixation & Default Method Error Pages | **LOW** | `server.py` (`do_POST`, `do_PUT/DELETE/TRACE`) | Re-login did not revoke any prior cookie; unsupported methods returned Python's default HTML error page. | Revoked prior `rmp_session` cookie on re-login and added clean JSON `405 Method Not Allowed` handlers for `PUT`, `DELETE`, and `TRACE`. Added Check 41. | **PASS** (`405` JSON) |

## Remaining Risks & Pre-Production Requirements
- **CRITICAL (Configuration):** Production deployment requires strong unique secrets in `.env` (`SESSION_SECRET`, staff passwords, live Razorpay & SMS keys), `SECURE_COOKIES=true`, `DEBUG=false`, and TLS/HTTPS via Caddy/Nginx.
- **HIGH (External Verification):** Automated tests do not substitute for an independent third-party VAPT, live OWASP ZAP / Trivy / Bandit / Gitleaks scans in staging, or legal sign-off on DPDP Act 2023 / DPDP Rules 2025 compliance before the May 2027 Phase 3 deadline.
- **MEDIUM (Operational):** Local SQLite backups (`backup_db.py`) are unencrypted on disk (`0600`); encrypt backups before off-site storage and add optional TOTP MFA for `admin`/`doctor` accounts.
