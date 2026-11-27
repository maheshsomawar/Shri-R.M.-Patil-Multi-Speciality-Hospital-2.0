# Shri R.M. Patil Multi Speciality Hospital & Trauma Care — Complete HMS

Zero-dependency Python 3.11 + SQLite WAL full-stack Hospital Management System with online pre-visit appointment booking, instant confirmation, Pay-at-Hospital & Razorpay test-mode payments, non-sensitive QR code check-in, all 7 RBAC roles, automated 36-point security audit, and 380-request concurrency & double-booking race simulation.

## Quick Start (Windows 11 & VS Code)

1. Open `shri_rm_patil_hospital` in VS Code and open the terminal (`Ctrl + ~`).
2. Create your local environment file (never commit `.env` to Git):
   ```powershell
   Copy-Item .env.example .env
   ```
3. Generate a strong `SESSION_SECRET` and update `.env`:
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
4. Run safe idempotent database migrations (`Asia/Kolkata` timezone):
   ```powershell
   python migrations.py
   ```
5. Run the 36-point security audit & 380-request traffic/race simulation:
   ```powershell
   python security_audit.py
   python traffic_sim.py
   ```
   *(If you update staff passwords in `.env` after initial seeding, run `python db.py --sync-passwords` to update their scrypt hashes in SQLite.)*
6. Start the server:
   ```powershell
   python server.py
   ```
   Open `http://127.0.0.1:8080` in your browser.

## Database Schema (Migrations 001–006)
- `001_initial_schema`: `users`, `appointments`, `notifications`, `audit_logs`
- `002_departments_and_doctors`: `departments`, `doctors` (with verified Reg. Nos., fees, slot durations)
- `003_patients_and_patient_links`: `patients` (`PAT-YYYYMMDD-NNN`), `appointments.patient_code`
- `004_doctor_schedules_and_slots`: `doctor_schedules`, `doctor_holidays`, `appointments.slot_time` + partial unique index `uq_appointments_active_slot`
- `005_payments_qr_and_checkin`: `payments` (`RCP-YYYYMMDD-NNN`), `payment_webhooks`, `appointments.qr_token`, `checked_in_at`, `queue_token`
- `006_clinical_pharmacy_lab_billing`: `prescriptions`, `pharmacy_inventory` (Shiv Medical Stores), `lab_tests`, `invoices` (`INV-YYYYMMDD-NNN`)

## REST API Summary
- **Public:** `GET /api/health`, `GET /api/public/info`, `GET /api/doctors/<username>/slots?date=YYYY-MM-DD`, `GET /api/payments/config`, `POST /api/appointments`
- **Auth:** `POST /api/patients/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- **Patient (isolated):** `GET /api/patient/me`, `PATCH /api/patient/me`, `GET /api/patient/appointments`, `GET /api/patient/appointments/<id>`, `POST /api/patient/appointments/<id>/cancel`, `POST /api/patient/appointments/<id>/reschedule`, `GET /api/patient/prescriptions`, `POST /api/patient/consent`, `GET/POST /api/patient/privacy-requests`, `GET /api/receipts/<id>/print`, `GET /api/prescriptions/<id>/print`
- **Payments & QR Check-In:** `POST /api/payments/online/verify`, `POST /api/payments/webhook`, `POST /api/staff/payments/<id>/collect`, `POST /api/staff/checkin/scan`
- **Doctor / Staff / Clinical:** `GET /api/staff/appointments`, `GET /api/staff/appointments/summary`, `PATCH /api/staff/appointments/<id>`, `POST /api/staff/appointments/<id>/notify`, `GET /api/staff/notifications`, `GET/POST /api/staff/holidays`, `POST /api/doctor/prescriptions`
- **Pharmacy, Lab & Billing:** `GET /api/pharmacy/inventory`, `POST /api/pharmacy/dispense`, `GET/POST /api/lab/tests`, `PATCH /api/lab/tests/<id>`, `GET/POST /api/billing/invoices`, `POST /api/billing/refunds`
- **Admin:** `GET /admin`, `GET /api/admin/overview`, `GET /api/admin/metrics`, `GET /api/admin/audit`

## Production Deployment & Backup Checklist
1. Set `DEBUG=false`, `SECURE_COOKIES=true`, a 64-char random `SESSION_SECRET`, strong unique staff passwords, and exact `ALLOWED_ORIGINS` (your HTTPS domain) in `.env`.
2. Terminate TLS/HTTPS in front of `127.0.0.1:8080` using Caddy or Nginx with Let's Encrypt certificates.
3. Schedule encrypted daily SQLite backups using SQLite's online backup API (`sqlite3 data/hospital.db ".backup 'backups/hospital_YYYYMMDD.db'"`).
4. Before go-live, complete an independent security review and verify compliance with applicable healthcare data protection requirements (e.g., India's DPDP Act).
