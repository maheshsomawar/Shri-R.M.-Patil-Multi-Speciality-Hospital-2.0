"""
Production-hardened HTTP/API server for Shri R.M. Patil Multi Speciality Hospital.
Zero external third-party dependencies (Python 3.11 stdlib only).

Features & Security Controls:
- Secrets loaded strictly from environment variables (never hardcoded or sent to client)
- Debug mode disabled by default (no stack trace leaks)
- Signed HMAC-SHA256 HttpOnly/SameSite=Strict session cookies + CSRF token verification
- Strict Role-Based Access Control (admin, doctor, receptionist)
- Sequential Appointment Number (APT-YYYYMMDD-NNN) + automatic confirmation SMS on booking
- Doctor-scoped patient notifications (POST /api/staff/appointments/<id>/notify) with ownership check
- Doctor-scoped Daily & Monthly appointment summaries (GET /api/staff/appointments/summary)
- Input validation + HTML/XSS sanitization
- Thread-safe sliding-window rate limiting per IP & endpoint group (including SMS anti-abuse)
- High-concurrency TCP backlog (request_queue_size=128) + SQLite WAL mode
- Strict CORS allowlist, 7 security headers, static file allowlist + path traversal protection
"""

import base64
import collections
import concurrent.futures
import gzip
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, Optional, Tuple
from urllib import error as urllib_error, request as urllib_request
from urllib.parse import parse_qs, urlparse

from db import HospitalDB, SlotConflictError, SlotUnavailableError, verify_password
from migrations import ist_now_iso, ist_today

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
MAX_BODY_BYTES = 16 * 1024  # 16 KB max JSON payload

DEPARTMENT_TO_DOCTOR = {
    "Orthopaedics — Dr. Rohan Patil": "dr_rohan",
    "Obstetrics & Gynaecology — Dr. Rahul Patil": "dr_rahul",
    "Dental Surgery — Dr. Manjusha Patil": "dr_manjusha",
    "General Medicine — Dr. Snehal Patil": "dr_snehal",
}

ALLOWED_STATUSES = {"pending", "confirmed", "completed", "cancelled"}
STATIC_ALLOWLIST = {"index.html", "admin.html", "staff.html"}
ASSET_ALLOWLIST = {
    "site.v1.css": ("text/css; charset=utf-8", True),
    "site.v1.js": ("application/javascript; charset=utf-8", True),
    "hospital-atrium-480.webp": ("image/webp", False),
    "hospital-atrium-800.webp": ("image/webp", False),
    "hospital-atrium-1200.webp": ("image/webp", False),
    "hospital-atrium-800.jpg": ("image/jpeg", False),
}

NAME_RE = re.compile(r"^[A-Za-z\s.'-]{2,60}$")
MOBILE_RE = re.compile(r"^[6-9]\d{9}$")


def normalize_indian_mobile(raw: str) -> str:
    """Normalize Indian mobile numbers (+91 / 91 / leading 0 / spaces / dashes) to 10 digits."""
    digits = re.sub(r"[\s\-()+]", "", str(raw or "").strip())
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}$")
SCRIPT_TAG_RE = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)


def load_dotenv_file(path: str) -> None:
    """Minimal .env parser (never overrides already-set environment variables)."""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val



def render_letterhead_html(title: str, body_html: str) -> bytes:
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{html.escape(title)} — Shri R.M. Patil Hospital</title>
<style>
  body {{ font-family: Georgia, serif; color: #0f172a; margin: 0; padding: 24px; background: #f8fafc; }}
  .sheet {{ max-width: 780px; margin: 0 auto; background: #fff; border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; }}
  .hdr {{ background: #071324; color: #fff; padding: 20px 28px; border-bottom: 4px solid #d8b54c; }}
  .hdr h1 {{ margin: 0; font-size: 22px; }}
  .hdr .sub {{ color: #d8b54c; font-size: 13px; margin-top: 4px; }}
  .hdr .motto {{ color: #94a3b8; font-size: 12px; font-style: italic; margin-top: 4px; }}
  .docs {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; background: #0d1c31; color: #e2e8f0; padding: 10px 20px; font-family: sans-serif; font-size: 11px; }}
  .content {{ padding: 24px 28px; font-family: sans-serif; font-size: 14px; line-height: 1.6; }}
  .ftr {{ background: #f1f5f9; border-top: 2px solid #0d9488; padding: 12px 24px; font-family: sans-serif; font-size: 12px; color: #334155; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
  .print-btn {{ margin-top: 16px; padding: 8px 16px; background: #0d9488; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }}
  @media print {{ body {{ background: #fff; padding: 0; }} .sheet {{ border: none; }} .print-btn {{ display: none; }} }}
</style>
</head>
<body>
  <div class="sheet">
    <div class="hdr">
      <h1>श्री आर.एम. पाटील मल्टिस्पेशालिटी हॉस्पिटल अँड ट्रॉमा केअर</h1>
      <div class="sub">Shri R.M. Patil Multi Speciality Hospital &amp; Trauma Care · प्रसूतीगृह व ॲक्सिडेंट हॉस्पिटल</div>
      <div class="motto">ॐ सर्वे भवन्तु सुखिनः सर्वे सन्तु निरामयाः</div>
    </div>
    <div class="docs">
      <div><strong>Dr. Rohan Patil</strong><br/>Ortho · 2008/10/3539</div>
      <div><strong>Dr. Rahul Patil</strong><br/>Obgy · 2022/12/9582</div>
      <div><strong>Dr. Manjusha Patil</strong><br/>Dental · A-29811</div>
      <div><strong>Dr. Snehal Patil</strong><br/>Physician · A-2018/03/0645</div>
    </div>
    <div class="content">
      {body_html}
      <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
    </div>
    <div class="ftr">
      <span>Manu-Madhav Plaza, SBI Bank Bldg, Chakur, Dist. Latur · 02381-299133 | 94217 62599</span>
      <span>Pharmacy: Shiv Medical Stores · Mo. 84213 07374</span>
    </div>
  </div>
</body>
</html>"""
    return doc.encode("utf-8")

def sanitize_text(value: str, max_len: int = 300) -> str:
    """Strip dangerous script tags/event handlers and HTML-escape untrusted input."""
    cleaned = SCRIPT_TAG_RE.sub("", value or "")
    cleaned = EVENT_HANDLER_RE.sub("", cleaned)
    cleaned = cleaned.strip()[:max_len]
    return html.escape(cleaned, quote=True)


def validate_date_str(date_str: str) -> Optional[str]:
    if not DATE_RE.match(date_str):
        return None
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return date_str
    except ValueError:
        return None


def validate_month_str(month_str: str) -> Optional[str]:
    if not MONTH_RE.match(month_str):
        return None
    try:
        datetime.strptime(month_str, "%Y-%m")
        return month_str
    except ValueError:
        return None


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding-window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)

    def allow(self, key: str, limit: int, window_sec: float) -> Tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_sec
        with self._lock:
            dq = self._buckets[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= limit:
                retry_after = max(1, int(window_sec - (now - dq[0])) + 1)
                return False, retry_after
            dq.append(now)
            return True, 0


class TokenSigner:
    """HMAC-SHA256 signed session tokens with expiration and server-side revocation."""

    def __init__(self, secret_key: str) -> None:
        self._key = secret_key.encode("utf-8")
        self._revoked_lock = threading.Lock()
        self._revoked: Dict[str, int] = {}

    def sign(self, payload: Dict[str, Any], ttl_seconds: int = 3600) -> str:
        body = dict(payload)
        body["exp"] = int(time.time()) + ttl_seconds
        body["csrf"] = secrets.token_hex(16)
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        sig = hmac.new(self._key, b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{b64}.{sig}"

    def revoke(self, token: str) -> None:
        try:
            _, sig = token.split(".", 1)
            now = int(time.time())
            with self._revoked_lock:
                self._revoked[sig] = now + 3600
                expired = [k for k, exp in self._revoked.items() if exp < now]
                for k in expired:
                    del self._revoked[k]
        except Exception:
            pass

    def verify(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            b64, sig = token.split(".", 1)
            with self._revoked_lock:
                if sig in self._revoked:
                    return None
            expected = hmac.new(self._key, b64.encode("ascii"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            padded = b64 + "=" * (-len(b64) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            if int(data.get("exp", 0)) < int(time.time()):
                return None
            return data
        except Exception:
            return None


def _safe_server_secret(raw_value: str, min_len: int = 32) -> str:
    """Reject empty, short, or placeholder secrets and generate an ephemeral cryptographic key."""
    val = (raw_value or "").strip()
    lower = val.lower()
    if len(val) < min_len or any(tok in lower for tok in ("replace_with", "change_me", "placeholder", "replace_me")):
        return secrets.token_hex(32)
    return val


class AppConfig:
    def __init__(self) -> None:
        load_dotenv_file(os.path.join(BASE_DIR, ".env"))
        self.host = os.environ.get("HOST", "127.0.0.1")
        self.port = int(os.environ.get("PORT", "8080"))
        self.debug = os.environ.get("DEBUG", "false").lower() == "true"
        self.trust_proxy = os.environ.get("TRUST_PROXY", "false").lower() == "true"
        self.secure_cookies = os.environ.get("SECURE_COOKIES", "false").lower() == "true"
        self.session_secret = _safe_server_secret(os.environ.get("SESSION_SECRET", ""), min_len=32)
        self.sms_api_key = os.environ.get("SMS_GATEWAY_API_KEY", "")
        self.sms_provider = os.environ.get("SMS_PROVIDER", "").strip().lower()
        self.msg91_sender_id = os.environ.get("MSG91_SENDER_ID", "RMPHSP").strip()
        self.msg91_template_id = os.environ.get("MSG91_TEMPLATE_ID", "").strip()
        self.razorpay_key_id = os.environ.get("RAZORPAY_KEY_ID", "rzp_test_replace_me")
        self.razorpay_key_secret = _safe_server_secret(os.environ.get("RAZORPAY_KEY_SECRET", ""), min_len=16)
        self.razorpay_webhook_secret = _safe_server_secret(os.environ.get("RAZORPAY_WEBHOOK_SECRET", ""), min_len=16)
        origins_raw = os.environ.get("ALLOWED_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080")
        self.allowed_origins = {o.strip() for o in origins_raw.split(",") if o.strip()}
        self.db_path = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "hospital.db"))
        self.rate_limit_public = int(os.environ.get("RATE_LIMIT_PUBLIC", "120"))
        self.rate_limit_booking = int(os.environ.get("RATE_LIMIT_BOOKING", "15"))
        self.rate_limit_login = int(os.environ.get("RATE_LIMIT_LOGIN", "10"))
        self.rate_limit_notify = int(os.environ.get("RATE_LIMIT_NOTIFY", "30"))
        self.staff_passwords = {
            "admin": os.environ.get("ADMIN_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "dr_rohan": os.environ.get("DR_ROHAN_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "dr_rahul": os.environ.get("DR_RAHUL_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "dr_manjusha": os.environ.get("DR_MANJUSHA_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "dr_snehal": os.environ.get("DR_SNEHAL_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "reception": os.environ.get("RECEPTION_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "nurse": os.environ.get("NURSE_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "pharmacist": os.environ.get("PHARMACIST_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "lab_tech": os.environ.get("LAB_TECH_PASSWORD", "").strip() or secrets.token_urlsafe(20),
            "billing_desk": os.environ.get("BILLING_PASSWORD", "").strip() or secrets.token_urlsafe(20),
        }


class MetricsCollector:
    """Thread-safe observability metrics (never stores PII, tokens, or passwords)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.total_requests = 0
        self.active_requests = 0
        self.peak_concurrent = 0
        self.status_2xx = 0
        self.status_4xx = 0
        self.status_429 = 0
        self.status_5xx = 0

    def enter_request(self) -> None:
        with self._lock:
            self.active_requests += 1
            if self.active_requests > self.peak_concurrent:
                self.peak_concurrent = self.active_requests

    def exit_request(self) -> None:
        with self._lock:
            self.active_requests = max(0, self.active_requests - 1)

    def record(self, status: int) -> None:
        with self._lock:
            self.total_requests += 1
            if 200 <= status < 300:
                self.status_2xx += 1
            elif status == 429:
                self.status_429 += 1
                self.status_4xx += 1
            elif 400 <= status < 500:
                self.status_4xx += 1
            elif status >= 500:
                self.status_5xx += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "total_requests": self.total_requests,
                "active_requests": self.active_requests,
                "peak_concurrent": self.peak_concurrent,
                "status_2xx": self.status_2xx,
                "status_4xx": self.status_4xx,
                "status_429": self.status_429,
                "status_5xx": self.status_5xx,
            }


class PublicTTLCache:
    """Short-TTL cache strictly for non-sensitive public hospital catalog data."""

    def __init__(self, ttl_sec: float = 30.0) -> None:
        self._lock = threading.Lock()
        self._ttl = ttl_sec
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        with self._lock:
            item = self._store.get(key)
            if not item or item[0] < now:
                return None
            return item[1]

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic() + self._ttl, value)


class HospitalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 512

    def __init__(self, server_address, handler_cls, config: AppConfig, db: HospitalDB):
        super().__init__(server_address, handler_cls)
        self.config = config
        self.db = db
        self.signer = TokenSigner(config.session_secret)
        self.rate_limiter = SlidingWindowRateLimiter()
        self.metrics = MetricsCollector()
        self.public_cache = PublicTTLCache(ttl_sec=30.0)
        self.idempotency_cache = PublicTTLCache(ttl_sec=600.0)
        max_workers = int(os.environ.get("MAX_WORKERS", "64"))
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self._login_lock = threading.Lock()
        self._login_failures: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)

    def process_request(self, request, client_address) -> None:
        request.settimeout(10.0)
        self._pool.submit(self._bounded_worker, request, client_address)

    def _bounded_worker(self, request, client_address) -> None:
        self.metrics.enter_request()
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.metrics.exit_request()
            self.shutdown_request(request)

    def server_close(self) -> None:
        try:
            self._pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        super().server_close()


class HospitalRequestHandler(BaseHTTPRequestHandler):
    def version_string(self) -> str:
        return "HospitalWeb"

    def send_error(self, code: int, message: Optional[str] = None, explain: Optional[str] = None) -> None:
        safe_msg = "Request could not be processed" if code >= 500 else (message or "Bad request")
        self._send_json(code, {"error": safe_msg})

    def log_message(self, format: str, *args: Any) -> None:
        if self.server.config.debug:  # type: ignore[attr-defined]
            super().log_message(format, *args)

    @property
    def cfg(self) -> AppConfig:
        return self.server.config  # type: ignore[attr-defined]

    @property
    def db(self) -> HospitalDB:
        return self.server.db  # type: ignore[attr-defined]

    @property
    def signer(self) -> TokenSigner:
        return self.server.signer  # type: ignore[attr-defined]

    @property
    def limiter(self) -> SlidingWindowRateLimiter:
        return self.server.rate_limiter  # type: ignore[attr-defined]

    def _client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else "unknown"
        if self.cfg.trust_proxy and peer in ("127.0.0.1", "::1"):
            real_ip = (self.headers.get("X-Real-IP") or "").strip()
            if real_ip and re.fullmatch(r"[0-9a-fA-F.:]{3,45}", real_ip):
                return real_ip
        return peer

    def _has_real_sms_key(self) -> bool:
        return bool(self.cfg.sms_api_key and not self.cfg.sms_api_key.startswith("replace_with_"))

    def _has_real_razorpay(self) -> bool:
        kid = self.cfg.razorpay_key_id
        sec = self.cfg.razorpay_key_secret
        return bool(
            kid.startswith("rzp_")
            and not kid.startswith("rzp_test_replace")
            and not kid.startswith("rzp_test_local")
            and sec
            and not sec.startswith("replace_with_")
        )

    def _create_razorpay_order(self, amount_inr: int, receipt_ref: str) -> Optional[str]:
        """Create a real Razorpay Order server-side when real test/live keys are configured."""
        if not self._has_real_razorpay():
            return None
        auth_b64 = base64.b64encode(
            f"{self.cfg.razorpay_key_id}:{self.cfg.razorpay_key_secret}".encode("utf-8")
        ).decode("ascii")
        payload = json.dumps({
            "amount": amount_inr * 100,
            "currency": "INR",
            "receipt": receipt_ref[:40],
        }).encode("utf-8")
        req = urllib_request.Request(
            "https://api.razorpay.com/v1/orders",
            data=payload,
            headers={
                "Authorization": f"Basic {auth_b64}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                order_id = str(data.get("id", "")).strip()
                return order_id if order_id.startswith("order_") else None
        except Exception:
            return None

    def _dispatch_sms(self, mobile: str, text: str) -> str:
        """
        Server-side SMS dispatcher using hidden SMS_GATEWAY_API_KEY env var.
        Supports Fast2SMS (SMS_PROVIDER=fast2sms) and MSG91 (SMS_PROVIDER=msg91) over HTTPS;
        never exposes keys to browser JS and gracefully falls back when unconfigured.
        """
        if not self._has_real_sms_key():
            return "queued_local"
        if self.cfg.sms_provider == "fast2sms":
            payload = json.dumps({
                "route": "q",
                "message": text,
                "language": "english",
                "flash": 0,
                "numbers": mobile,
            }).encode("utf-8")
            req = urllib_request.Request(
                "https://www.fast2sms.com/dev/bulkV2",
                data=payload,
                headers={
                    "authorization": self.cfg.sms_api_key,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib_request.urlopen(req, timeout=4) as resp:
                    return "sent" if 200 <= resp.status < 300 else "gateway_error"
            except (urllib_error.URLError, TimeoutError, ValueError):
                return "gateway_error"
        if self.cfg.sms_provider == "msg91" and self.cfg.msg91_template_id:
            payload = json.dumps({
                "template_id": self.cfg.msg91_template_id,
                "short_url": "0",
                "recipients": [{"mobiles": f"91{mobile}", "message": text}],
            }).encode("utf-8")
            req = urllib_request.Request(
                "https://control.msg91.com/api/v5/flow/",
                data=payload,
                headers={
                    "authkey": self.cfg.sms_api_key,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib_request.urlopen(req, timeout=4) as resp:
                    return "sent" if 200 <= resp.status < 300 else "gateway_error"
            except (urllib_error.URLError, TimeoutError, ValueError):
                return "gateway_error"
        return "sent"

    def _apply_security_headers(self, is_api: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        if is_api:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
            self.send_header("Pragma", "no-cache")
        else:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://checkout.razorpay.com; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.razorpay.com; "
                "frame-src https://api.razorpay.com https://checkout.razorpay.com; "
                "connect-src 'self' https://api.razorpay.com https://lumberjack.razorpay.com; "
                "frame-ancestors 'none'; base-uri 'self'",
            )
        origin = self.headers.get("Origin")
        if origin and origin in self.cfg.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def _send_json(
        self,
        status: int,
        payload: Dict[str, Any],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.server.metrics.record(status)  # type: ignore[attr-defined]
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._apply_security_headers(is_api=True)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, "Invalid Content-Length header"
        if length <= 0 or length > MAX_BODY_BYTES:
            return None, "Payload size out of allowed bounds"
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return None, "JSON object expected"
            return data, None
        except Exception:
            return None, "Malformed JSON payload"

    def _get_session(self) -> Optional[Dict[str, Any]]:
        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw_cookie)
        except Exception:
            return None
        if "rmp_session" not in jar:
            return None
        return self.signer.verify(jar["rmp_session"].value)

    def _check_rate_limit(self, group: str, limit: int, window_sec: float = 60.0) -> bool:
        key = f"{group}:{self._client_ip()}"
        ok, retry = self.limiter.allow(key, limit, window_sec)
        if not ok:
            self._send_json(
                429,
                {"error": "Too many requests. Please try again shortly."},
                extra_headers={"Retry-After": str(retry)},
            )
            return False
        return True

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"error": "Method not allowed"})

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_TRACE(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin in self.cfg.allowed_origins:
            self.send_response(204)
            self._apply_security_headers(is_api=True)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
            self.end_headers()
        else:
            self._send_json(403, {"error": "Origin not allowed"})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if not self._check_rate_limit("public", self.cfg.rate_limit_public, 60.0):
            return

        if path == "/api/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "hospital": "Shri R.M. Patil Multi Speciality Hospital & Trauma Care",
                    "timezone": "Asia/Kolkata",
                    "server_time_ist": ist_now_iso(),
                    "debug": False,
                    "sms_gateway_configured": self._has_real_sms_key(),
                    "razorpay_configured": self._has_real_razorpay(),
                },
            )
            return

        if path == "/api/appointments/check":
            self._send_json(
                405,
                {"error": "Method not allowed. Use POST /api/appointments/check with JSON body."},
                extra_headers={"Allow": "POST"},
            )
            return

        if path == "/api/payments/config":
            has_rzp = self._has_real_razorpay()
            self._send_json(
                200,
                {
                    "razorpay_configured": has_rzp,
                    "key_id": self.cfg.razorpay_key_id if has_rzp else None,
                    "mode": "test" if self.cfg.razorpay_key_id.startswith("rzp_test_") else ("live" if has_rzp else "placeholder"),
                },
            )
            return

        if path == "/api/public/info":
            cached = self.server.public_cache.get("public_info")  # type: ignore[attr-defined]
            if cached is not None:
                self._send_json(200, cached, extra_headers={"X-Cache": "HIT"})
                return
            payload = {
                "hospital": "Shri R.M. Patil Multi Speciality Hospital & Trauma Care",
                "timezone": "Asia/Kolkata",
                "today_ist": ist_today(),
                "address": "Manu-Madhav Plaza, SBI Bank Building, Near Old Bus Stand, Chakur, Dist. Latur, Maharashtra",
                "phones": ["02381-299133", "94217 62599"],
                "pharmacy": {"name": "Shiv Medical Stores", "mobile": "84213 07374"},
                "departments": self.db.list_departments(),
                "doctors": self.db.list_doctors(),
            }
            self.server.public_cache.set("public_info", payload)  # type: ignore[attr-defined]
            self._send_json(200, payload, extra_headers={"X-Cache": "MISS"})
            return

        # Public doctor availability & open time slots (blocks past dates, holidays, breaks, booked slots)
        if path.startswith("/api/doctors/") and path.endswith("/slots"):
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                self._send_json(400, {"error": "Invalid doctor slots route"})
                return
            doc_user = parts[2].strip().lower()
            date_param = qs.get("date", [ist_today()])[0]
            valid_date = validate_date_str(date_param)
            if not valid_date:
                self._send_json(400, {"error": "Invalid date parameter (expected YYYY-MM-DD)"})
                return
            try:
                info = self.db.get_available_slots(doc_user, valid_date)
                self._send_json(200, info)
            except SlotUnavailableError as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if path == "/api/auth/me":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            self._send_json(
                200,
                {
                    "username": session["username"],
                    "full_name": session["full_name"],
                    "role": session["role"],
                    "csrf_token": session["csrf"],
                },
            )
            return

        # Daily & Monthly summary strictly scoped by doctor RBAC
        if path == "/api/staff/appointments/summary":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            role = session.get("role")
            if role not in ("admin", "receptionist", "doctor", "billing"):
                self._send_json(403, {"error": "Forbidden"})
                return
            today = ist_today()
            date_param = qs.get("date", [today])[0]
            month_param = qs.get("month", [date_param[:7]])[0]
            valid_date = validate_date_str(date_param)
            valid_month = validate_month_str(month_param)
            if not valid_date or not valid_month:
                self._send_json(400, {"error": "Invalid date (YYYY-MM-DD) or month (YYYY-MM) parameter"})
                return
            doctor_scope = session["username"] if role == "doctor" else None
            summary = self.db.get_appointment_summary(valid_date, valid_month, doctor_username=doctor_scope)
            self._send_json(200, summary)
            return

        # Staff appointments (supports ?date=YYYY-MM-DD or ?month=YYYY-MM)
        if path == "/api/staff/appointments":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            role = session.get("role")
            if role not in ("admin", "receptionist", "doctor", "billing"):
                self._send_json(403, {"error": "Forbidden"})
                return
            date_filter = None
            month_filter = None
            if "date" in qs and qs["date"][0]:
                date_filter = validate_date_str(qs["date"][0])
                if not date_filter:
                    self._send_json(400, {"error": "Invalid date parameter (expected YYYY-MM-DD)"})
                    return
            elif "month" in qs and qs["month"][0]:
                month_filter = validate_month_str(qs["month"][0])
                if not month_filter:
                    self._send_json(400, {"error": "Invalid month parameter (expected YYYY-MM)"})
                    return
            doctor_scope = session["username"] if role == "doctor" else None
            rows = self.db.list_appointments(
                doctor_username=doctor_scope,
                appointment_date=date_filter,
                month_prefix=month_filter,
            )
            self._send_json(200, {"appointments": rows, "count": len(rows)})
            return

        # Doctor/Staff notifications log (strictly scoped to own patients for doctors)
        if path == "/api/staff/notifications":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            role = session.get("role")
            if role not in ("admin", "receptionist", "doctor", "billing"):
                self._send_json(403, {"error": "Forbidden"})
                return
            doctor_scope = session["username"] if role == "doctor" else None
            notes = self.db.list_notifications(doctor_username=doctor_scope, limit=50)
            self._send_json(200, {"notifications": notes, "count": len(notes)})
            return

        # Patient-only profile (strictly isolated to logged-in patient)
        if path == "/api/patient/me":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            self._send_json(200, {"patient": prof, "csrf_token": session["csrf"]})
            return

        # Patient-only appointment list (zero cross-patient access)
        if path == "/api/patient/appointments":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            rows = self.db.list_patient_appointments(prof["patient_code"], prof["mobile"])
            self._send_json(200, {"appointments": rows, "count": len(rows)})
            return

        # Patient-only single appointment lookup (blocks guessing another patient's ID with 403)
        if path.startswith("/api/patient/appointments/"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            try:
                appt_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            appt = self.db.get_patient_appointment_by_id(appt_id, prof["patient_code"], prof["mobile"])
            if not appt:
                self.db.log_audit(session["username"], f"BLOCKED_CROSS_PATIENT_READ:{appt_id}", self._client_ip(), 403)
                self._send_json(403, {"error": "Access denied to requested appointment"})
                return
            self._send_json(200, {"appointment": appt})
            return

        if path == "/api/patient/prescriptions":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            rows = self.db.list_patient_prescriptions(prof["patient_code"], prof["mobile"])
            self._send_json(200, {"prescriptions": rows, "count": len(rows)})
            return

        if path == "/api/patient/privacy-requests":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            rows = self.db.list_privacy_requests(patient_code=prof["patient_code"])
            self._send_json(200, {"privacy_requests": rows, "count": len(rows)})
            return

        # Shared Ward Nurse Roster & Notifications (Nurse, Doctor, Admin ONLY — zero billing/admin leak!)
        if path == "/api/nurse/notifications":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("nurse", "doctor", "admin"):
                self._send_json(403, {"error": "Nurse, Doctor, or Admin access required"})
                return
            self._send_json(200, self.db.list_nurse_roster_and_alerts())
            return

        # Separate Shiv Medical Stores Financial Reports, Purchases & Bills (Pharmacist & Admin ONLY — separate from hospital billing_desk!)
        if path == "/api/pharmacy/reports":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self._send_json(403, {"error": "Shiv Medical Stores Pharmacist or Admin access required"})
                return
            self._send_json(200, {"report": self.db.get_pharmacy_financial_report()})
            return

        if path == "/api/pharmacy/purchases":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self._send_json(403, {"error": "Shiv Medical Stores Pharmacist or Admin access required"})
                return
            purchases = self.db.list_pharmacy_purchases(50)
            self._send_json(200, {"store_name": "Shiv Medical Stores", "purchases": purchases, "count": len(purchases)})
            return

        if path == "/api/pharmacy/bills":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self._send_json(403, {"error": "Shiv Medical Stores Pharmacist or Admin access required"})
                return
            bills = self.db.list_pharmacy_bills(50)
            self._send_json(200, {"store_name": "Shiv Medical Stores", "bills": bills, "count": len(bills)})
            return

        # Dynamic Lab Test Catalog (All clinical staff can view; Lab Tech & Admin can add new tests)
        if path == "/api/lab/catalog":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("lab_tech", "doctor", "admin", "receptionist"):
                self._send_json(403, {"error": "Clinical staff access required"})
                return
            items = self.db.list_lab_catalog()
            self._send_json(200, {"catalog": items, "count": len(items)})
            return

        if path == "/api/pharmacy/inventory":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self._send_json(403, {"error": "Pharmacist or Admin access required"})
                return
            self._send_json(200, self.db.list_pharmacy_inventory())
            return

        if path == "/api/lab/tests":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            role = session.get("role")
            if role not in ("doctor", "lab_tech", "admin"):
                self._send_json(403, {"error": "Doctor, Lab Tech, or Admin access required"})
                return
            doc_scope = session["username"] if role == "doctor" else None
            rows = self.db.list_lab_tests(doctor_username=doc_scope)
            self._send_json(200, {"lab_tests": rows, "count": len(rows)})
            return

        if path == "/api/billing/invoices":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") not in ("billing", "receptionist", "admin"):
                self._send_json(403, {"error": "Billing, Receptionist, or Admin access required"})
                return
            rows = self.db.list_invoices()
            self._send_json(200, {"invoices": rows, "count": len(rows)})
            return

        if path == "/api/staff/holidays":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            role = session.get("role")
            if role not in ("doctor", "receptionist", "admin"):
                self._send_json(403, {"error": "Staff access required"})
                return
            doc_scope = session["username"] if role == "doctor" else None
            rows = self.db.list_doctor_holidays(doctor_username=doc_scope)
            self._send_json(200, {"holidays": rows, "count": len(rows)})
            return

        # Printable Official Letterhead Receipt (Admin, Receptionist, or Owning Patient ONLY)
        if path.startswith("/api/receipts/") and path.endswith("/print"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                self._send_json(400, {"error": "Invalid receipt route"})
                return
            try:
                appt_id = int(parts[2])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            rec = self.db.get_receipt_detail(appt_id)
            if not rec:
                self._send_json(404, {"error": "Receipt not found"})
                return
            role = session.get("role")
            if role == "patient":
                prof = self.db.get_patient_profile(session["username"])
                if not prof or (rec.get("patient_code") != prof["patient_code"] and rec.get("mobile") != prof["mobile"]):
                    self._send_json(403, {"error": "Access denied to this receipt"})
                    return
            elif role not in ("admin", "receptionist", "billing"):
                self._send_json(403, {"error": "Access denied"})
                return
            body_html = f"""
              <h2 style="margin-top:0;color:#0d9488;">Payment &amp; Appointment Receipt</h2>
              <p><strong>Receipt No:</strong> {html.escape(str(rec.get('receipt_number') or 'PENDING'))}<br/>
              <strong>Appointment No:</strong> {html.escape(str(rec['appointment_number']))} ({html.escape(str(rec['appointment_date']))} {html.escape(str(rec.get('slot_time') or ''))})<br/>
              <strong>Patient:</strong> {html.escape(str(rec['first_name']))} {html.escape(str(rec['last_name']))} · Mobile: {html.escape(str(rec['mobile']))}<br/>
              <strong>Department / Doctor:</strong> {html.escape(str(rec['department']))}<br/>
              <strong>Consultation Fee:</strong> ₹{int(rec.get('amount_inr') or 0)}<br/>
              <strong>Payment Status:</strong> {html.escape(str(rec.get('payment_status') or 'PENDING'))} ({html.escape(str(rec.get('method') or 'pay_at_hospital'))})</p>
            """
            page = render_letterhead_html(f"Receipt {rec.get('receipt_number') or rec['appointment_number']}", body_html)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self._apply_security_headers(is_api=False)
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
            self.end_headers()
            self.wfile.write(page)
            return

        # Printable Official Letterhead Prescription (Admin, Authoring Doctor, or Owning Patient ONLY)
        if path.startswith("/api/prescriptions/") and path.endswith("/print"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                self._send_json(400, {"error": "Invalid prescription route"})
                return
            try:
                rx_id = int(parts[2])
            except ValueError:
                self._send_json(400, {"error": "Invalid prescription ID"})
                return
            rx = self.db.get_prescription_detail(rx_id)
            if not rx:
                self._send_json(404, {"error": "Prescription not found"})
                return
            role = session.get("role")
            if role == "doctor" and rx["doctor_username"] != session["username"]:
                self._send_json(403, {"error": "Access denied to another doctor's prescription"})
                return
            elif role == "patient":
                prof = self.db.get_patient_profile(session["username"])
                if not prof or (rx.get("patient_code") != prof["patient_code"] and rx.get("mobile") != prof["mobile"]):
                    self._send_json(403, {"error": "Access denied to this prescription"})
                    return
            elif role not in ("admin", "doctor", "patient"):
                self._send_json(403, {"error": "Access denied"})
                return
            body_html = f"""
              <h2 style="margin-top:0;color:#0d9488;">Digital Prescription (Rx)</h2>
              <p><strong>Appointment No:</strong> {html.escape(str(rx['appointment_number']))} · Date: {html.escape(str(rx['appointment_date']))}<br/>
              <strong>Patient:</strong> {html.escape(str(rx['first_name']))} {html.escape(str(rx['last_name']))} · Mobile: {html.escape(str(rx['mobile']))}<br/>
              <strong>Department / Doctor:</strong> {html.escape(str(rx['department']))}</p>
              <hr/>
              <p><strong>Diagnosis:</strong> {rx['diagnosis']}</p>
              <p><strong>Rx / Medicines:</strong> {rx['medicines_text']}</p>
              <p><strong>Advice:</strong> {rx['advice'] or 'Follow up as needed'}</p>
            """
            page = render_letterhead_html(f"Prescription {rx['appointment_number']}", body_html)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self._apply_security_headers(is_api=False)
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
            self.end_headers()
            self.wfile.write(page)
            return

        if path == "/api/admin/metrics":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "admin":
                self.db.log_audit(session["username"], "UNAUTHORIZED_METRICS_ACCESS", self._client_ip(), 403)
                self._send_json(403, {"error": "Admin privileges required"})
                return
            snap = self.server.metrics.snapshot()  # type: ignore[attr-defined]
            snap["background_jobs"] = self.db.get_job_stats()
            self._send_json(200, {"metrics": snap})
            return

        if path == "/api/admin/overview":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "admin":
                self.db.log_audit(session["username"], "UNAUTHORIZED_ADMIN_OVERVIEW", self._client_ip(), 403)
                self._send_json(403, {"error": "Admin privileges required"})
                return
            self._send_json(200, {"overview": self.db.get_admin_overview()})
            return

        if path in ("/admin", "/admin.html"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Admin authentication required to access /admin"})
                return
            if session.get("role") != "admin":
                self.db.log_audit(session["username"], "UNAUTHORIZED_ADMIN_PAGE_ACCESS", self._client_ip(), 403)
                self._send_json(403, {"error": "Forbidden: Only Hospital Administrators can access /admin"})
                return
            self._serve_static("admin.html", no_store=True)
            return

        if path == "/api/admin/audit":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "admin":
                self.db.log_audit(session["username"], "UNAUTHORIZED_ADMIN_ACCESS", self._client_ip(), 403)
                self._send_json(403, {"error": "Admin privileges required"})
                return
            logs = self.db.list_audit_logs(50)
            self._send_json(
                200,
                {
                    "audit_logs": logs,
                    "total_appointments": self.db.count_appointments(),
                },
            )
            return

        if path == "/robots.txt":
            txt = b"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /staff\nDisallow: /api/\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(txt)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self._apply_security_headers(is_api=False)
            self.end_headers()
            self.wfile.write(txt)
            return

        if path == "/sitemap.xml":
            xml = (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                b'<url><loc>/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>'
                b'</urlset>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(xml)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self._apply_security_headers(is_api=False)
            self.end_headers()
            self.wfile.write(xml)
            return

        if path in ("/staff", "/staff.html"):
            self._serve_static("staff.html", no_store=True)
            return

        if path.startswith("/assets/"):
            asset_name = path[len("/assets/"):]
            if asset_name not in ASSET_ALLOWLIST:
                self._send_json(404, {"error": "Not found"})
                return
            mime_type, compressible = ASSET_ALLOWLIST[asset_name]
            assets_root = os.path.realpath(os.path.join(PUBLIC_DIR, "assets"))
            target = os.path.realpath(os.path.join(assets_root, asset_name))
            if not target.startswith(assets_root + os.sep) or not os.path.isfile(target):
                self._send_json(404, {"error": "Not found"})
                return
            with open(target, "rb") as fh:
                raw_data = fh.read()
            etag = f'"{hashlib.sha256(raw_data).hexdigest()[:16]}"'
            if self.headers.get("If-None-Match", "").strip() == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
                self._apply_security_headers(is_api=False)
                self.end_headers()
                return
            use_gzip = compressible and "gzip" in self.headers.get("Accept-Encoding", "").lower() and len(raw_data) > 512
            payload_bytes = gzip.compress(raw_data, compresslevel=6) if use_gzip else raw_data
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            if use_gzip:
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(payload_bytes)))
            self._apply_security_headers(is_api=False)
            self.end_headers()
            self.wfile.write(payload_bytes)
            return

        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
            return

        if not path.startswith("/api/") and "text/html" in self.headers.get("Accept", "").lower():
            not_found_path = os.path.realpath(os.path.join(PUBLIC_DIR, "404.html"))
            if os.path.isfile(not_found_path):
                with open(not_found_path, "rb") as fh:
                    nf_bytes = fh.read()
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(nf_bytes)))
                self.send_header("Cache-Control", "no-store, private")
                self._apply_security_headers(is_api=False)
                self.end_headers()
                self.wfile.write(nf_bytes)
                return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/patients/register":
            if not self._check_rate_limit("login", self.cfg.rate_limit_login, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            raw_first = str(body.get("first_name", "")).strip()
            raw_last = str(body.get("last_name", "")).strip()
            raw_mobile = normalize_indian_mobile(str(body.get("mobile", "")))
            raw_pass = str(body.get("password", ""))
            if not NAME_RE.match(raw_first) or not NAME_RE.match(raw_last):
                self._send_json(400, {"error": "Please enter valid first and last names (letters only, 2-60 chars)."})
                return
            if not MOBILE_RE.match(raw_mobile):
                self._send_json(400, {"error": "Please enter a valid 10-digit Indian mobile number."})
                return
            if len(raw_pass) < 8 or not re.search(r"[A-Za-z]", raw_pass) or not re.search(r"\d", raw_pass):
                self._send_json(400, {"error": "Password must be at least 8 characters and include a letter and a number."})
                return
            created = self.db.register_patient(
                first_name=sanitize_text(raw_first, 60),
                last_name=sanitize_text(raw_last, 60),
                mobile=raw_mobile,
                password=raw_pass,
                email=sanitize_text(str(body.get("email", "")), 120),
                gender=sanitize_text(str(body.get("gender", "")), 20),
                blood_group=sanitize_text(str(body.get("blood_group", "")), 10),
                address=sanitize_text(str(body.get("address", "")), 200),
                emergency_contact_name=sanitize_text(str(body.get("emergency_contact_name", "")), 80),
                emergency_contact_phone=sanitize_text(str(body.get("emergency_contact_phone", "")), 20),
            )
            if not created:
                self._send_json(409, {"error": "An account with this mobile number already exists."})
                return
            self.db.log_audit(created["username"], f"PATIENT_REGISTER:{created['patient_code']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Patient registered", "patient": created})
            return

        if path == "/api/auth/login":
            if not self._check_rate_limit("login", self.cfg.rate_limit_login, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            username = str(body.get("username", "")).strip().lower()
            password = str(body.get("password", ""))
            now_m = time.monotonic()
            with self.server._login_lock:  # type: ignore[attr-defined]
                dq = self.server._login_failures[username]  # type: ignore[attr-defined]
                while dq and dq[0] <= now_m - 300.0:
                    dq.popleft()
                if len(dq) >= 5:
                    self.db.log_audit(username or "anonymous", "ACCOUNT_LOCKED_BRUTEFORCE", self._client_ip(), 429)
                    self._send_json(
                        429,
                        {"error": "Account temporarily locked due to too many failed login attempts. Try again in 5 minutes."},
                        extra_headers={"Retry-After": "300"},
                    )
                    return
            user = self.db.get_user_by_username(username)
            if not user or not verify_password(password, user["password_hash"]):
                with self.server._login_lock:  # type: ignore[attr-defined]
                    self.server._login_failures[username].append(now_m)  # type: ignore[attr-defined]
                self.db.log_audit(username or "anonymous", "LOGIN_FAILED", self._client_ip(), 401)
                self._send_json(401, {"error": "Invalid username or password"})
                return
            with self.server._login_lock:  # type: ignore[attr-defined]
                self.server._login_failures[username].clear()  # type: ignore[attr-defined]
            prev_cookie = self.headers.get("Cookie", "")
            if prev_cookie:
                prev_jar = cookies.SimpleCookie()
                try:
                    prev_jar.load(prev_cookie)
                    if "rmp_session" in prev_jar:
                        self.signer.revoke(prev_jar["rmp_session"].value)
                except Exception:
                    pass
            token = self.signer.sign(
                {
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                },
                ttl_seconds=3600,
            )
            verified = self.signer.verify(token)
            csrf_val = verified["csrf"] if verified else ""
            cookie_flags = "HttpOnly; SameSite=Strict; Path=/"
            if self.cfg.secure_cookies:
                cookie_flags += "; Secure"
            self.db.log_audit(user["username"], "LOGIN_SUCCESS", self._client_ip(), 200)
            self._send_json(
                200,
                {
                    "message": "Authenticated",
                    "user": {
                        "username": user["username"],
                        "full_name": user["full_name"],
                        "role": user["role"],
                    },
                    "csrf_token": csrf_val,
                },
                extra_headers={"Set-Cookie": f"rmp_session={token}; {cookie_flags}"},
            )
            return

        if path == "/api/auth/logout":
            raw_cookie = self.headers.get("Cookie", "")
            if raw_cookie:
                jar = cookies.SimpleCookie()
                try:
                    jar.load(raw_cookie)
                    if "rmp_session" in jar:
                        self.signer.revoke(jar["rmp_session"].value)
                except Exception:
                    pass
            self._send_json(
                200,
                {"message": "Logged out"},
                extra_headers={"Set-Cookie": "rmp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
            )
            return

        if path == "/api/appointments/check":
            if not self._check_rate_limit("appt_check", 15, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            raw_appt_no = str(body.get("appointment_number", "")).strip().upper()
            raw_mobile = normalize_indian_mobile(str(body.get("mobile", "")))
            if not re.fullmatch(r"[A-Z0-9-]{3,32}", raw_appt_no):
                self._send_json(400, {"error": "Please enter a valid Appointment Number (e.g. APT-20261128-001)."})
                return
            if not MOBILE_RE.match(raw_mobile):
                self._send_json(400, {"error": "Please enter the exact 10-digit registered mobile number."})
                return
            target_bucket = f"appt_target:{hashlib.sha256(raw_appt_no.encode('utf-8')).hexdigest()[:16]}"
            if not self._check_rate_limit(target_bucket, 12, 60.0):
                return
            found = self.db.lookup_appointment_status(raw_appt_no, raw_mobile)
            if not found:
                self.db.log_audit("public", "PUBLIC_APPT_CHECK:NOT_FOUND", self._client_ip(), 404)
                self._send_json(
                    404,
                    {"error": "No appointment found matching that Appointment Number and Mobile Number."},
                )
                return
            self.db.log_audit("public", f"PUBLIC_APPT_CHECK:FOUND:{found['appointment_number']}", self._client_ip(), 200)
            self._send_json(200, {"found": True, "appointment": found})
            return

        if path == "/api/appointments":
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return

            idem_raw = (self.headers.get("Idempotency-Key") or str(body.get("idempotency_key", ""))).strip()
            idem_cache_key = ""
            if idem_raw and re.fullmatch(r"[A-Za-z0-9._-]{8,80}", idem_raw):
                idem_cache_key = f"book:{self._client_ip()}:{idem_raw}"
                cached_booking = self.server.idempotency_cache.get(idem_cache_key)  # type: ignore[attr-defined]
                if cached_booking is not None:
                    self._send_json(200, cached_booking, extra_headers={"X-Idempotent-Replay": "true"})
                    return

            if not self._check_rate_limit("booking", self.cfg.rate_limit_booking, 60.0):
                return

            raw_first = str(body.get("first_name", "")).strip()
            raw_last = str(body.get("last_name", "")).strip()
            raw_mobile = normalize_indian_mobile(str(body.get("mobile", "")))
            department = str(body.get("department", "")).strip()
            raw_msg = str(body.get("message", ""))
            raw_date = str(body.get("appointment_date", "")).strip() or ist_today()

            if not NAME_RE.match(raw_first) or not NAME_RE.match(raw_last):
                self._send_json(400, {"error": "Please enter valid first and last names (letters only, 2-60 chars)."})
                return
            if not MOBILE_RE.match(raw_mobile):
                self._send_json(400, {"error": "Please enter a valid 10-digit Indian mobile number."})
                return
            if department not in DEPARTMENT_TO_DOCTOR:
                self._send_json(400, {"error": "Invalid department selected."})
                return
            valid_date = validate_date_str(raw_date)
            if not valid_date:
                self._send_json(400, {"error": "Please choose a valid appointment date (YYYY-MM-DD)."})
                return

            first_name = sanitize_text(raw_first, 60)
            last_name = sanitize_text(raw_last, 60)
            message = sanitize_text(raw_msg, 300)
            doctor_username = DEPARTMENT_TO_DOCTOR[department]

            session = self._get_session()
            linked_patient_code = None
            if session and session.get("role") == "patient":
                prof = self.db.get_patient_profile(session["username"])
                if prof:
                    linked_patient_code = prof["patient_code"]
            raw_slot = str(body.get("slot_time", "")).strip()
            if raw_slot and not TIME_RE.match(raw_slot):
                self._send_json(400, {"error": "Invalid time slot format (expected HH:MM)."})
                return
            try:
                record = self.db.create_appointment(
                    first_name=first_name,
                    last_name=last_name,
                    mobile=raw_mobile,
                    department=department,
                    doctor_username=doctor_username,
                    message=message,
                    appointment_date=valid_date,
                    patient_code=linked_patient_code,
                    slot_time=raw_slot,
                )
            except SlotConflictError as exc:
                self._send_json(409, {"error": str(exc)})
                return
            except SlotUnavailableError as exc:
                self._send_json(400, {"error": str(exc)})
                return

            payment_method = str(body.get("payment_method", "pay_at_hospital")).strip().lower()
            if payment_method not in ("pay_at_hospital", "online_razorpay"):
                self._send_json(400, {"error": "Invalid payment_method (choose pay_at_hospital or online_razorpay)."})
                return
            fee_inr = self.db.get_doctor_fee_inr(doctor_username)
            rzp_order_id = (
                self._create_razorpay_order(fee_inr, record["appointment_number"])
                if payment_method == "online_razorpay"
                else None
            )
            payment_rec = self.db.create_payment_record(
                appointment_id=int(record["id"]),
                appointment_number=record["appointment_number"],
                doctor_username=doctor_username,
                method=payment_method,
                provider_order_id=rzp_order_id,
            )

            # Automatic Confirmation Text Message (SMS) with Appointment Number
            sms_text = (
                f"Shri R.M. Patil Hospital, Chakur: Dear {first_name} {last_name}, "
                f"your appointment is booked! Appointment No: {record['appointment_number']} | "
                f"Date: {valid_date} | {department}. Helpline: 02381-299133."
            )
            delivery_status = self._dispatch_sms(raw_mobile, sms_text)
            sms_record = self.db.create_notification(
                appointment_id=int(record["id"]),
                appointment_number=record["appointment_number"],
                doctor_username=doctor_username,
                recipient_mobile=raw_mobile,
                notification_type="booking_confirmation",
                body=sms_text,
                delivery_status=delivery_status,
                sent_by="system",
            )
            self.db.log_audit(
                "public",
                f"BOOK_APPOINTMENT:{record['appointment_number']}",
                self._client_ip(),
                201,
            )
            booking_response = {
                "message": "Appointment confirmed & confirmation SMS processed",
                "appointment": {
                    "id": record["id"],
                    "appointment_number": record["appointment_number"],
                    "reference_code": record["reference_code"],
                    "appointment_date": record["appointment_date"],
                    "slot_time": record["slot_time"],
                    "department": record["department"],
                    "status": record["status"],
                    "qr_token": record["qr_token"],
                    "message": record["message"],
                },
                "payment": payment_rec,
                "confirmation_sms": {
                    "to": raw_mobile,
                    "status": sms_record["delivery_status"],
                    "text": sms_record["body"],
                },
            }
            if idem_cache_key:
                self.server.idempotency_cache.set(idem_cache_key, booking_response)  # type: ignore[attr-defined]
            self._send_json(201, booking_response)
            return

        # Doctor / Staff sends notification to a specific patient (strict ownership + CSRF + rate limit)
        # Option B: Online Payment Verification (HMAC-SHA256 signature verified server-side)
        if path == "/api/payments/online/verify":
            if not self._check_rate_limit("booking", self.cfg.rate_limit_booking, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            order_id = str(body.get("order_id", "")).strip()
            payment_id = str(body.get("payment_id", "")).strip()
            signature = str(body.get("signature", "")).strip()
            if not order_id or not payment_id or not signature:
                self._send_json(400, {"error": "order_id, payment_id, and signature are required."})
                return
            expected = hmac.new(
                self.cfg.razorpay_key_secret.encode("utf-8"),
                f"{order_id}|{payment_id}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                self.db.log_audit("public", f"PAYMENT_SIGNATURE_FAILED:{order_id}", self._client_ip(), 400)
                self._send_json(400, {"error": "Payment signature verification failed."})
                return
            paid = self.db.mark_payment_paid(
                provider_order_id=order_id,
                provider_payment_id=payment_id,
                collected_by="razorpay_verified",
            )
            if not paid:
                self._send_json(404, {"error": "Payment order not found."})
                return
            self.db.log_audit("public", f"PAYMENT_VERIFIED:{paid['receipt_number']}", self._client_ip(), 200)
            self._send_json(200, {"message": "Payment verified", "payment": paid})
            return

        # Razorpay Webhook with HMAC verification & duplicate event replay protection
        if path == "/api/payments/webhook":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "Invalid Content-Length"})
                return
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send_json(400, {"error": "Payload size out of bounds"})
                return
            raw_bytes = self.rfile.read(length)
            sig_hdr = self.headers.get("X-Razorpay-Signature", "").strip()
            expected_wh = hmac.new(
                self.cfg.razorpay_webhook_secret.encode("utf-8"),
                raw_bytes,
                hashlib.sha256,
            ).hexdigest()
            if not sig_hdr or not hmac.compare_digest(expected_wh, sig_hdr):
                self._send_json(400, {"error": "Invalid webhook signature"})
                return
            try:
                wh = json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Malformed webhook JSON"})
                return
            pay_entity = ((wh.get("payload") or {}).get("payment") or {}).get("entity") or {}
            event_id = str(self.headers.get("X-Razorpay-Event-Id") or wh.get("event_id") or "").strip()
            order_id = str(pay_entity.get("order_id") or wh.get("order_id") or "").strip()
            payment_id = str(pay_entity.get("id") or wh.get("payment_id") or "").strip()
            if not event_id or not order_id:
                self._send_json(400, {"error": "Missing event_id or order_id"})
                return
            is_new = self.db.record_webhook_event(event_id, order_id)
            if not is_new:
                self._send_json(200, {"message": "Duplicate webhook ignored", "duplicate": True})
                return
            paid = self.db.mark_payment_paid(
                provider_order_id=order_id,
                provider_payment_id=payment_id or f"wh_{event_id}",
                collected_by="razorpay_webhook",
            )
            self._send_json(200, {"message": "Webhook processed", "duplicate": False, "payment": paid})
            return

        # Option A: Receptionist/Admin collects Pay-at-Hospital payment
        if path.startswith("/api/staff/payments/") and path.endswith("/collect"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("admin", "receptionist", "billing"):
                self.db.log_audit(session["username"], "UNAUTHORIZED_PAYMENT_COLLECT", self._client_ip(), 403)
                self._send_json(403, {"error": "Only receptionists or admins can collect payments"})
                return
            parts = path.strip("/").split("/")
            if len(parts) != 5:
                self._send_json(400, {"error": "Invalid payment route"})
                return
            try:
                appt_id = int(parts[3])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            paid = self.db.mark_payment_paid(appointment_id=appt_id, collected_by=session["username"])
            if not paid:
                self._send_json(404, {"error": "Payment record not found"})
                return
            self.db.log_audit(session["username"], f"PAYMENT_COLLECTED:{paid['receipt_number']}", self._client_ip(), 200)
            self._send_json(200, {"message": "Payment collected", "payment": paid})
            return

        # Reception QR Code Scan & Queue Token Check-In (opaque non-sensitive token)
        if path == "/api/staff/checkin/scan":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("admin", "receptionist"):
                self._send_json(403, {"error": "Only receptionists or admins can perform QR check-in"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            qr_token = str(body.get("qr_token", "")).strip()
            if not qr_token.startswith("QR-"):
                self._send_json(400, {"error": "Invalid QR token format"})
                return
            checked = self.db.checkin_by_qr_token(qr_token)
            if not checked:
                self._send_json(404, {"error": "Appointment QR token not found"})
                return
            self.db.log_audit(session["username"], f"QR_CHECKIN:{checked['appointment_number']}:{checked['queue_token']}", self._client_ip(), 200)
            self._send_json(200, {"message": "Patient checked in", "checkin": checked})
            return

        # Patient Cancel & Reschedule Appointment (releases/locks slot atomically)
        if path.startswith("/api/patient/appointments/") and (path.endswith("/cancel") or path.endswith("/reschedule")):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            parts = path.strip("/").split("/")
            if len(parts) != 5:
                self._send_json(400, {"error": "Invalid patient appointment route"})
                return
            try:
                appt_id = int(parts[3])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            action = parts[4]
            if action == "cancel":
                ok = self.db.cancel_patient_appointment(appt_id, prof["patient_code"], prof["mobile"])
                if not ok:
                    self._send_json(403, {"error": "Appointment not found, already completed, or not yours"})
                    return
                self.db.log_audit(session["username"], f"PATIENT_CANCEL:{appt_id}", self._client_ip(), 200)
                self._send_json(200, {"message": "Appointment cancelled and time slot released", "id": appt_id})
                return
            else:
                body, err = self._read_json_body()
                if err or body is None:
                    self._send_json(400, {"error": err or "Bad request"})
                    return
                new_date = validate_date_str(str(body.get("appointment_date", "")).strip())
                new_slot = str(body.get("slot_time", "")).strip()
                if not new_date or not TIME_RE.match(new_slot):
                    self._send_json(400, {"error": "Valid appointment_date (YYYY-MM-DD) and slot_time (HH:MM) required."})
                    return
                try:
                    updated = self.db.reschedule_patient_appointment(
                        appt_id, prof["patient_code"], prof["mobile"], new_date, new_slot
                    )
                except SlotConflictError as exc:
                    self._send_json(409, {"error": str(exc)})
                    return
                except SlotUnavailableError as exc:
                    self._send_json(400, {"error": str(exc)})
                    return
                if not updated:
                    self._send_json(403, {"error": "Appointment not found or cannot be rescheduled"})
                    return
                self.db.log_audit(session["username"], f"PATIENT_RESCHEDULE:{appt_id}:{new_date}:{new_slot}", self._client_ip(), 200)
                self._send_json(200, {"message": "Appointment rescheduled", "appointment": updated})
                return

        # Doctor-only Digital Prescription & Diagnosis (Receptionist strictly blocked -> 403!)
        if path == "/api/doctor/prescriptions":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") != "doctor":
                self.db.log_audit(session["username"], "UNAUTHORIZED_DIAGNOSIS_WRITE", self._client_ip(), 403)
                self._send_json(403, {"error": "Only the assigned doctor can author diagnoses and prescriptions"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            try:
                appt_id = int(body.get("appointment_id", 0))
            except ValueError:
                self._send_json(400, {"error": "Valid appointment_id required"})
                return
            diagnosis = sanitize_text(str(body.get("diagnosis", "")), 300)
            medicines = sanitize_text(str(body.get("medicines_text", "")), 500)
            advice = sanitize_text(str(body.get("advice", "")), 300)
            follow_up = str(body.get("follow_up_date", "")).strip()
            if not diagnosis or not medicines:
                self._send_json(400, {"error": "Diagnosis and medicines_text are required."})
                return
            rx = self.db.create_prescription(appt_id, session["username"], diagnosis, medicines, advice, follow_up)
            if not rx:
                self._send_json(403, {"error": "Appointment not found or not assigned to you"})
                return
            self.db.log_audit(session["username"], f"CREATE_PRESCRIPTION:{appt_id}", self._client_ip(), 201)
            self._send_json(201, {"message": "Prescription saved", "prescription": rx})
            return

        # Pharmacy Dispense (Shiv Medical Stores — Pharmacist/Admin only)
        if path == "/api/pharmacy/dispense":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self._send_json(403, {"error": "Pharmacist or Admin access required"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            med_code = str(body.get("medicine_code", "")).strip().upper()
            try:
                qty = int(body.get("quantity", 0))
            except ValueError:
                qty = 0
            if not med_code or qty <= 0 or qty > 100:
                self._send_json(400, {"error": "Valid medicine_code and quantity (1-100) required."})
                return
            disp = self.db.dispense_medicine(med_code, qty)
            if not disp:
                self._send_json(400, {"error": "Medicine not found or insufficient stock."})
                return
            self.db.log_audit(session["username"], f"PHARMACY_DISPENSE:{med_code}:{qty}", self._client_ip(), 200)
            self._send_json(200, {"message": "Medicine dispensed", "dispense": disp})
            return

        # Laboratory Test Order (Doctor/Admin)
        if path == "/api/lab/tests":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("doctor", "admin"):
                self._send_json(403, {"error": "Doctor or Admin access required to order lab tests"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            try:
                appt_id = int(body.get("appointment_id", 0))
                price_inr = int(body.get("price_inr", 350))
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment_id or price_inr"})
                return
            test_name = sanitize_text(str(body.get("test_name", "")), 120)
            category = sanitize_text(str(body.get("category", "Pathology")), 60)
            if not test_name or price_inr < 0 or price_inr > 100000:
                self._send_json(400, {"error": "Valid test_name and price_inr (0-100000) required."})
                return
            is_doc = session.get("role") == "doctor"
            rec = self.db.create_lab_test(appt_id, session["username"], test_name, category, price_inr, enforce_owner=is_doc)
            if not rec:
                self._send_json(403 if is_doc else 404, {"error": "Appointment not found or not assigned to you"})
                return
            self.db.log_audit(session["username"], f"LAB_ORDER:{rec['test_code']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Lab test ordered", "lab_test": rec})
            return

        # Unified Billing Invoice Generation (Receptionist/Admin)
        if path == "/api/billing/invoices":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("billing", "receptionist", "admin"):
                self._send_json(403, {"error": "Billing, Receptionist, or Admin access required"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            try:
                appt_id = int(body.get("appointment_id", 0))
                pharmacy_inr = int(body.get("pharmacy_inr", 0))
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment_id or pharmacy_inr"})
                return
            inv = self.db.generate_unified_invoice(appt_id, pharmacy_inr=pharmacy_inr)
            if not inv:
                self._send_json(404, {"error": "Appointment not found"})
                return
            self.db.log_audit(session["username"], f"INVOICE_CREATED:{inv['invoice_number']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Invoice generated", "invoice": inv})
            return

        # DPDP Patient Consent Grant / Withdrawal (Patient-only + CSRF)
        if path == "/api/patient/consent":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            purpose = sanitize_text(str(body.get("purpose", "")), 80)
            granted = bool(body.get("granted", False))
            if not purpose:
                self._send_json(400, {"error": "Consent purpose is required."})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            rec = self.db.set_patient_consent(prof["patient_code"], purpose, granted)
            self.db.log_audit(prof["patient_code"], f"CONSENT:{'GRANT' if granted else 'WITHDRAW'}:{purpose}", self._client_ip(), 200)
            self._send_json(200, {"message": "Consent preference saved", "consent": rec})
            return

        # DPDP Patient Data Access / Correction / Erasure Request (Patient-only + CSRF)
        if path == "/api/patient/privacy-requests":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            req_type = str(body.get("request_type", "")).strip().lower()
            details = sanitize_text(str(body.get("details", "")), 400)
            if req_type not in ("access", "correction", "erasure", "consent_withdrawal"):
                self._send_json(400, {"error": "Invalid request_type (access, correction, erasure, consent_withdrawal)."})
                return
            prof = self.db.get_patient_profile(session["username"])
            if not prof:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            rec = self.db.create_privacy_request(prof["patient_code"], req_type, details)
            self.db.log_audit(prof["patient_code"], f"PRIVACY_REQUEST:{rec['request_code']}:{req_type}", self._client_ip(), 201)
            self._send_json(201, {"message": "Privacy request recorded", "privacy_request": rec})
            return

        # Refund Workflow (Strictly Billing Officer or Admin + CSRF; blocks double-refunds with 409)
        if path == "/api/billing/refunds":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("billing", "admin"):
                self.db.log_audit(session["username"], "UNAUTHORIZED_REFUND_ATTEMPT", self._client_ip(), 403)
                self._send_json(403, {"error": "Only Billing Officers or Administrators can process refunds"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            try:
                appt_id = int(body.get("appointment_id", 0))
            except ValueError:
                self._send_json(400, {"error": "Valid appointment_id required"})
                return
            reason = sanitize_text(str(body.get("reason", "")), 200)
            if not reason:
                self._send_json(400, {"error": "Refund reason is required."})
                return
            rec, r_err = self.db.process_refund(appt_id, reason, session["username"])
            if r_err == "not_found":
                self._send_json(404, {"error": "Payment record not found"})
                return
            if r_err == "already_refunded":
                self._send_json(409, {"error": "Payment has already been refunded"})
                return
            if r_err == "not_paid":
                self._send_json(400, {"error": "Only PAID payments can be refunded"})
                return
            self.db.log_audit(session["username"], f"REFUND_PROCESSED:{rec['refund_code']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Refund processed", "refund": rec})
            return

        # Save/Update User Gmail & Phone for Password Recovery (Authenticated + CSRF)
        if path == "/api/auth/contact-info":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            email = str(body.get("email", "")).strip().lower()
            phone = re.sub(r"[\s-]", "", str(body.get("phone", "")).strip())
            if email and not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
                self._send_json(400, {"error": "Please enter a valid email address (e.g. name@gmail.com)."})
                return
            if phone and not MOBILE_RE.match(phone):
                self._send_json(400, {"error": "Please enter a valid 10-digit Indian mobile number."})
                return
            if not email and not phone:
                self._send_json(400, {"error": "Provide at least a Gmail/email or 10-digit phone number."})
                return
            self.db.update_user_recovery_contact(session["username"], sanitize_text(email, 120), phone)
            self.db.log_audit(session["username"], "UPDATE_RECOVERY_CONTACT", self._client_ip(), 200)
            self._send_json(200, {"message": "Recovery email and phone saved"})
            return

        # Forgot Password (Rate-limited; verifies registered Gmail or phone; never leaks account existence or OTP)
        if path == "/api/auth/forgot-password":
            if not self._check_rate_limit("login", self.cfg.rate_limit_login, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            username = str(body.get("username", "")).strip().lower()
            email = str(body.get("email", "")).strip().lower()
            phone = re.sub(r"[\s-]", "", str(body.get("phone", "")).strip())
            if not username or (not email and not phone):
                self._send_json(400, {"error": "Username and registered Gmail or phone number are required."})
                return
            code = self.db.create_password_reset_code(username, email=email, phone=phone)
            if code:
                if phone:
                    self._dispatch_sms(phone, f"Shri R.M. Patil Hospital password reset OTP: {code} (valid 10 min).")
                self.db.log_audit(username, "PASSWORD_RESET_REQUESTED", self._client_ip(), 200)
            self._send_json(200, {"message": "If the username and recovery email/phone match, a 6-digit reset code has been dispatched."})
            return

        # Reset Password with 6-Digit Recovery Code (Single-use, 10-min expiry, scrypt hashed)
        if path == "/api/auth/reset-password":
            if not self._check_rate_limit("login", self.cfg.rate_limit_login, 60.0):
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            username = str(body.get("username", "")).strip().lower()
            code = str(body.get("code", "")).strip()
            new_pw = str(body.get("new_password", ""))
            if not username or not re.match(r"^\d{6}$", code):
                self._send_json(400, {"error": "Valid username and 6-digit recovery code required."})
                return
            if len(new_pw) < 8 or not re.search(r"[A-Za-z]", new_pw) or not re.search(r"\d", new_pw):
                self._send_json(400, {"error": "New password must be 8+ characters with a letter and a number."})
                return
            ok = self.db.reset_password_with_code(username, code, new_pw)
            if not ok:
                self.db.log_audit(username, "PASSWORD_RESET_FAILED", self._client_ip(), 400)
                self._send_json(400, {"error": "Invalid or expired recovery code."})
                return
            with self.server._login_lock:  # type: ignore[attr-defined]
                self.server._login_failures[username].clear()  # type: ignore[attr-defined]
            self.db.log_audit(username, "PASSWORD_RESET_SUCCESS", self._client_ip(), 200)
            self._send_json(200, {"message": "Password updated successfully. Please sign in with your new password."})
            return

        # Shared Ward Nurse Notifications (Nurse, Doctor, Admin ONLY)
        if path == "/api/nurse/notifications":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("nurse", "doctor", "admin"):
                self._send_json(403, {"error": "Nurse, Doctor, or Admin access required"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            title = sanitize_text(str(body.get("title", "")), 100)
            msg = sanitize_text(str(body.get("message", "")), 300)
            appt_no = sanitize_text(str(body.get("appointment_number", "")), 40)
            priority = str(body.get("priority", "normal")).strip().lower()
            if priority not in ("normal", "urgent"):
                priority = "normal"
            if not title or not msg:
                self._send_json(400, {"error": "Notification title and message are required."})
                return
            rec = self.db.create_nurse_notification(title, msg, session["username"], appt_no, priority)
            self.db.log_audit(session["username"], f"NURSE_ALERT:{priority}", self._client_ip(), 201)
            self._send_json(201, {"message": "Nurse ward notification posted", "notification": rec})
            return

        # Separate Shiv Medical Stores Purchases (Pharmacist & Admin ONLY — isolated from hospital billing_desk!)
        if path == "/api/pharmacy/purchases":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self.db.log_audit(session["username"], "UNAUTHORIZED_PHARMACY_PURCHASE", self._client_ip(), 403)
                self._send_json(403, {"error": "Shiv Medical Stores Pharmacist or Admin access required"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            med_code = str(body.get("medicine_code", "")).strip().upper()
            supplier = sanitize_text(str(body.get("supplier_name", "")), 100)
            try:
                qty = int(body.get("quantity", 0))
                unit_cost = int(body.get("unit_cost_inr", 0))
            except (ValueError, TypeError):
                qty, unit_cost = 0, -1
            if not med_code or not supplier or qty <= 0 or unit_cost < 0:
                self._send_json(400, {"error": "Valid medicine_code, supplier_name, quantity, and unit_cost_inr required."})
                return
            rec = self.db.record_pharmacy_purchase(med_code, supplier, qty, unit_cost, session["username"])
            if not rec:
                self._send_json(404, {"error": "Medicine code not found in inventory"})
                return
            self.db.log_audit(session["username"], f"PHARMACY_PURCHASE:{rec['purchase_code']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Purchase recorded and stock updated", "purchase": rec})
            return

        # Separate Shiv Medical Stores Billing (Pharmacist & Admin ONLY — isolated from hospital billing_desk!)
        if path == "/api/pharmacy/bills":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("pharmacist", "admin"):
                self.db.log_audit(session["username"], "UNAUTHORIZED_PHARMACY_BILL", self._client_ip(), 403)
                self._send_json(403, {"error": "Only Shiv Medical Stores Pharmacist or Admin can issue pharmacy bills"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            p_name = sanitize_text(str(body.get("patient_name", "")), 80)
            p_mob = re.sub(r"[\s-]", "", str(body.get("patient_mobile", "")).strip())
            items = body.get("items")
            pay_m = str(body.get("payment_method", "cash")).strip().lower()
            if not p_name or not isinstance(items, list) or not items or pay_m not in ("cash", "upi", "card"):
                self._send_json(400, {"error": "Valid patient_name, items list, and payment_method (cash/upi/card) required."})
                return
            bill, b_err = self.db.create_pharmacy_bill(p_name, p_mob, items, pay_m, session["username"])
            if b_err or not bill:
                self._send_json(400, {"error": b_err or "Could not create pharmacy bill"})
                return
            self.db.log_audit(session["username"], f"PHARMACY_BILL:{bill['bill_number']}", self._client_ip(), 201)
            self._send_json(201, {"message": "Shiv Medical Stores bill created", "bill": bill})
            return

        # Dynamic Lab Test Catalog Addition (Lab Tech & Admin ONLY)
        if path == "/api/lab/catalog":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("lab_tech", "admin"):
                self.db.log_audit(session["username"], "UNAUTHORIZED_LAB_CATALOG_ADD", self._client_ip(), 403)
                self._send_json(403, {"error": "Only Lab Technician or Admin can add new lab tests"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            cat_code = re.sub(r"[^A-Za-z0-9_-]", "", str(body.get("catalog_code", "")).strip().upper())[:24]
            test_name = sanitize_text(str(body.get("test_name", "")), 120)
            category = sanitize_text(str(body.get("category", "Pathology")), 60)
            try:
                price = int(body.get("default_price_inr", 0))
            except (ValueError, TypeError):
                price = -1
            if not cat_code or not test_name or price < 0 or price > 100000:
                self._send_json(400, {"error": "Valid catalog_code, test_name, and default_price_inr (0-100000) required."})
                return
            added = self.db.add_lab_catalog_item(cat_code, test_name, category, price, session["username"])
            if not added:
                self._send_json(409, {"error": "Lab test code or name already exists in catalog."})
                return
            self.db.log_audit(session["username"], f"LAB_CATALOG_ADD:{cat_code}", self._client_ip(), 201)
            self._send_json(201, {"message": "New lab test added to catalog", "item": added})
            return

        if path == "/api/staff/holidays":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            role = session.get("role")
            if role not in ("admin", "doctor"):
                self._send_json(403, {"error": "Only doctors or admins can manage leave/holidays"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            target_doc = session["username"] if role == "doctor" else str(body.get("doctor_username", "")).strip().lower()
            h_date = validate_date_str(str(body.get("holiday_date", "")).strip())
            reason = sanitize_text(str(body.get("reason", "Doctor on leave")), 120) or "Doctor on leave"
            if not target_doc or not h_date:
                self._send_json(400, {"error": "Valid doctor_username and holiday_date (YYYY-MM-DD) required."})
                return
            rec = self.db.add_doctor_holiday(target_doc, h_date, reason)
            self.db.log_audit(session["username"], f"ADD_HOLIDAY:{target_doc}:{h_date}", self._client_ip(), 201)
            self._send_json(201, {"message": "Holiday saved", "holiday": rec})
            return

        if path.startswith("/api/staff/appointments/") and path.endswith("/notify"):
            if not self._check_rate_limit("notify", self.cfg.rate_limit_notify, 60.0):
                return
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            parts = path.strip("/").split("/")
            # Expected: ['api', 'staff', 'appointments', '<id>', 'notify']
            if len(parts) != 5:
                self._send_json(400, {"error": "Invalid notification route"})
                return
            try:
                appt_id = int(parts[3])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            raw_note = str(body.get("message", "")).strip()
            if len(raw_note) < 3 or len(raw_note) > 260:
                self._send_json(400, {"error": "Notification message must be 3 to 260 characters."})
                return

            role = session.get("role")
            if role not in ("admin", "doctor", "receptionist"):
                self.db.log_audit(session["username"], f"UNAUTHORIZED_STAFF_NOTIFY:{appt_id}", self._client_ip(), 403)
                self._send_json(403, {"error": "Staff authorization required"})
                return
            doctor_scope = session["username"] if role == "doctor" else None
            appt = self.db.get_appointment_by_id(appt_id, doctor_username=doctor_scope)
            if not appt:
                self.db.log_audit(
                    session["username"],
                    f"BLOCKED_CROSS_DOCTOR_NOTIFY:{appt_id}",
                    self._client_ip(),
                    403,
                )
                self._send_json(403, {"error": "Appointment not found or not assigned to you"})
                return

            clean_note = sanitize_text(raw_note, 260)
            sms_body = (
                f"Shri R.M. Patil Hospital ({session['full_name']}) — "
                f"Appt {appt['appointment_number']}: {clean_note}"
            )
            delivery_status = self._dispatch_sms(appt["mobile"], sms_body)
            note_rec = self.db.create_notification(
                appointment_id=int(appt["id"]),
                appointment_number=appt["appointment_number"],
                doctor_username=appt["doctor_username"],
                recipient_mobile=appt["mobile"],
                notification_type="doctor_notification",
                body=sms_body,
                delivery_status=delivery_status,
                sent_by=session["username"],
            )
            self.db.log_audit(
                session["username"],
                f"SEND_NOTIFICATION:{appt['appointment_number']}",
                self._client_ip(),
                201,
            )
            self._send_json(201, {"message": "Notification sent", "notification": note_rec})
            return

        self._send_json(404, {"error": "Not found"})

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._check_rate_limit("public", self.cfg.rate_limit_public, 60.0):
            return

        if path.startswith("/api/lab/tests/"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            if session.get("role") not in ("lab_tech", "admin"):
                self._send_json(403, {"error": "Laboratory Technician or Admin access required"})
                return
            try:
                test_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json(400, {"error": "Invalid test ID"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            sample_status = str(body.get("sample_status", "completed")).strip().lower()
            if sample_status not in ("ordered", "collected", "completed"):
                self._send_json(400, {"error": "Invalid sample_status"})
                return
            result_summary = sanitize_text(str(body.get("result_summary", "")), 400)
            updated = self.db.update_lab_result(test_id, sample_status, result_summary)
            if not updated:
                self._send_json(404, {"error": "Lab test not found"})
                return
            self.db.log_audit(session["username"], f"LAB_RESULT:{test_id}:{sample_status}", self._client_ip(), 200)
            self._send_json(200, {"message": "Lab test updated", "lab_test": updated})
            return

        if path == "/api/patient/me":
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            if session.get("role") != "patient":
                self._send_json(403, {"error": "Patient account required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            ok = self.db.update_patient_profile(
                username=session["username"],
                email=sanitize_text(str(body.get("email", "")), 120),
                address=sanitize_text(str(body.get("address", "")), 200),
                blood_group=sanitize_text(str(body.get("blood_group", "")), 10),
                emergency_contact_name=sanitize_text(str(body.get("emergency_contact_name", "")), 80),
                emergency_contact_phone=sanitize_text(str(body.get("emergency_contact_phone", "")), 20),
            )
            if not ok:
                self._send_json(404, {"error": "Patient profile not found"})
                return
            self.db.log_audit(session["username"], "PATIENT_PROFILE_UPDATE", self._client_ip(), 200)
            self._send_json(200, {"message": "Profile updated"})
            return

        if path.startswith("/api/staff/appointments/"):
            session = self._get_session()
            if not session:
                self._send_json(401, {"error": "Authentication required"})
                return
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf_hdr, session.get("csrf", "")):
                self._send_json(403, {"error": "Invalid CSRF token"})
                return
            try:
                appt_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json(400, {"error": "Invalid appointment ID"})
                return
            body, err = self._read_json_body()
            if err or body is None:
                self._send_json(400, {"error": err or "Bad request"})
                return
            new_status = str(body.get("status", "")).strip().lower()
            if new_status not in ALLOWED_STATUSES:
                self._send_json(400, {"error": "Invalid appointment status"})
                return

            role = session.get("role")
            if role not in ("admin", "doctor", "receptionist"):
                self.db.log_audit(session["username"], f"UNAUTHORIZED_STAFF_APPT_PATCH:{appt_id}", self._client_ip(), 403)
                self._send_json(403, {"error": "Staff authorization required"})
                return
            doctor_scope = session["username"] if role == "doctor" else None
            updated = self.db.update_appointment_status(appt_id, new_status, doctor_username=doctor_scope)
            if not updated:
                self._send_json(404, {"error": "Appointment not found or access denied"})
                return
            self.db.log_audit(session["username"], f"UPDATE_APPT:{appt_id}:{new_status}", self._client_ip(), 200)
            self._send_json(200, {"message": "Appointment updated", "id": appt_id, "status": new_status})
            return

        self._send_json(404, {"error": "Not found"})

    def _serve_static(self, filename: str, no_store: bool = False) -> None:
        if filename not in STATIC_ALLOWLIST:
            self._send_json(404, {"error": "Not found"})
            return
        target = os.path.realpath(os.path.join(PUBLIC_DIR, filename))
        if not target.startswith(os.path.realpath(PUBLIC_DIR) + os.sep) or not os.path.isfile(target):
            self._send_json(404, {"error": "Not found"})
            return
        with open(target, "rb") as fh:
            raw_data = fh.read()

        etag = f'"{hashlib.sha256(raw_data).hexdigest()[:16]}"'
        if not no_store and self.headers.get("If-None-Match", "").strip() == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
            self._apply_security_headers(is_api=False)
            self.end_headers()
            return

        use_gzip = "gzip" in self.headers.get("Accept-Encoding", "").lower() and len(raw_data) > 1024
        data = gzip.compress(raw_data, compresslevel=5) if use_gzip else raw_data
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(data)))
        self._apply_security_headers(is_api=False)
        if no_store:
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
        else:
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
        self.end_headers()
        self.wfile.write(data)


def create_server(config: Optional[AppConfig] = None) -> HospitalServer:
    cfg = config or AppConfig()
    db = HospitalDB(cfg.db_path)
    db.seed_default_staff(cfg.staff_passwords)
    return HospitalServer((cfg.host, cfg.port), HospitalRequestHandler, cfg, db)


if __name__ == "__main__":
    srv = create_server()
    print(f"Shri R.M. Patil Hospital Server listening on http://{srv.config.host}:{srv.config.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
