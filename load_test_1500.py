"""
Multi-Level Concurrency & Load Benchmark (100, 500, 1,000, 1,500 simulated users)
for Shri R.M. Patil Multi Speciality Hospital.

Tests browsing reads SEPARATELY from simultaneous appointment bookings & same-slot conflicts.
Uses synthetic data and an isolated temporary SQLite WAL database.
Reports actual measured p50/p95/p99, avg latency, req/s, error %, RAM (MB), and DB integrity.
"""

import concurrent.futures
import ctypes
import http.client
import json
import os
import statistics
import tempfile
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

try:
    import resource  # type: ignore[import-not-found]
except ImportError:
    resource = None  # Windows fallback below

from migrations import IST
from server import AppConfig, create_server


def _get_peak_rss_mb() -> float:
    if resource is not None:
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)
    try:
        from ctypes import wintypes

        class _PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        get_mem = getattr(k32, "K32GetProcessMemoryInfo", None)
        if get_mem is None:
            get_mem = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        get_mem.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
        get_mem.restype = wintypes.BOOL
        pmc = _PMC()
        pmc.cb = ctypes.sizeof(_PMC)
        if get_mem(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            return round(pmc.PeakWorkingSetSize / (1024.0 * 1024.0), 2)
    except Exception:
        pass
    return 0.0


def _req(port: int, method: str, path: str, body: Dict[str, Any] | None = None) -> Tuple[int, float]:
    t0 = time.perf_counter()
    raw = json.dumps(body).encode("utf-8") if body is not None else None
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    headers = {"Connection": "close", "Accept-Encoding": "gzip"}
    if raw is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        resp.read()
        st = resp.status
    except Exception:
        st = 599
    finally:
        conn.close()
    return st, (time.perf_counter() - t0) * 1000.0


def _stats(statuses: List[int], latencies: List[float], elapsed: float) -> Dict[str, Any]:
    s_lat = sorted(latencies)
    n = len(s_lat)
    err_5xx = sum(1 for c in statuses if c >= 500)
    return {
        "requests": n,
        "rps": round(n / max(elapsed, 0.001), 1),
        "avg_ms": round(sum(s_lat) / max(n, 1), 2),
        "p50_ms": round(statistics.median(s_lat), 2) if n else 0.0,
        "p95_ms": round(s_lat[min(n - 1, int(0.95 * n))], 2) if n else 0.0,
        "p99_ms": round(s_lat[min(n - 1, int(0.99 * n))], 2) if n else 0.0,
        "ok_2xx": sum(1 for c in statuses if 200 <= c < 300),
        "conflict_409": statuses.count(409),
        "error_5xx": err_5xx,
        "error_rate_pct": round((err_5xx / max(n, 1)) * 100.0, 2),
    }


def run_load_suite() -> Dict[str, Any]:
    d = datetime.now(IST) + timedelta(days=1)
    while d.weekday() == 6:
        d += timedelta(days=1)
    workday = d.strftime("%Y-%m-%d")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        cfg = AppConfig()
        cfg.host = "127.0.0.1"
        cfg.port = 0
        cfg.debug = False
        cfg.db_path = os.path.join(tmpdir, "load_hospital.db")
        # Raise per-IP limiter since all simulated users share 127.0.0.1 in local benchmark
        cfg.rate_limit_public = 50000
        cfg.rate_limit_booking = 50000

        srv = create_server(cfg)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            # 1. Public Browsing Read Benchmarks at 100, 250, 500, 750, 1,000, 1,250, and 1,500 concurrent requests
            browsing_levels: Dict[str, Any] = {}
            for level in (100, 250, 500, 750, 1000, 1250, 1500):
                statuses: List[int] = []
                latencies: List[float] = []
                t0 = time.perf_counter()
                # Cap client thread pool at 150 to avoid OS client-side ephemeral port exhaustion while queuing full wave
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(level, 150)) as pool:
                    paths = ["/api/public/info", "/api/health", f"/api/doctors/dr_rohan/slots?date={workday}", "/"]
                    futs = [pool.submit(_req, port, "GET", paths[i % len(paths)]) for i in range(level)]
                    for f in concurrent.futures.as_completed(futs):
                        st, ms = f.result()
                        statuses.append(st)
                        latencies.append(ms)
                browsing_levels[f"{level}_users"] = _stats(statuses, latencies, time.perf_counter() - t0)

            # 2. Simultaneous Write & Slot-Conflict Test (100 concurrent bookings: 50 distinct + 50 racing same slot)
            w_statuses: List[int] = []
            w_latencies: List[float] = []
            depts = [
                "Orthopaedics — Dr. Rohan Patil",
                "Obstetrics & Gynaecology — Dr. Rahul Patil",
                "Dental Surgery — Dr. Manjusha Patil",
                "General Medicine — Dr. Snehal Patil",
            ]
            t0 = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
                futs = []
                # 50 distinct callback bookings
                for i in range(50):
                    futs.append(
                        pool.submit(
                            _req,
                            port,
                            "POST",
                            "/api/appointments",
                            {
                                "first_name": f"Load{chr(65 + (i % 26))}",
                                "last_name": "Patient",
                                "mobile": f"981000{i:04d}",
                                "department": depts[i % 4],
                                "appointment_date": workday,
                                "message": f"Synthetic load booking {i}",
                            },
                        )
                    )
                # 50 simultaneous bookings racing for the EXACT same doctor & slot (09:30)
                for i in range(50):
                    futs.append(
                        pool.submit(
                            _req,
                            port,
                            "POST",
                            "/api/appointments",
                            {
                                "first_name": f"Race{chr(65 + (i % 26))}",
                                "last_name": "Conflict",
                                "mobile": f"982000{i:04d}",
                                "department": "Orthopaedics — Dr. Rohan Patil",
                                "appointment_date": workday,
                                "slot_time": "09:30",
                            },
                        )
                    )
                for f in concurrent.futures.as_completed(futs):
                    st, ms = f.result()
                    w_statuses.append(st)
                    w_latencies.append(ms)
            write_stats = _stats(w_statuses, w_latencies, time.perf_counter() - t0)
            db_rows = srv.db.count_appointments()
            metrics = srv.metrics.snapshot()
            rss_mb = _get_peak_rss_mb()

            # 3. Simultaneous Patient Registration Test (30 concurrent registrations: 25 unique + 5 duplicate mobile race)
            cfg.rate_limit_login = 50000
            reg_statuses: List[int] = []
            reg_latencies: List[float] = []
            t_reg = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
                futs = []
                for i in range(25):
                    futs.append(pool.submit(_req, port, "POST", "/api/patients/register", {
                        "first_name": f"Reg{chr(65 + (i % 26))}",
                        "last_name": "Load",
                        "mobile": f"970000{i:04d}",
                        "password": "Patient#2026",
                    }))
                for i in range(5):
                    futs.append(pool.submit(_req, port, "POST", "/api/patients/register", {
                        "first_name": "Dup",
                        "last_name": "Race",
                        "mobile": "9799999999",
                        "password": "Patient#2026",
                    }))
                for f in concurrent.futures.as_completed(futs):
                    st, ms = f.result()
                    reg_statuses.append(st)
                    reg_latencies.append(ms)
            reg_stats = _stats(reg_statuses, reg_latencies, time.perf_counter() - t_reg)

            import sqlite3
            chk_conn = sqlite3.connect(cfg.db_path)
            integrity = chk_conn.execute("PRAGMA integrity_check;").fetchone()[0]
            chk_conn.close()

            return {
                "sqlite_integrity_check": integrity,
                "concurrent_patient_reg_30": {
                    **reg_stats,
                    "expected_created_201": 26,
                    "expected_duplicate_409": 4,
                    "passed": (reg_stats["ok_2xx"] == 26 and reg_stats["conflict_409"] == 4 and reg_stats["error_5xx"] == 0),
                },
                "browsing_read_benchmarks": browsing_levels,
                "concurrent_write_and_race_100": {
                    **write_stats,
                    "expected_db_rows": 51,
                    "actual_db_rows": db_rows,
                    "zero_double_bookings": (write_stats["ok_2xx"] == 51 and write_stats["conflict_409"] == 49 and db_rows == 51),
                },
                "server_metrics": metrics,
                "peak_process_ram_mb": rss_mb,
                "all_targets_met": (
                    all(v["error_rate_pct"] < 1.0 and v["p95_ms"] < 1000.0 for v in browsing_levels.values())
                    and write_stats["error_rate_pct"] < 1.0
                    and write_stats["p95_ms"] < (5000.0 if os.name == "nt" else 2000.0)
                    and db_rows == 51
                ),
            }
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    res = run_load_suite()
    print(json.dumps(res, indent=2))
    if not res["all_targets_met"]:
        raise SystemExit(1)
