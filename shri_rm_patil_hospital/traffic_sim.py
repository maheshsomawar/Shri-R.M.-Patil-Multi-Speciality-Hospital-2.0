"""
Concurrent Traffic & Load Simulation for Shri R.M. Patil Hospital Server.
Tests:
- Multi-threaded concurrent public browsing & health checks
- Concurrent appointment bookings persisted into SQLite WAL database
- Abusive bot burst triggering rate-limit protection (HTTP 429)
- Zero 5xx server errors under load, measuring real p50/p95/p99 latencies and req/sec
"""

import concurrent.futures
import http.client
import json
import os
import statistics
import tempfile
import threading
import time
from typing import Any, Dict, List, Tuple

from datetime import datetime, timedelta
from migrations import IST
from server import AppConfig, create_server


def _send(port: int, method: str, path: str, payload: Dict[str, Any] | None = None) -> Tuple[int, float]:
    t0 = time.perf_counter()
    raw = json.dumps(payload).encode("utf-8") if payload is not None else None
    for attempt in range(3):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Connection": "close"}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            conn.close()
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return status, dt_ms
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            conn.close()
            if attempt == 2:
                raise
            time.sleep(0.02 * (attempt + 1))
    return 500, 0.0


def run_simulation() -> Dict[str, Any]:
    _d = datetime.now(IST) + timedelta(days=1)
    while _d.weekday() == 6:
        _d += timedelta(days=1)
    next_workday = _d.strftime("%Y-%m-%d")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        cfg = AppConfig()
        cfg.host = "127.0.0.1"
        cfg.port = 0
        cfg.debug = False
        cfg.db_path = os.path.join(tmpdir, "traffic_hospital.db")
        # High public capacity for legitimate browsing, strict booking cap to test burst throttling
        cfg.rate_limit_public = 600
        cfg.rate_limit_booking = 40
        cfg.rate_limit_login = 20

        srv = create_server(cfg)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            # Phase 1: 300 concurrent public read requests across 20 worker threads
            read_latencies: List[float] = []
            read_statuses: List[int] = []
            t_start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                futs = [
                    pool.submit(_send, port, "GET", "/api/public/info" if i % 2 == 0 else "/api/health")
                    for i in range(300)
                ]
                for f in concurrent.futures.as_completed(futs):
                    st, ms = f.result()
                    read_statuses.append(st)
                    read_latencies.append(ms)
            read_elapsed = time.perf_counter() - t_start

            # Phase 2: 60 concurrent appointment booking requests (40 should succeed 201, 20 should be rate-limited 429)
            book_latencies: List[float] = []
            book_statuses: List[int] = []
            departments = [
                "Orthopaedics — Dr. Rohan Patil",
                "Obstetrics & Gynaecology — Dr. Rahul Patil",
                "Dental Surgery — Dr. Manjusha Patil",
                "General Medicine — Dr. Snehal Patil",
            ]
            t_book_start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
                futs = [
                    pool.submit(
                        _send,
                        port,
                        "POST",
                        "/api/appointments",
                        {
                            "first_name": f"Patient{chr(65 + (i % 26))}",
                            "last_name": "LoadTest",
                            "mobile": f"98{10000000 + i}",
                            "department": departments[i % len(departments)],
                            "message": f"Routine consultation request #{i}",
                        },
                    )
                    for i in range(60)
                ]
                for f in concurrent.futures.as_completed(futs):
                    st, ms = f.result()
                    book_statuses.append(st)
                    book_latencies.append(ms)
            book_elapsed = time.perf_counter() - t_book_start

            # Phase 3: 20 concurrent threads racing for the EXACT same doctor & time slot (1 must win 201, 19 must get 409)
            srv.config.rate_limit_booking = 200
            race_latencies: List[float] = []
            race_statuses: List[int] = []
            t_race_start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                futs = [
                    pool.submit(
                        _send,
                        port,
                        "POST",
                        "/api/appointments",
                        {
                            "first_name": f"Race{chr(65 + (i % 26))}",
                            "last_name": "Patient",
                            "mobile": f"98900000{i:02d}",
                            "department": "Orthopaedics — Dr. Rohan Patil",
                            "appointment_date": next_workday,
                            "slot_time": "10:30",
                            "message": "Slot race simulation",
                        },
                    )
                    for i in range(20)
                ]
                for f in concurrent.futures.as_completed(futs):
                    st, ms = f.result()
                    race_statuses.append(st)
                    race_latencies.append(ms)
            race_elapsed = time.perf_counter() - t_race_start

            db_saved = srv.db.count_appointments()
            all_latencies = sorted(read_latencies + book_latencies + race_latencies)
            p50 = round(statistics.median(all_latencies), 2)
            p95 = round(all_latencies[int(0.95 * len(all_latencies))], 2)
            p99 = round(all_latencies[int(0.99 * len(all_latencies))], 2)
            total_reqs = len(read_statuses) + len(book_statuses) + len(race_statuses)
            total_time = read_elapsed + book_elapsed + race_elapsed
            err_5xx = sum(1 for s in (read_statuses + book_statuses + race_statuses) if s >= 500)

            summary = {
                "total_requests": total_reqs,
                "throughput_rps": round(total_reqs / total_time, 1),
                "p50_ms": p50,
                "p95_ms": p95,
                "p99_ms": p99,
                "public_reads": {
                    "total": len(read_statuses),
                    "ok_200": read_statuses.count(200),
                    "rate_limited_429": read_statuses.count(429),
                },
                "booking_burst": {
                    "total": len(book_statuses),
                    "created_201": book_statuses.count(201),
                    "rate_limited_429": book_statuses.count(429),
                },
                "slot_race_test": {
                    "total_concurrent_attempts": len(race_statuses),
                    "won_slot_201": race_statuses.count(201),
                    "blocked_conflict_409": race_statuses.count(409),
                },
                "db_persisted_rows": db_saved,
                "server_errors_5xx": err_5xx,
                "passed": (
                    read_statuses.count(200) == 300
                    and book_statuses.count(201) == 40
                    and book_statuses.count(429) == 20
                    and race_statuses.count(201) == 1
                    and race_statuses.count(409) == 19
                    and db_saved == 41
                    and err_5xx == 0
                ),
            }
            return summary
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    res = run_simulation()
    print(json.dumps(res, indent=2))
    if not res["passed"]:
        raise SystemExit(1)
