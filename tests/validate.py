"""
LogLens validation test suite.
Run from project root: python tests/validate.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import app, build_analytics  # noqa: E402
from log_parser import parse_log_file, parse_log_line  # noqa: E402
from threat_detector import load_signatures, scan_entries  # noqa: E402

SAMPLES = os.path.join(ROOT, "sample_logs")
SIGS = load_signatures(os.path.join(ROOT, "signatures.json"))


def ok(name: str, condition: bool, detail: str = "") -> dict:
    return {"name": name, "passed": condition, "detail": detail}


def run_parser_tests() -> list[dict]:
    results = []
    line = (
        '192.168.1.1 - - [10/Oct/2023:13:55:36 -0700] '
        '"GET /index.html HTTP/1.1" 200 2326'
    )
    parsed = parse_log_line(line)
    results.append(
        ok(
            "Parser: single Apache line",
            parsed is not None and parsed["ip"] == "192.168.1.1",
            str(parsed),
        )
    )

    entries, skipped = parse_log_file(os.path.join(SAMPLES, "sample.log"))
    results.append(
        ok(
            "Parser: sample.log",
            len(entries) == 10 and skipped == 1,
            f"parsed={len(entries)}, skipped={skipped}",
        )
    )
    return results


def run_upload_tests() -> list[dict]:
    results = []
    client = app.test_client()

    r = client.get("/")
    results.append(ok("Upload: GET /", r.status_code == 200, f"status={r.status_code}"))

    r = client.post("/upload", data={})
    results.append(
        ok(
            "Upload: missing file returns 400",
            r.status_code == 400 and b"No file included" in r.data,
            f"status={r.status_code}",
        )
    )

    r = client.post(
        "/upload",
        data={"logfile": (b"", "")},
        content_type="multipart/form-data",
    )
    results.append(
        ok(
            "Upload: empty filename returns 400",
            r.status_code == 400,
            f"status={r.status_code}",
        )
    )

    with open(os.path.join(SAMPLES, "sample.log"), "rb") as f:
        r = client.post(
            "/upload",
            data={"logfile": (f, "sample.log")},
            content_type="multipart/form-data",
        )
    results.append(
        ok(
            "Upload: valid clean log returns 200",
            r.status_code == 200 and b"Analysis Results" in r.data,
            f"status={r.status_code}",
        )
    )
    return results


def _scan(path: str) -> tuple[list, dict, dict]:
    entries, _ = parse_log_file(path)
    scanned, summary = scan_entries(entries, SIGS)
    analytics = build_analytics(scanned)
    return scanned, summary, analytics


def run_threat_tests() -> list[dict]:
    results = []
    scanned, summary, analytics = _scan(os.path.join(SAMPLES, "threats.log"))

    sqli = sum(1 for e in scanned if e.get("attack_type") == "SQL Injection")
    xss = sum(1 for e in scanned if e.get("attack_type") == "XSS")
    trav = sum(1 for e in scanned if e.get("attack_type") == "Directory Traversal")
    brute = sum(1 for e in scanned if e.get("attack_type") == "Brute Force")

    results.append(ok("SQLi detection", sqli == 2, f"detected={sqli}, expected=2"))
    results.append(ok("XSS detection", xss == 2, f"detected={xss}, expected=2"))
    results.append(
        ok("Directory Traversal detection", trav == 3, f"detected={trav}, expected=3")
    )
    results.append(
        ok("Brute Force detection (threats.log)", brute == 6, f"detected={brute}, expected=6")
    )
    results.append(
        ok(
            "Threat summary totals",
            summary["total"] == 13,
            str(summary),
        )
    )
    return results


def run_brute_force_tests() -> list[dict]:
    results = []
    scanned, summary, _ = _scan(os.path.join(SAMPLES, "brute_force_test.log"))
    brute_ips = {e["ip"] for e in scanned if e.get("attack_type") == "Brute Force"}

    results.append(
        ok(
            "Brute Force: dedicated test log",
            summary["total"] == 6 and summary["high"] == 6,
            str(summary),
        )
    )
    results.append(
        ok(
            "Brute Force: attacker IP flagged",
            "192.168.1.100" in brute_ips,
            f"ips={sorted(brute_ips)}",
        )
    )
    return results


def run_analytics_tests() -> list[dict]:
    results = []
    _, summary, analytics = _scan(os.path.join(SAMPLES, "threats.log"))

    top = analytics["top_attackers"]
    breakdown = analytics["attack_breakdown"]
    severity = analytics["severity_breakdown"]

    results.append(
        ok(
            "Analytics: top attackers populated",
            len(top) >= 1 and top[0]["ip"] == "10.0.0.50" and top[0]["count"] == 6,
            str(top[0]),
        )
    )
    results.append(
        ok(
            "Analytics: attack breakdown",
            breakdown.get("Brute Force") == 6
            and breakdown.get("SQL Injection") == 2
            and breakdown.get("XSS") == 2
            and breakdown.get("Directory Traversal") == 3,
            str(breakdown),
        )
    )
    results.append(
        ok(
            "Analytics: severity distribution",
            severity["High"] == 11 and severity["Medium"] == 2 and severity["Low"] == 0,
            str(severity),
        )
    )

    client = app.test_client()
    with open(os.path.join(SAMPLES, "threats.log"), "rb") as f:
        r = client.post(
            "/upload",
            data={"logfile": (f, "threats.log")},
            content_type="multipart/form-data",
        )
    html = r.get_data(as_text=True)
    results.append(
        ok(
            "Analytics: dashboard panels render",
            all(
                s in html
                for s in [
                    "Top Attackers",
                    "Attack Type Breakdown",
                    "Severity Distribution",
                    "Threat Intelligence Analysis",
                ]
            ),
            f"status={r.status_code}",
        )
    )
    return results


def run_import_tests() -> list[dict]:
    results = []
    results.append(ok("Imports: signatures loaded", len(SIGS) == 10, f"count={len(SIGS)}"))
    return results


def main() -> int:
    sections = [
        ("Import Tests", run_import_tests),
        ("Upload Tests", run_upload_tests),
        ("Parser Tests", run_parser_tests),
        ("Threat Detection Tests", run_threat_tests),
        ("Brute Force Tests", run_brute_force_tests),
        ("Analytics Tests", run_analytics_tests),
    ]

    total = 0
    passed = 0
    print("LogLens Validation Suite")
    print("=" * 60)

    for title, fn in sections:
        print(f"\n{title}")
        print("-" * 60)
        for result in fn():
            total += 1
            if result["passed"]:
                passed += 1
                mark = "PASS"
            else:
                mark = "FAIL"
            detail = f" — {result['detail']}" if result["detail"] else ""
            print(f"  [{mark}] {result['name']}{detail}")

    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} passed ({100 * passed // total if total else 0}%)")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
