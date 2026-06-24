"""
app.py — LogLens
Flask application: upload, parse, threat detection, analytics dashboard,
and attack timeline visualization.
"""

import os
from flask import Flask, request, render_template
from werkzeug.utils import secure_filename

from log_parser import parse_log_file
from threat_detector import load_signatures, scan_entries
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)
import csv
from flask import send_file
from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"log", "txt"}

# ──────────────────────────────────────────────────────────────
# Load signatures once at startup
# ──────────────────────────────────────────────────────────────

SIGNATURES_PATH = os.path.join(
    os.path.dirname(__file__),
    "signatures.json"
)

try:
    SIGNATURES = load_signatures(SIGNATURES_PATH)
    print(f"[LogLens] Loaded {len(SIGNATURES)} signatures.")
except FileNotFoundError:
    print(
        f"[LogLens] WARNING: signatures.json not found at "
        f"{SIGNATURES_PATH}"
    )
    SIGNATURES = []


# ──────────────────────────────────────────────────────────────
# File validation
# ──────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ──────────────────────────────────────────────────────────────
# Phase 3.3 + Phase 4.1 Analytics
# ──────────────────────────────────────────────────────────────

def build_analytics(scanned: list[dict]) -> dict:
    """
    Build threat intelligence analytics.

    Returns:
        top_attackers
        attack_breakdown
        severity_breakdown
        timeline
    """

    # ----------------------------------------------------------
    # TOP ATTACKERS
    # ----------------------------------------------------------

    ip_data = {}

    for entry in scanned:

        if not entry.get("threat"):
            continue

        ip = entry["ip"]

        if ip not in ip_data:
            ip_data[ip] = {
                "count": 0,
                "types": set(),
            }

        ip_data[ip]["count"] += 1
        ip_data[ip]["types"].add(
            entry["attack_type"]
        )

    sorted_ips = sorted(
        ip_data.items(),
        key=lambda kv: kv[1]["count"],
        reverse=True,
    )

    top_attackers = []

    for ip, data in sorted_ips[:10]:
        top_attackers.append(
            {
                "ip": ip,
                "count": data["count"],
                "types": sorted(data["types"]),
            }
        )

    # ----------------------------------------------------------
    # ATTACK TYPE BREAKDOWN
    # ----------------------------------------------------------

    attack_breakdown = {}

    for entry in scanned:

        if not entry.get("threat"):
            continue

        attack_type = entry["attack_type"]

        attack_breakdown[attack_type] = (
            attack_breakdown.get(
                attack_type,
                0,
            )
            + 1
        )

    attack_breakdown = dict(
        sorted(
            attack_breakdown.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )
    )

    # ----------------------------------------------------------
    # SEVERITY BREAKDOWN
    # ----------------------------------------------------------

    severity_breakdown = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for entry in scanned:

        if (
            entry.get("threat")
            and entry.get("severity")
            in severity_breakdown
        ):
            severity_breakdown[
                entry["severity"]
            ] += 1

    # ----------------------------------------------------------
    # PHASE 4.1 — ATTACK TIMELINE
    # ----------------------------------------------------------

    timeline = {}

    for entry in scanned:

        if not entry.get("threat"):
            continue

        timestamp = entry.get("timestamp")

        if not timestamp:
            continue

        try:

            # Example:
            # 15/Jun/2026:14:03:00 -0700
            #
            # Bucket:
            # 15/Jun/2026:14

            parts = timestamp.split(":")

            if len(parts) >= 2:
                hour_bucket = (
                    parts[0]
                    + ":"
                    + parts[1]
                )
            else:
                hour_bucket = timestamp[:14]

            timeline[hour_bucket] = (
                timeline.get(hour_bucket, 0)
                + 1
            )

        except Exception:
            continue

    timeline = dict(
        sorted(timeline.items())
    )

    return {
        "top_attackers": top_attackers,
        "attack_breakdown": attack_breakdown,
        "severity_breakdown": severity_breakdown,
        "timeline": timeline,
    }


# ──────────────────────────────────────────────────────────────
# Home page
# ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ──────────────────────────────────────────────────────────────
# Upload route
# ──────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload():

    if "logfile" not in request.files:
        return (
            render_template(
                "index.html",
                error="No file included in the request.",
            ),
            400,
        )

    file = request.files["logfile"]

    if file.filename == "":
        return (
            render_template(
                "index.html",
                error="Please choose a file before submitting.",
            ),
            400,
        )

    if not allowed_file(file.filename):
        return (
            render_template(
                "index.html",
                error="Only .log and .txt files are allowed.",
            ),
            400,
        )

    # ----------------------------------------------------------
    # Save upload
    # ----------------------------------------------------------

    safe_name = secure_filename(
        file.filename
    )

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_name,
    )

    file.save(save_path)

    # ----------------------------------------------------------
    # Parse logs
    # ----------------------------------------------------------

    entries, skipped = parse_log_file(
        save_path
    )

    # ----------------------------------------------------------
    # Threat detection
    # ----------------------------------------------------------

    scanned, threat_summary = scan_entries(
        entries,
        SIGNATURES,
    )

    # ----------------------------------------------------------
    # Analytics
    # ----------------------------------------------------------

    analytics = build_analytics(scanned)

    # ----------------------------------------------------------
    # Render dashboard
    # ----------------------------------------------------------

    return render_template(
        "results.html",

        filename=safe_name,

        total_parsed=len(entries),
        total_skipped=skipped,

        entries=scanned,

        threat_summary=threat_summary,

        top_attackers=analytics[
            "top_attackers"
        ],

        attack_breakdown=analytics[
            "attack_breakdown"
        ],

        severity_breakdown=analytics[
            "severity_breakdown"
        ],

        timeline=analytics[
            "timeline"
        ],
    )


# ──────────────────────────────────────────────────────────────
# Run app
# ──────────────────────────────────────────────────────────────

# ── DEMO ROUTE ─────────────────────────────────────────────
@app.route("/demo")
def demo():

    demo_file = os.path.join(
        os.path.dirname(__file__),
        "sample_logs",
        "threats.log"
    )

    entries, skipped = parse_log_file(demo_file)

    scanned, threat_summary = scan_entries(
        entries,
        SIGNATURES
    )

    analytics = build_analytics(scanned)

    return render_template(
        "results.html",
        filename="Demo Threat Log",
        total_parsed=len(entries),
        total_skipped=skipped,
        entries=scanned,
        threat_summary=threat_summary,
        top_attackers=analytics["top_attackers"],
        attack_breakdown=analytics["attack_breakdown"],
        severity_breakdown=analytics["severity_breakdown"],
        timeline=analytics["timeline"]
    )

@app.route("/report")
def report():

    report_path = os.path.join(
        os.path.dirname(__file__),
        "security_report.pdf"
    )

    doc = SimpleDocTemplate(report_path)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "LogLens Security Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "Generated by LogLens Threat Detection System",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "This report confirms successful log analysis.",
            styles["Normal"]
        )
    )

    doc.build(content)

    return send_file(
    report_path,
    as_attachment=True
)


@app.route("/export-csv")
def export_csv():

    csv_path = os.path.join(
        os.path.dirname(__file__),
        "threat_report.csv"
    )

    csv_path = os.path.join(
        os.path.dirname(__file__),
        "threat_report.csv"
    )

    demo_file = os.path.join(
        os.path.dirname(__file__),
        "sample_logs",
        "threats.log"
    )

    entries, skipped = parse_log_file(demo_file)

    scanned, threat_summary = scan_entries(
        entries,
        SIGNATURES
    )

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "IP",
            "Timestamp",
            "Method",
            "Path",
            "Status",
            "Threat",
            "Attack Type",
            "Severity"
        ])

        for entry in scanned:

            if not entry.get("threat"):
                continue

            writer.writerow([
                entry["ip"],
                entry["timestamp"],
                entry["method"],
                entry["path"],
                entry["status"],
                entry["threat"],
                entry["attack_type"],
                entry["severity"]
            ])

    return send_file(
        csv_path,
        as_attachment=True
    )
if __name__ == "__main__":
    app.run(debug=True)