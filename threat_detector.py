"""
threat_detector.py — Phase 3.1
Loads attack signatures from signatures.json and checks every
parsed log entry for matches.

How it works in plain English:
  1. We read signatures.json and turn each raw regex string into a
     compiled Pattern object (faster than compiling on every line).
  2. For every log entry, we pull out the request path.
  3. We URL-decode the path so encoded attacks (%3Cscript%3E → <script>)
     don't slip through.
  4. We test the path (raw and decoded) against every pattern.
  5. On a match we annotate the entry with attack_type and severity.
"""

import json
import re
from urllib.parse import unquote_plus   # %2F → /,  + → space


# ─────────────────────────────────────────────────────────────────
#  STEP 1 — LOAD AND COMPILE SIGNATURES
# ─────────────────────────────────────────────────────────────────

def load_signatures(json_path: str) -> list[dict]:
    """
    Read signatures.json from disk and compile every regex pattern.

    WHY PRE-COMPILE?
      re.compile() converts a pattern string into an internal state
      machine once. If we passed the raw string to re.search() on
      every log line, Python would redo that work millions of times
      for a large file. Compiling once and reusing is much faster.

    Returns a list of signature dicts. Each dict is identical to the
    JSON object plus one extra key:
        "compiled_patterns"  →  list[re.Pattern]
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    compiled_signatures = []

    for sig in data["signatures"]:
        patterns = []

        for raw_pattern in sig["patterns"]:
            try:
                patterns.append(re.compile(raw_pattern))
            except re.error as err:
                # A bad regex in the JSON file should not crash the app.
                # We print a warning and skip that one pattern.
                print(f"[threat_detector] WARNING — bad pattern in "
                      f"{sig['id']}: {err}")

        # {**sig, "compiled_patterns": patterns}
        #   → creates a NEW dict with all keys from 'sig' PLUS our
        #   new "compiled_patterns" key. The original sig dict is not
        #   mutated.
        compiled_signatures.append({**sig, "compiled_patterns": patterns})

    return compiled_signatures


# ─────────────────────────────────────────────────────────────────
#  STEP 2 — CHECK A SINGLE ENTRY
# ─────────────────────────────────────────────────────────────────

def check_entry(entry: dict, signatures: list[dict]) -> dict | None:
    """
    Test one parsed log entry against every loaded signature.

    WHERE WE LOOK
    ─────────────
    We check the request PATH (the URL including any query string).
    That is where injection payloads almost always appear, e.g.:
        /search?q=<script>alert(1)</script>
        /login?user=admin%27+OR+1=1--
        /files/../../../../etc/passwd

    WHY WE URL-DECODE
    ─────────────────
    Attackers often URL-encode characters to bypass simple text filters:
        %3C  →  <
        %27  →  '
        %2e%2e%2f  →  ../

    unquote_plus() decodes %XX sequences AND converts + into spaces
    (the + convention is used in query strings: a+b → "a b").

    We check BOTH the raw path (catches clear-text attacks and
    double-encoded patterns like %252e) AND the decoded path (catches
    single-encoded attacks).

    WHICH MATCH WINS
    ────────────────
    We return the FIRST matching signature — the one that appears
    earliest in signatures.json. In practice this means the most
    specific / most dangerous pattern wins if signatures are ordered
    by severity. Phase 3.x could collect all matches instead.

    Returns:
        dict  — { attack_type, severity, signature_id, signature_name }
        None  — if the entry looks clean
    """
    raw_path     = entry.get("path", "")
    decoded_path = unquote_plus(raw_path)

    # We test both strings but avoid running patterns twice against
    # the same string (happens when there were no encoded chars).
    # dict.fromkeys preserves order while deduplicating.
    targets = list(dict.fromkeys([raw_path, decoded_path]))

    for sig in signatures:
        for pattern in sig["compiled_patterns"]:
            for target in targets:
                if pattern.search(target):
                    # ── Hit! ───────────────────────────────────────
                    return {
                        "attack_type":    sig["attack_type"],
                        "severity":       sig["severity"],
                        "signature_id":   sig["id"],
                        "signature_name": sig["name"],
                    }

    return None   # every pattern missed → entry is clean


# ─────────────────────────────────────────────────────────────────
#  STEP 3 — DETECT BRUTE FORCE ATTACKS
# ─────────────────────────────────────────────────────────────────

def detect_brute_force(entries: list[dict], threshold: int = 5) -> list[dict]:
    """
    Detect brute force attacks by counting HTTP 401 responses per IP.

    A brute force attack is detected when the same IP address makes 5 or more
    failed login attempts (HTTP 401 Unauthorized responses).

    Args:
        entries    — list of parsed log entries (already annotated with signature threats)
        threshold  — minimum number of 401s from one IP to flag as brute force (default 5)

    Returns:
        entries list with brute force threats marked (threat, attack_type, severity, etc.)

    How it works:
    ─────────────
    1. Count HTTP 401 responses grouped by IP address.
    2. Identify IPs that exceed the threshold.
    3. Mark all 401 entries from those IPs with brute force threat.
    4. Only mark entries that don't already have a threat from signature detection.
    """
    # Count 401 responses by IP
    ip_401_counts = {}
    for entry in entries:
        if entry.get("status") == 401:
            ip = entry.get("ip", "")
            ip_401_counts[ip] = ip_401_counts.get(ip, 0) + 1

    # Identify IPs that meet or exceed the threshold
    brute_force_ips = {ip for ip, count in ip_401_counts.items() if count >= threshold}

    # Mark entries from these IPs as brute force threats
    # Only mark 401 entries that don't already have a signature-based threat
    for entry in entries:
        if (entry.get("ip") in brute_force_ips and
            entry.get("status") == 401 and
            not entry.get("threat", False)):

            entry["threat"] = True
            entry["attack_type"] = "Brute Force"
            entry["severity"] = "High"
            entry["signature_id"] = "BRUTEFORCE-001"
            entry["signature_name"] = "Brute Force Attack — Multiple Failed Login Attempts"

    return entries


# ─────────────────────────────────────────────────────────────────
#  STEP 4 — RECALCULATE THREAT SUMMARY (POST-DETECTION)
# ─────────────────────────────────────────────────────────────────

def recalculate_threat_summary(entries: list[dict]) -> dict:
    """
    Recalculate threat counts from the final scanned entries.

    This is called AFTER all detection logic (signatures + brute force) has run,
    so it captures threats from both detection methods.

    Args:
        entries — list of entries with all threat annotations applied

    Returns:
        counts dict: { "total": int, "high": int, "medium": int, "low": int }
    """
    counts = {"total": 0, "high": 0, "medium": 0, "low": 0}

    for entry in entries:
        if entry.get("threat", False):
            counts["total"] += 1
            severity = entry.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1

    return counts


# ─────────────────────────────────────────────────────────────────
#  STEP 5 — SCAN ALL ENTRIES AND BUILD A SUMMARY
# ─────────────────────────────────────────────────────────────────

def scan_entries(entries: list[dict], signatures: list[dict]) -> tuple[list[dict], dict]:
    """
    Run every parsed log entry through check_entry and annotate results.

    Flow:
    1. Scan for signature-based threats (SQL Injection, XSS, Directory Traversal)
    2. Detect brute force attacks (HTTP 401 patterns)
    3. Recalculate the threat summary to include all detected threats

    Args:
        entries    — output of parse_log_file() from log_parser.py
        signatures — output of load_signatures()

    Returns a tuple of two things:

    scanned_entries  (list[dict])
        Every entry from the input list, now with extra keys:
            "threat"         → True / False
            "attack_type"    → e.g. "SQL Injection" / "Brute Force" or ""
            "severity"       → e.g. "High" or ""
            "signature_id"   → e.g. "SQLI-001" / "BRUTEFORCE-001" or ""
            "signature_name" → e.g. "SQL Injection — UNION SELECT" or ""

    threat_summary   (dict)
        A count of threats broken down by severity:
            { "total": int, "high": int, "medium": int, "low": int }
        Useful for displaying stat cards without looping in the template.
    """
    scanned = []
    counts  = {"total": 0, "high": 0, "medium": 0, "low": 0}

    # ── PHASE 3.1: Signature-based threat detection ────────────────
    for entry in entries:
        match = check_entry(entry, signatures)

        if match:
            # Merge the original entry dict with the threat fields.
            # {**entry, **match}  →  creates a new dict; does NOT
            # change 'entry' itself.
            annotated = {**entry, "threat": True, **match}

            counts["total"] += 1
            # match["severity"] is "High", "Medium", or "Low"
            # .lower() converts it so it matches our dict keys
            counts[match["severity"].lower()] += 1

        else:
            # Add empty threat fields so the template can always
            # reference entry.attack_type without checking first.
            annotated = {
                **entry,
                "threat":         False,
                "attack_type":    "",
                "severity":       "",
                "signature_id":   "",
                "signature_name": "",
            }

        scanned.append(annotated)

    # ── PHASE 3.2: Brute force detection + recalculate summary ────
    scanned = detect_brute_force(scanned)
    counts = recalculate_threat_summary(scanned)

    return scanned, counts
