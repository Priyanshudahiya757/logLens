"""
log_parser.py — Phase 2.1
Parses Apache Common Log Format files line by line using regex.

Apache Common Log Format example:
  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1234
  ─────────   ─ ─────  ──────────────────────────  ─────────────────────────  ─── ────
  IP         │ user   timestamp                    request line               status bytes
             ident (almost always -)
"""

import re


# ─────────────────────────────────────────────────────────────────
#  THE REGEX — broken into named pieces so it's easy to understand
# ─────────────────────────────────────────────────────────────────
#
#  re.compile() builds the pattern once and reuses it — much faster
#  than compiling it on every line.  The r"..." prefix means "raw
#  string": backslashes are passed straight to the regex engine.
#
#  (?P<name>...)  →  a *named* group; match.group("name") to read it.

LOG_PATTERN = re.compile(
    # ── 1. IP ADDRESS ──────────────────────────────────────────────
    # \d{1,3}      → one to three digits  (e.g. "192")
    # (?:\.){3}    → exactly three more groups of dot + digits
    # Full match:  "192.168.1.101"
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'

    # ── 2. SKIP IDENT AND AUTH USER ────────────────────────────────
    # These two fields are almost always "-" in real-world logs.
    # \s+  → one or more whitespace chars (the spaces between fields)
    # \S+  → one or more non-whitespace chars (the "-" or a username)
    r'\s+\S+\s+\S+'

    # ── 3. TIMESTAMP ───────────────────────────────────────────────
    # \[        → literal opening bracket  (must escape with \)
    # [^\]]+    → one or more chars that are NOT a closing bracket
    #             This grabs everything inside [...] without knowing
    #             the exact date format.
    # \]        → literal closing bracket
    # Example captured value:  "10/Oct/2000:13:55:36 -0700"
    r'\s+\[(?P<timestamp>[^\]]+)\]'

    # ── 4. HTTP METHOD ─────────────────────────────────────────────
    # \"        → literal opening double-quote (the request starts with ")
    # [A-Z]+    → one or more uppercase letters  e.g. GET, POST, PUT, DELETE
    r'\s+"(?P<method>[A-Z]+)'

    # ── 5. REQUEST PATH ────────────────────────────────────────────
    # \S+       → one or more non-whitespace chars
    #             e.g. "/index.html" or "/api/v1/users?id=5"
    r'\s+(?P<path>\S+)'

    # ── 6. SKIP HTTP VERSION ───────────────────────────────────────
    # \S+  → matches "HTTP/1.1" (or HTTP/2, etc.)
    # \"   → the closing double-quote that ends the request string
    r'\s+\S+"'

    # ── 7. STATUS CODE ─────────────────────────────────────────────
    # \d{3}    → exactly three digits  e.g. 200, 404, 500
    r'\s+(?P<status>\d{3})'
)


# ─────────────────────────────────────────────────────────────────
#  PARSE A SINGLE LINE
# ─────────────────────────────────────────────────────────────────

def parse_log_line(line: str) -> dict | None:
    """
    Try to match one line against the Apache log pattern.

    Returns a dict with the five extracted fields,
    or None if the line doesn't look like a valid log entry.

    Example return value:
    {
        "ip":        "192.168.1.101",
        "timestamp": "10/Oct/2000:13:55:36 -0700",
        "method":    "GET",
        "path":      "/index.html",
        "status":    200
    }
    """
    # .search() scans the whole line for the pattern (more forgiving
    # than .match() which only checks from the very start).
    match = LOG_PATTERN.search(line)

    if not match:
        # Line doesn't look like a log entry — return None so the
        # caller can count how many lines we skipped.
        return None

    return {
        "ip":        match.group("ip"),
        "timestamp": match.group("timestamp"),
        "method":    match.group("method"),
        "path":      match.group("path"),
        "status":    int(match.group("status")),  # str → int (200, 404, 500…)
    }


# ─────────────────────────────────────────────────────────────────
#  PARSE AN ENTIRE FILE
# ─────────────────────────────────────────────────────────────────

def parse_log_file(file_path: str) -> tuple[list[dict], int]:
    """
    Open an Apache log file and parse every line.

    Args:
        file_path: absolute path to the saved log file

    Returns:
        entries  — list of successfully parsed dicts
        skipped  — count of lines we couldn't parse (malformed / blank)

    Usage:
        entries, skipped = parse_log_file("/uploads/access.log")
        print(f"Parsed {len(entries)} lines, skipped {skipped}")
    """
    entries = []
    skipped = 0

    # errors="replace" means garbled bytes become "?" instead of
    # crashing with a UnicodeDecodeError.
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()   # remove leading/trailing whitespace + newline

            if not line:              # blank line → skip silently (don't count)
                continue

            result = parse_log_line(line)

            if result:
                entries.append(result)
            else:
                skipped += 1          # count lines we couldn't understand

    return entries, skipped
