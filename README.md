# LogLens 🔍

### Flask-Based Log Analysis & Threat Detection Dashboard

LogLens is a lightweight Security Information and Event Management (SIEM-lite) application built with Python and Flask. It analyzes Apache access logs, detects common web attacks, identifies brute-force activity, and presents findings through an interactive dashboard.

Designed as a cybersecurity portfolio project, LogLens demonstrates practical skills in log parsing, threat detection engineering, security analytics, and web application development.

---

## Features

### Log Parsing

* Apache Common Log Format support
* Structured extraction of:

  * Source IP
  * Timestamp
  * HTTP Method
  * Request Path
  * Status Code

### Threat Detection

* SQL Injection detection
* Cross-Site Scripting (XSS) detection
* Directory Traversal detection
* Behavioral Brute Force detection

### Security Analytics

* Top attacking IP addresses
* Attack category breakdown
* Severity distribution
* Threat summary metrics

### Dashboard

* File upload interface
* Security summary cards
* Threat intelligence panels
* Annotated log event table
* Bootstrap-based responsive UI

---

## Technology Stack

| Category          | Technology                                           |
| ----------------- | ---------------------------------------------------- |
| Backend           | Python                                               |
| Framework         | Flask                                                |
| Frontend          | HTML, Bootstrap 5, Jinja2                            |
| Detection Engine  | Regex-based signatures                               |
| Data Format       | JSON                                                 |
| Security Concepts | Threat Detection, Log Analysis, Behavioral Analytics |

---

## Detection Coverage

| Attack Type         | Examples Detected                          |
| ------------------- | ------------------------------------------ |
| SQL Injection       | UNION SELECT, OR 1=1, xp_cmdshell          |
| XSS                 | script tags, javascript:, event handlers   |
| Directory Traversal | ../, encoded traversal sequences           |
| Brute Force         | Excessive HTTP 401 authentication failures |

---

## Project Architecture

```text
Access Logs
      │
      ▼
 Log Parser
      │
      ▼
Threat Detection Engine
 ├── SQL Injection
 ├── XSS
 ├── Traversal
 └── Brute Force
      │
      ▼
 Analytics Engine
      │
      ▼
 Security Dashboard
```

---

## Project Structure

```text
LogLens/
├── app.py
├── log_parser.py
├── threat_detector.py
├── signatures.json
├── requirements.txt
├── sample_logs/
├── templates/
├── tests/
└── uploads/
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Priyanshudahiya757/logLens.git
cd loglens
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Environment

Windows

```bash
venv\Scripts\activate
```

Linux / macOS

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Example Workflow

1. Upload an Apache access log file.
2. LogLens parses log entries.
3. Detection engine scans for attack signatures.
4. Behavioral analysis identifies brute-force activity.
5. Results are displayed in the dashboard.

---

## Sample Detection Results

| Threat               | Severity |
| -------------------- | -------- |
| SQL Injection        | High     |
| Cross-Site Scripting | High     |
| Directory Traversal  | Medium   |
| Brute Force Attack   | High     |

---

## What I Learned

This project helped me gain hands-on experience with:

* Flask application development
* File upload handling
* Regex-based log parsing
* Signature-based threat detection
* Behavioral security analytics
* Dashboard design and visualization
* Modular Python application architecture

---

## Future Enhancements

* Nginx log support
* GeoIP enrichment
* CSV / JSON export
* Real-time log monitoring
* Threat intelligence integration
* Email and webhook alerts
* User authentication

## Disclaimer

LogLens is an educational and portfolio project intended to demonstrate security engineering concepts. It is not designed as a production-grade SIEM solution.

---

## Author

** Priyanshu Dahiya **

Cybersecurity | Python | Security Engineering

GitHub: https://github.com/Priyanshudahiya757

