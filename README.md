# SQL Injection Scanner

A Python-based SQL injection scanner built as part of my Syntecxhub Cybersecurity internship (Week 3 task), including a deliberately vulnerable Flask app used as a safe, legal local target to test it against.

## What it does
Tests web form fields for common SQL injection patterns by submitting a set of known SQLi payloads and analyzing the response for signs of a vulnerability - either a leaked database error message or signs of an authentication bypass. Results are printed to the console and logged in full to `sqli_scan_results.log`.

## Why there's a second app in this repo
Testing a SQL injection scanner requires an actual vulnerable target. Rather than scanning DVWA or any external site, `vulnerable_app.py` is a small, intentionally vulnerable local Flask login page I built specifically for this - it uses raw string concatenation in its SQL query instead of parameterized queries, which is the exact class of mistake the scanner is designed to catch. This keeps testing fully legal and self-contained, since it only ever runs against something I built and own.

## Features
- Tests multiple form fields (e.g., username, password) with a set of common SQLi payloads
- Detects two kinds of indicators: leaked SQL error messages, and signs of authentication bypass
- Basic concurrency - each field is tested on its own thread
- Rate-limiting between requests (0.5s delay) so the scanner doesn't hammer the target
- Full logging of every test performed, vulnerable or not, with timestamps
- Clear console warning about only testing permitted targets

## Technologies used
- Python 3
- `flask` - for the local vulnerable test app
- `requests` - for sending the actual HTTP requests to test the target
- `sqlite3` - the vulnerable app's backend database
- `threading` - basic concurrency across fields being tested
- `logging` - persistent scan results

## How it works
For each form field given, the scanner sends a series of known SQL injection payloads as that field's value (keeping other fields filled with a harmless placeholder), then checks the HTTP response for two things: known SQL error message fingerprints (like SQLite or MySQL error text leaking into the page), or signs that a login succeeded when it shouldn't have (authentication bypass). Each field is tested on its own thread, with a short delay between requests to avoid flooding the target. Every result - vulnerable or not, gets logged, and anything flagged gets printed to the console immediately.

## How to run
Install dependencies:
```bash
pip install flask requests
```

**Terminal 1 — start the vulnerable test target:**
```bash
python vulnerable_app.py
```

**Terminal 2 — run the scanner against it:**
```bash
python sqli_scanner.py
```
When prompted, enter:
