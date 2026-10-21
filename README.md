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

**Terminal 1 - start the vulnerable test target:**
```bash
python vulnerable_app.py
```

**Terminal 2 - run the scanner against it:**
```bash
python sqli_scanner.py
```
When prompted, enter:

Target URL: http://127.0.0.1:5000/login
Form field names to test, comma-separated: username,password


## Example result
Running the scanner against the included vulnerable app correctly identifies multiple exploitable payloads, including classic authentication bypass strings like `' OR '1'='1` and `admin'--`, as well as a payload that triggers a visible database error (`' UNION SELECT NULL--`). Full results are saved to `sqli_scan_results.log`.

## A technical nuance worth noting
One tested payload, `'; DROP TABLE users--`, gets flagged by the scanner as a bypass indicator rather than confirming the table was actually dropped. This is because the vulnerable app executes each request as a single SQL statement, and SQLite's Python driver doesn't run multiple semicolon-separated statements in one call by default, so the `DROP TABLE` portion never actually executed, even though the malformed query still behaved like a bypass. This is a useful real-world distinction: detecting a vulnerability indicator isn't always the same as confirming destructive execution, and a real assessment would need to verify that separately.

## Security considerations
- The vulnerable app is intentionally insecure and should never be deployed outside a local test environment
- The scanner includes rate-limiting specifically to avoid being an unintentional denial-of-service tool against a real target
- Scanning any system without explicit authorization is illegal in most jurisdictions - this tool is built and documented for authorized, local testing only
- The payload list here is a representative sample, not exhaustive - a thorough real-world test would use a much larger, regularly updated payload set

## Limitations
- Only tests form-based (POST) inputs, not URL parameters or headers
- Payload list is fixed and relatively small - doesn't cover blind/time-based SQLi detection
- Error-signature detection relies on string matching, which can miss custom/obscured error handling
- No distinction made between a confirmed bypass and a merely suspicious response

## Future improvements
- Add time-based blind SQLi detection (measuring response delay rather than relying on visible errors)
- Expand the payload list and make it configurable via a file
- Add URL parameter and header-based injection testing, not just form fields
- Add a proper HTML/PDF report output instead of just console + log file

## Real-world relevance
SQL injection remains one of the most common and damaging web vulnerabilities in real breaches, despite being well understood and preventable with parameterized queries. Beyond building the scanner, recognizing these exact payload patterns = `' OR 1=1--`, `UNION SELECT`, leaked database errors is directly useful for a SOC analyst reviewing web server or WAF logs, since these are some of the most common attack signatures seen in real traffic.
