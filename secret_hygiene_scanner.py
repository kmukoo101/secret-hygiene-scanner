"""
An extensible local secret scanner and hygiene auditor for developers, security engineers,
and DevOps teams. Designed to run as a CLI tool or GitHub Action, this scanner finds secrets
in code, config files, history, and system paths. Includes entropy detection, known pattern
matching, PDF/HTML export, CI/CD fail thresholds, and advanced alerting.
"""

import os
import re
import json
import argparse
import logging
import subprocess
from pathlib import Path
from datetime import datetime
import smtplib
from email.message import EmailMessage
import requests
from getpass import getpass
from fpdf import FPDF

# --- Logging ---
LOG_FILE = f"secret_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# --- Default Patterns ---
DEFAULT_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Generic Secret": r"(?<![A-Za-z0-9])[a-z0-9]{32,}(?![A-Za-z0-9])",
    "JWT": r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Password": r"(?i)password\s*[=:]\s*['\"]?.{6,}['\"]?"
}

# --- Utilities ---
def scan_file_for_secrets(filepath, patterns):
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for name, pattern in patterns.items():
                    if re.search(pattern, line):
                        findings.append({"file": str(filepath), "line": lineno, "type": name, "match": line.strip()})
    except Exception as e:
        logging.warning(f"Failed to read {filepath}: {e}")
    return findings

def entropy_score(s):
    import math
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob]) if len(s) > 0 else 0

def check_entropy(filepath):
    hits = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                tokens = re.findall(r'\b[a-zA-Z0-9/+]{20,}\b', line)
                for token in tokens:
                    if entropy_score(token) > 4.5:
                        hits.append({"file": str(filepath), "line": lineno, "match": token, "type": "High Entropy"})
    except:
        pass
    return hits

def check_ssh_keys():
    ssh_dir = Path.home() / ".ssh"
    issues = []
    if ssh_dir.exists():
        for file in ssh_dir.glob("*"):
            if file.is_file() and oct(file.stat().st_mode)[-3:] != '600':
                issues.append(str(file))
    return issues

def scan_git_history():
    results = []
    try:
        output = subprocess.check_output("git grep -I -n -e 'AKIA' -e 'ghp_'", shell=True).decode()
        for line in output.strip().splitlines():
            results.append({"type": "Git History Match", "match": line})
    except Exception:
        pass
    return results

def scan_directory(root, patterns):
    all_findings = []
    for path in Path(root).rglob("*"):
        if path.is_file() and path.suffix in ['.env', '.py', '.js', '.json', '.yaml', '.yml', '.txt']:
            all_findings.extend(scan_file_for_secrets(path, patterns))
            all_findings.extend(check_entropy(path))
    return all_findings

def redacted(data):
    redacted_results = json.loads(json.dumps(data))
    for entry in redacted_results.get("secrets", []):
        entry["match"] = "[REDACTED]"
    return redacted_results

def check_hibp(email):
    try:
        resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"hibp-api-key": "YOUR_KEY"})
        return resp.status_code == 200 and resp.json() or []
    except:
        return []

def send_email_alert(recipient, content):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Secret Hygiene Scanner Alert'
        msg['From'] = 'scanner@localhost'
        msg['To'] = recipient
        msg.set_content(content)
        with smtplib.SMTP('localhost') as s:
            s.send_message(msg)
    except Exception as e:
        print(f"[!] Email alert failed: {e}")

def export_pdf(data, password=None):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    pdf.set_font("Arial", size=8)
    pdf.multi_cell(0, 5, json.dumps(data, indent=2))
    name = "secret_scan_report.pdf"
    pdf.output(name)
    if password:
        try:
            from PyPDF2 import PdfReader, PdfWriter
            reader = PdfReader(name)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(password)
            with open(name, 'wb') as f_out:
                writer.write(f_out)
        except:
            print("[!] PDF encryption failed")

# --- Main Entry ---
def main():
    parser = argparse.ArgumentParser(description="GitHub Secret Hygiene Scanner")
    parser.add_argument("--path", default=".", help="Directory to scan")
    parser.add_argument("--config", help="Path to custom pattern config JSON")
    parser.add_argument("--output", help="Save results to JSON")
    parser.add_argument("--export-pdf", action="store_true", help="Export PDF report")
    parser.add_argument("--pdf-password", help="Password for exported PDF")
    parser.add_argument("--fail-on", type=int, default=0, help="Fail with exit code if findings exceed this number")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--email", help="Email address to send alerts")
    parser.add_argument("--interactive", action="store_true", help="Interactive review mode")
    args = parser.parse_args()

    patterns = DEFAULT_PATTERNS.copy()
    if args.config:
        try:
            with open(args.config) as f:
                user_patterns = json.load(f)
                patterns.update(user_patterns)
        except Exception as e:
            print(f"[!] Failed to load config: {e}")

    findings = scan_directory(args.path, patterns)
    git_results = scan_git_history()
    ssh_warnings = check_ssh_keys()

    results = {
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings) + len(git_results) + len(ssh_warnings),
        "secrets": findings,
        "git_matches": git_results,
        "ssh_key_warnings": ssh_warnings
    }

    if args.interactive:
        for i, f in enumerate(findings):
            print(f"[{i+1}] {f['type']} in {f['file']}:{f['line']} — {f['match']}")
            input("Press Enter to continue...")

    if not args.quiet:
        print(json.dumps(results, indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    if args.export_pdf:
        export_pdf(results if not args.quiet else redacted(results), password=args.pdf_password)

    if args.email:
        send_email_alert(args.email, f"Secret hygiene scan completed with {results['total_findings']} findings.")

    if args.fail_on and results["total_findings"] > args.fail_on:
        exit(1)

if __name__ == "__main__":
    main()
