# Secret Hygiene Scanner
This is a local scanner for secrets, credentials, and misconfigurations that may be accidentally committed to source code. 
Built for developers, DevSecOps, and security engineers to run locally or as part of CI pipelines.
Supports entropy detection, known pattern matching, Git history review, PDF/JSON export, alerting, and interactive redaction review.

## Features
	•	Detects common secret formats (AWS, GitHub, JWT, etc.)
	•	Entropy-based detection of high-risk strings
	•	Git history scanning for historical secrets
	•	SSH key permission audit
	•	Interactive review mode
	•	Optional PDF export (with encryption support)
	•	Email alert integration
	•	Custom pattern and ignore support via config
	•	Designed for GitHub Actions / CI/CD integration

## Installation
```
git clone https://github.com/kmukoo101/Secret-Hygiene-Scanner.git
cd Secret-Hygiene-Scanner
pip install -r requirements.txt
```

## Usage
### Basic Scan
`python secret_scanner.py --path ./my_project`
### With Export and Alerting
```
python secret_scanner.py \\
  --path ./repo \\
  --output results.json \\
  --export-pdf \\
  --pdf-password "securepass123" \\
  --email security@company.com
```
### Interactive Mode
`python secret_scanner.py --interactive`
### Fail CI Pipeline If Threshold Exceeded
`python secret_scanner.py --fail-on 5`

## Configuration File
You can customize the scanner using `config.json`:
```
{
  "patterns": {
    "Azure Key": "AZURE_[A-Za-z0-9]{32}",
    "Mongo URI": "mongodb(?:\\+srv)?:\\/\\/[\\w:-]+@"
  },
  "ignore_paths": ["tests/", "docs/", ".venv/"],
  "ignore_keywords": ["example_key", "not_a_real_secret"]
}
```
Then run:
`python secret_scanner.py --config config.json`

## Optional HIBP Lookup
This scanner supports HaveIBeenPwned email lookups via API (key needed). To enable, replace YOUR_KEY in the code or pass an environment variable and add:
check_hibp("email@example.com")

## Output
	•	JSON Report: Optional file output with full findings
	•	PDF Report: Printable version, with redacted mode in --quiet
	•	Logging: Timestamped .log file stored locally
	•	Email: Sends a plain text notification with summary

## GitHub Actions Integration
This scanner can run automatically in pull requests and CI pipelines. Use the workflow file in `.github/workflows/secret-hygiene-scan.yml` to block commits that contain secrets, and upload scan results as artifacts.
