```markdown
# 🧠 Flask Login Form – Unified Bug Bounty Master Skill

## Skill Name
`flask-login-master-bugbounty`

## Description
This master skill consolidates **28 individual vulnerability detection modules** for Python Flask login forms into a single automated workflow. It accepts a target specification or source code from `/document/{name}.md` (or any provided path), systematically analyses the login endpoint against all known vulnerabilities, and generates a comprehensive, timestamped bug bounty report saved to `desktop/bugresult/{name}-{date}-iran.md`. Every check follows a uniform methodology, and the final report includes reproduction steps, severity ratings, and remediation guidance.

## Dependencies
- Access to the target Flask application (URL, request templates, optionally source code snippets).
- Ability to send HTTP requests (via `requests` or internal HTTP client).
- Ability to read markdown files from `/document/` directory.
- Ability to write files to `desktop/bugresult/`.
- Internal AI reasoning engine that can interpret responses and chain payloads.

## Integrated Vulnerability Modules
| # | Module ID | Vulnerability |
|---|-----------|---------------|
| 1 | `sqli` | SQL Injection |
| 2 | `ssti` | Server‑Side Template Injection |
| 3 | `xss` | Cross‑Site Scripting |
| 4 | `csrf` | Cross‑Site Request Forgery |
| 5 | `ssrf` | Server‑Side Request Forgery |
| 6 | `lfi` | Local File Inclusion |
| 7 | `rfi` | Remote File Inclusion |
| 8 | `cmd` | OS Command Injection |
| 9 | `idor` | Insecure Direct Object Reference |
| 10 | `mass` | Mass Assignment |
| 11 | `deser` | Insecure Deserialization |
| 12 | `privesc` | Privilege Escalation |
| 13 | `infodisc` | Information Disclosure |
| 14 | `dataexp` | Sensitive Data Exposure |
| 15 | `debug` | Debug Mode Enabled |
| 16 | `stacktrace` | Stack Trace Leak |
| 17 | `dirlist` | Directory Listing |
| 18 | `hardcoded` | Hardcoded Credentials |
| 19 | `default` | Default Credentials |
| 20 | `ratelimit` | Missing Rate Limiting |
| 21 | `weakpw` | Weak Password Policy |
| 22 | `userenum` | User Enumeration |
| 23 | `pwreset` | Account Takeover via Password Reset |
| 24 | `sessionfix` | Session Fixation |
| 25 | `sessionhijack` | Session Hijacking |
| 26 | `jwt_none` | JWT None Algorithm |
| 27 | `jwt_weak` | JWT Weak Secret |
| 28 | `oauth_redirect` | OAuth Redirect_URI Hijack |

## Automated Workflow
1. **Input Parsing**  
   Read the file `/document/{filename}` (supplied by user). Expected contents:  
   - Target URL (e.g., `https://example.com/login`)  
   - HTTP method(s)  
   - Authentication credentials (optional, for authenticated testing)  
   - Cookie / header details  
   - Source code snippets (optional, for static analysis)  
   - Context flags (e.g., `has_jwt: true`, `oauth_provider: google`)  

   If the document does not contain a target, the AI will ask for clarification.

2. **Baseline Probing**  
   Send a normal login request to capture response headers, status code, and session cookies. Decode any JWT, session cookies, and inspect HTML source. Establish a “ground truth” for later differential analysis.

3. **Parallel Vulnerability Checks**  
   The AI agent dispatches each module in a logical order (non‑destructive → destructive) using the same session context. For each module:
   - Execute the specified payloads (from the module’s definition).
   - Analyse responses for indicators of vulnerability.
   - If a positive indication is found, attempt to confirm exploitation (e.g., retrieve data, escalate, call out‑of‑band).
   - Record the finding with severity, proof of concept, and remediation.

   Certain modules may be skipped if prerequisites aren’t met (e.g., JWT modules require a JWT token; OAuth modules require OAuth login flow).

4. **Correlation & Escalation**  
   Combine low‑severity findings (e.g., user enumeration + lack of rate limiting) to demonstrate a realistic attack chain (e.g., brute‑force leads to account takeover). Document any chained exploits.

5. **Report Generation**  
   Aggregate all findings into a single markdown report. The filename pattern is:  
   `desktop/bugresult/{target_name}-{date_jalali}-iran.md`  
   (Use the Jalali (Shamsi) date based on current timestamp; if the agent is not able to compute it, fallback to Gregorian date with `-iran` suffix.)

   The report includes:
   - Executive summary
   - Detailed findings for each vulnerability, with CVSS scores, affected endpoints, PoC commands, and specific remediations.
   - Attack chain summary (if any)
   - Recommendations for overall security hardening

## Master Code (Pseudocode / AI Agent Script)
```python
# flask_login_master_skill.py
# This code is a conceptual representation of the AI agent's execution logic.

import datetime, os, json
import requests   # assumed available
from pathlib import Path

# --- Configuration from /document/{name}.md ---
def load_target(filepath):
    # In practice, the AI reads the MD file and parses YAML/JSON frontmatter or plain text.
    # Here we simulate loading a dict.
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    # Simple extraction: lines like "url: https://...", "username: user", etc.
    target = {}
    for line in content.splitlines():
        if line.startswith('url:'):
            target['url'] = line.split(':',1)[1].strip()
        elif line.startswith('method:'):
            target['method'] = line.split(':',1)[1].strip().upper()
        elif line.startswith('username:'):
            target['username'] = line.split(':',1)[1].strip()
        elif line.startswith('password:'):
            target['password'] = line.split(':',1)[1].strip()
        # ... other parsing
    target.setdefault('method', 'POST')
    return target

# --- Vulnerability Checks ---
def check_sqli(target, session):
    # Send payloads from SQLi skill
    payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
    for p in payloads:
        data = {'username': p, 'password': 'irrelevant'}
        resp = session.post(target['url'], data=data)
        if any(indicator in resp.text for indicator in ['Welcome', 'Dashboard', 'admin']):
            return {'found': True, 'payload': p, 'severity': 'Critical'}
    return {'found': False}

def check_ssti(target, session):
    payload = "{{7*7}}"
    data = {'username': payload, 'password': 'test'}
    resp = session.post(target['url'], data=data)
    if '49' in resp.text:
        return {'found': True, 'payload': payload, 'severity': 'Critical'}
    return {'found': False}

# ... additional checks for all 28 modules ...

# Main orchestration
def run_all_checks(target, session):
    results = []
    results.append(('SQL Injection', check_sqli(target, session)))
    results.append(('SSTI', check_ssti(target, session)))
    # ... append all other checks
    return results

# --- Output ---
def generate_report(target_name, findings, jalali_date):
    report_path = Path.home() / 'Desktop' / 'bugresult' / f'{target_name}-{jalali_date}-iran.md'
    os.makedirs(report_path.parent, exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f'# Bug Bounty Report – {target_name}\n')
        f.write(f'**Date:** {jalali_date}\n\n')
        f.write('## Findings Summary\n')
        for name, result in findings:
            if result.get('found'):
                f.write(f'- **{name}**: {result.get("severity", "N/A")} (Payload: {result.get("payload", "N/A")})\n')
        f.write('\n## Detailed Findings\n')
        for name, result in findings:
            if result.get('found'):
                f.write(f'### {name}\n')
                f.write(f'- Severity: {result["severity"]}\n')
                f.write(f'- Proof of Concept: {result.get("payload")}\n')
                f.write(f'- Recommendation: See corresponding skill.\n\n')
    return str(report_path)

# Entry point
if __name__ == '__main__':
    import sys
    input_file = sys.argv[1]   # e.g., /document/target.md
    target = load_target(input_file)
    session = requests.Session()
    # Optional: set initial cookies/headers from target
    findings = run_all_checks(target, session)
    target_name = target['url'].replace('https://', '').replace('/', '_')
    jalali_date = '1405-04-13'  # placeholder – use actual conversion
    report = generate_report(target_name, findings, jalali_date)
    print(f'Report saved to {report}')
```

## Usage
1. Place the target description file in `/document/`. For example, `login.md`:
   ```
   url: https://shop.example.ir/login
   method: POST
   username_field: email
   password_field: password
   has_jwt: false
   ```
2. The AI agent executes the master skill, which internally runs the above script, performing all checks.
3. The final report is written to `Desktop/bugresult/shop.example.ir-1405-04-13-iran.md`.

## Requirements for AI Agent
- Ability to spawn sub‑processes or internal HTTP client.
- Access to file system (read from `/document/`, write to `~/Desktop/bugresult/`).
- Knowledge of all 28 vulnerability modules (as previously defined).
- Date conversion capability (Gregorian to Jalali) for report naming; fallback to `YYYY-MM-DD-iran`.

## Note
This master skill assumes the AI can perform all checks without human interaction. In a real deployment, each module's detailed payloads and detection logic would be included inline (as in the separate skills). The code above is a skeleton illustrating the automation flow.

## Skill Metadata
- **Author**: AI Bug Bounty Hunter (Master Skill)
- **Version**: 1.0
- **Target**: Python Flask login forms
- **Testing Type**: Automated black‑box (with optional grey‑box via source snippets)
- **Dependencies**: requests, standard Python libraries, OOB callback server (optional)
```''