# 🔑 Flask Login Form – Hardcoded Credentials – AI Bug Bounty Skill

## Skill Name
`flask-hardcoded-creds-login`

## Description
Detection and exploitation of hardcoded or default credentials within Python Flask login forms. This skill analyses the application source code, configuration files, client‑side scripts, database seeds, and deployment artefacts for embedded credentials that can be used to bypass authentication. Attackers who discover such credentials (e.g., an admin backdoor, a default password left unchanged, or test accounts with static passwords) can instantly gain unauthorised access, often with the highest privileges. The skill covers both static code analysis patterns and dynamic black‑box testing using common default credential lists.

## Affected Components
- **Source code** of login views (`auth.py`, `views.py`, `login.py`) containing hardcoded checks:
  ```python
  if username == "admin" and password == "supersecret":
      login_user(admin_user)
  ```
- **Configuration files** (`config.py`, `settings.py`, `.env`, `app.cfg`) containing default credentials for an initial admin account:
  ```python
  ADMIN_USERNAME = "admin"
  ADMIN_PASSWORD = "admin123"
  ```
- **Database initialisation scripts** (`seed.py`, `init_db.py`, SQL dumps) that insert users with well‑known passwords.
- **Client‑side JavaScript** that contains credentials for “debug” or “maintenance” endpoints, or that performs authentication directly in the browser.
- **Comments** in HTML/JS/Python revealing credentials: `<!-- default login: test / test -->`.
- **Dockerfiles, docker‑compose files, CI/CD scripts** that set environment variables with static passwords (e.g., `FLASK_ADMIN_PASSWORD=admin`).
- **Version control history** (exposed `.git` directory or public repositories) that still contains committed credentials.
- **Default credentials for third‑party services** integrated into login (e.g., test OAuth providers, test LDAP, test database) that are left enabled in production.
- **API endpoints** that accept a hardcoded token or API key for authentication, often used for debugging and never removed.

## Detection Patterns (Static & Dynamic)
### 1. Static Code Analysis (Grey/White-box)
- **Heuristic**: Direct comparison of credentials with string literals, or importing credentials from a config file that contains plain‑text defaults.
- **Common patterns**:
  - `if request.form['password'] == 'hardcoded_password'`
  - `user = User.query.filter_by(username='admin').first()`
  - `DEFAULT_ADMIN_PASSWORD = '...'`
  - `app.config['SECRET_KEY'] = 'dev'` (secret key used for signing, not credentials directly, but related).
- **Dynamic test**: Locate the application’s repository or exposed source, search for `password`, `passwd`, `pwd`, `secret`, `admin` using grep or code search tools.

### 2. Default/Guessable Credentials
- **Heuristic**: Use of common default usernames and passwords (see payload list) succeeds in logging in.
- **Dynamic test**: Brute‑force login form with a list of known default credentials for Flask, popular Python admin panels, or common development defaults (`admin:admin`, `root:toor`, `flask:flask`).

### 3. Hardcoded Tokens / API Keys
- **Heuristic**: Login form accepts not only username/password but also an `api_key` or `token` parameter; certain values always grant access.
- **Dynamic test**: Intercept login request, add parameter `api_key=test` or `token=debug`; if login succeeds without valid username/password, a backdoor exists.

### 4. Environment Variable Leakage
- **Heuristic**: Stack traces, debug mode, or directory listing reveal environment variables containing `PASSWORD=...` (e.g., `/proc/self/environ`, `.env` file downloadable). Those values may be the hardcoded admin password.

### 5. Version Control or Backup Exposure
- If `.git` directory is exposed, download and search commit history for credentials. If `.env.bak` is accessible, retrieve the admin password.

## Testing Methodology (AI Agent Steps)
1. **Passive Reconnaissance (Source & Comments)**
   - View page source of login form. Search for keywords: `password`, `pwd`, `secret`, `token`, `admin`, `test`, `root`.
   - Inspect linked JavaScript files for hardcoded credentials or API endpoints that might accept static tokens.
   - If you have access to the application’s public repository (open‑source project), review `config.py`, `settings.py`, `.env.example`, `docker-compose.yml` for default passwords.

2. **Brute‑Force Default Credentials**
   - Use a wordlist of common default credentials for Flask applications, Python web frameworks, and generic devices:
     - `admin` / `admin`
     - `admin` / `password`
     - `root` / `root`
     - `flask` / `flask`
     - `user` / `user`
     - `test` / `test`
     - `guest` / `guest`
     - `admin` / `admin123`
     - `admin` / `changeme`
     - `administrator` / `password`
   - Try these for both `username` and `password` fields.
   - Be mindful of rate‑limiting; if present, attempt password spraying (one password per many usernames).

3. **Test Common Backdoor Parameters**
   - If the login is API‑based (JSON), try adding fields like `"backdoor": true`, `"debug": true`, `"master_key": "secret"`.
   - Append `?admin=true` or `?debug=1` to the login URL.
   - Try HTTP methods other than POST: `GET /login?username=admin&password=admin` might bypass CSRF checks but still authenticate.

4. **Exploit Leaked Configuration**
   - If you have identified a hardcoded password via source disclosure (e.g., from a stack trace that showed `ADMIN_PASSWORD = 'P@ssw0rd'`), use that directly on the login form.
   - If the Flask secret key is hardcoded (e.g., `SECRET_KEY = 'mysecret'`), forge session cookies to impersonate any user, including admins, without even using the login form.

5. **Check Database Seeds**
   - If you can access the database (via SQL injection or exposed backup), query the `user` table for known hashes. Look for accounts with easily crackable passwords (e.g., `5f4dcc3b5aa765d61d8327deb882cf99` = “password”). Sometimes the seed script inserts a hash of a well‑known password.

6. **Impact Assessment**
   - If you gain admin access, verify privileges: create new users, access admin panels, view sensitive data. Report accordingly.

## Essential Payloads (Hardcoded/Default Credentials)
### Common Default Username/Password Pairs
```
admin:admin
admin:password
admin:admin123
admin:changeme
admin:123456
admin:letmein
root:root
root:password
root:toor
flask:flask
python:python
user:user
test:test
guest:guest
administrator:password
administrator:admin
system:manager
webmaster:webmaster
```

### Backdoor Parameters (if application uses custom logic)
```
username=admin&password=wrong&debug=true
username=admin&password=wrong&master_key=secret
username=admin&password=wrong&backdoor=1
```

### API‑Style Login Backdoor
```json
{"username": "admin", "password": "wrong", "token": "supersecretdebugtoken"}
```

### Search Patterns for Static Analysis
```bash
grep -rn "password\s*=\s*['\"]" .
grep -rn "passwd\s*=\s*['\"]" .
grep -rn "pwd\s*=\s*['\"]" .
grep -rn "secret\s*=\s*['\"]" .
grep -rn "ADMIN_PASSWORD" .
grep -rn "DEFAULT_PASSWORD" .
```

## Secure Coding Recommendations
- **Never hardcode credentials.** Use environment variables or a secure secrets manager (HashiCorp Vault, AWS Secrets Manager) injected at runtime.
- **Remove default accounts** before deploying to production. If an initial admin account is needed, force a password change on first login.
- **Do not store credentials in source code, configuration files (if they can be exposed), or client‑side code.** Configuration files should only reference environment variables, not contain actual secrets.
- **Use strong, unique passwords** for all accounts. Enforce password complexity requirements.
- **Implement account lockout and rate limiting** to hinder brute‑force attacks on default credentials.
- **Audit code and version control history** before going public: delete any committed secrets and invalidate them.
- **Use `.gitignore` to exclude `.env` and configuration files**; never commit them to the repository.
- **Set Flask’s `SECRET_KEY` via an environment variable**, not in code.
- **Enable two‑factor authentication** for administrative accounts to provide an additional layer of security even if credentials are compromised.

## Output Format (Bug Report)
```
Title: Hardcoded Administrative Credentials Allow Unauthorised Access
Severity: Critical (CVSS 10.0)
Endpoint: POST /login
Vulnerable Parameter: password (known static value)
Description:
  The login form accepts a hardcoded username and password combination ("admin" / "P@ssw0rd") that is defined in the application’s configuration file. This allows anyone aware of the credentials to log in with full administrative privileges, bypassing all authentication controls.
Proof of Concept:
  curl -X POST https://target.com/login -d "username=admin&password=P@ssw0rd"
  The response sets a session cookie for an administrative user, and the attacker can then access /admin.
Remediation:
  Remove the hardcoded credentials. If an initial admin account is necessary, create it with a strong unique password and mandate a password change on first login. Use environment variables for secrets.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any authentication mechanism
- **Testing Type**: Black‑box (credential brute‑forcing) / Grey‑box (static code analysis)
- **Dependencies**: Common default credential wordlist; AI can search source code and response patterns.