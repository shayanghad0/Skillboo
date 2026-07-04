# 🔐 Flask Authentication Bypass – Login Form (AI Bug Bounty Skill)

## Skill Name
`flask-auth-bypass-login`

## Description
Comprehensive detection and exploitation of authentication bypass vulnerabilities in Python Flask login forms. The skill analyses request/response patterns, source code snippets, and session handling to identify logic flaws, injection points, insecure defaults, and misconfigurations that allow an attacker to gain unauthorised access.

## Affected Components
- Flask-Login `login_user()` calls
- Custom session-based authentication
- Werkzeug password hashing misuse
- Login endpoints using `request.form` or `request.get_json()`
- Database queries (SQLAlchemy, raw SQL, MongoDB PyMongo)
- JWT token generation/validation in login
- OAuth2/flask-dance callback handling
- Password reset/login via token endpoints

## Detection Patterns (Static & Dynamic)
### 1. SQL Injection in Login Query
- **Pattern**: Raw SQL query using string formatting or f-strings with user-supplied `username` / `password`.
  ```python
  # Vulnerable
  query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
  ```
- **Heuristic**: Use of `cursor.execute(query % (user, pwd))` or similar, no parameterised queries.
- **Dynamic test**: Inject `' OR 1=1 --` in username, expect login bypass.

### 2. NoSQL Injection (MongoDB with Flask-PyMongo)
- **Pattern**: Using `request.form` directly in `find_one()` with dictionaries:
  ```python
  user = mongo.db.users.find_one({'username': username, 'password': password})
  ```
- **Dynamic test**: Send JSON content-type with `{"username": {"$ne": null}, "password": {"$ne": null}}` to bypass.

### 3. Insecure Password Comparison / Type Juggling
- **Pattern**: Loose comparison `==` instead of secure hash check.
  ```python
  if request.form['password'] == user.password:   # plain-text, or comparing hash with password
  ```
- **Heuristic**: `user.password` fetched from DB and compared directly without `check_password_hash`.
- **Dynamic test**: If loose comparison is used with hashes starting with `0e...` (PHP-like), test magic hashes; but in Python, test empty password arrays or boolean true if JSON.

### 4. Logic Flaw – User Enumeration then Brute Force
- **Pattern**: Different error messages for "user not found" vs "wrong password".
- **Heuristic**: Response contains distinct strings like "Invalid username" / "Incorrect password".
- **Exploit**: Enumerate valid usernames, then credential stuffing.

### 5. Session Fixation / Insecure Session Management
- **Pattern**: Flask session cookie not invalidated after login, or session ID from before login is accepted after successful authentication.
- **Heuristic**: Login does not call `session.clear()` or rotate session ID.
- **Exploit**: Set a known session ID, have victim login, reuse the same cookie to gain access.

### 6. Missing Rate Limiting / Account Lockout
- **Pattern**: No Flask-Limiter, no lockout mechanism after X failed attempts.
- **Exploit**: Brute force password dictionary attacks.

### 7. Weak Password Reset Token Prediction
- **Pattern**: Token generation using `random.randint()` or timestamps.
- **Heuristic**: Tokens not using `secrets.token_urlsafe()`.
- **Exploit**: Predict reset token and take over account.

### 8. JWT Algorithm Confusion / "none" Algorithm
- **Pattern**: Flask app using PyJWT without enforcing algorithm.
  ```python
  jwt.decode(token, verify=False)   # or algorithms not specified
  ```
- **Dynamic test**: Craft JWT with `"alg":"none"` and empty signature.

### 9. OAuth2 Redirect_uri Manipulation
- **Pattern**: Flawed redirect_uri validation in Flask-Dance.
- **Heuristic**: Missing `redirect_uri` whitelist or using `request.args.get('next')` unsafely.
- **Exploit**: Steal authorization code via open redirect.

### 10. Hardcoded Credentials / Debug Backdoor
- **Pattern**: `if username == "admin" and password == "test123": login_user(...)` for testing.
- **Heuristic**: Comments like `# TODO remove`, hardcoded secrets in config.

## Testing Methodology (AI Agent Steps)
1. **Reconnaissance**
   - Crawl the Flask app, locate login endpoints (`/login`, `/auth`, `/signin`).
   - Identify HTTP methods (GET, POST), content types accepted (`x-www-form-urlencoded`, `JSON`).
   - Collect CSRF token presence; check if token is tied to session.

2. **Parameter Fuzzing**
   - Send empty values, arrays, boolean `true`/`false`, special characters (`'`, `"`, `\`, `$`, `{`, `}`).
   - Test parameter pollution: `username=admin&username=attacker` (Flask `request.form.getlist`).

3. **Injection Probing**
   - SQLi payloads: `' OR 1=1--`, `' UNION SELECT 1,'admin','hash'--`, time-based if blind.
   - NoSQLi: `{"$gt": ""}`, `{"$ne": null}`, `{"$regex": ".*"}` for both fields.
   - LDAP injection if using LDAP auth (uncommon in Flask but possible with python-ldap): `*)(uid=*))(|(uid=*`.

4. **Session Analysis**
   - Before login, record Flask session cookie (decoded if using itsdangerous).
   - After failed/successful login, compare session content; check for `_user_id` or `user_id`.
   - Attempt to modify session data to impersonate another user (if secret key known/guessable).

5. **Business Logic Flaws**
   - Try to bypass password check by omitting password parameter entirely.
   - Send `password[]=` (array) to cause type error and potentially bypass check (e.g., `check_password_hash` expects string).
   - Try `remember_me` parameter manipulation to extend session indefinitely.

6. **Credential Brute Force**
   - Use common username/password lists; check for lockout.
   - If lockout exists, try race conditions (parallel requests).

7. **Password Reset Flow Testing**
   - Request password reset for known email; capture token.
   - Test token reuse, token expiry, enumeration (difference in response when email exists/not).
   - Attempt to change email in reset request to attacker-controlled email.

8. **JWT / Token Inspection**
   - If login returns a JWT, decode without verification, check for `iat`, `exp`, `sub`.
   - Alter payload (change `sub` to admin) and re-sign with `none` algorithm or brute-force weak HMAC secret.

## Exploit Payloads (Quick Reference)

| Technique | Payload |
|-----------|---------|
| SQLi (login bypass) | `' OR '1'='1` |
| NoSQLi (JSON) | `{"username": {"$ne": ""}, "password": {"$ne": ""}}` |
| Array bypass | `username=admin&password[]=` (if backend uses `request.form.get` not `getlist`) |
| Type juggling (Python bool) | Send JSON: `{"username": "admin", "password": true}` – if code compares `user.password == True`, may match some non-empty strings. |
| Flask session forgery | If secret key is `'secret'`, use `flask-unsign` to craft cookie with `{'user_id': 1}` |
| JWT `none` algorithm | `{"alg":"none","typ":"JWT"}` header, payload `{"sub":"admin"}`, empty signature. |

## Secure Coding Recommendations (for AI report generation)
- Use parameterised queries (SQLAlchemy ORM) for database lookups.
- Always compare password hashes using `werkzeug.security.check_password_hash`.
- Rotate session ID after login via `session.clear()` and regenerate.
- Implement rate limiting with Flask-Limiter on login and password reset endpoints.
- Use `itsdangerous.URLSafeTimedSerializer` for reset tokens with short expiry.
- Enforce JWT algorithm explicitly: `jwt.decode(token, key, algorithms=['HS256'])`.
- Validate redirect URIs against a whitelist.
- Remove all hardcoded credentials and debug backdoors.

## Output Format (AI bug bounty report)
When a vulnerability is identified, produce a structured finding:
```
Title: Authentication Bypass via SQL Injection
Severity: Critical
Endpoint: POST /login
Parameter: username
Description: ...
Proof of Concept: curl command or request snippet
Remediation: ...
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with common extensions
- **Testing Type**: Black-box / Grey-box (with optional source snippets)
- **Dependencies**: None (self-contained AI inference)